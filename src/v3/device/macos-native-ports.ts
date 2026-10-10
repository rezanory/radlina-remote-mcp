import { spawn, type ChildProcess } from "node:child_process";
import { open, lstat, realpath, readdir, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";

import type {
  FilesystemPort,
  PlatformFileInfo,
  ProcessPort,
  ProcessSnapshot,
  SearchPort,
  SearchRequest,
  SearchSnapshot,
} from "../platform/contracts.js";

export type MacOSNativePortOptions = {
  roots: string[];
  executableAllowlist: string[];
  environmentAllowlist?: string[];
  ripgrepExecutable: string;
  maxFileBytes?: number;
  maxOutputBytes?: number;
  maxProcessRuntimeMs?: number;
  maxSearchRuntimeMs?: number;
  maxSessions?: number;
};

export type MacOSNativePorts = {
  filesystem: FilesystemPort;
  process: ProcessPort;
  search: SearchPort;
  close(): Promise<void>;
};

type ProcessSession = {
  child: ChildProcess;
  status: ProcessSnapshot["status"];
  exitCode: number | null;
  outputBytes: number;
  timer: NodeJS.Timeout;
};

type SearchSession = {
  child: ChildProcess;
  status: SearchSnapshot["status"];
  results: unknown[];
  timer: NodeJS.Timeout;
};

const DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024;
const DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024;
const DEFAULT_MAX_PROCESS_RUNTIME_MS = 15 * 60 * 1000;
const DEFAULT_MAX_SEARCH_RUNTIME_MS = 2 * 60 * 1000;
const DEFAULT_MAX_SESSIONS = 12;

class MacOSRootGuard {
  private constructor(private readonly roots: string[]) {}

  static async create(rawRoots: string[]): Promise<MacOSRootGuard> {
    if (rawRoots.length === 0 || rawRoots.length > 32) {
      throw new Error("macOS native ports require between 1 and 32 roots");
    }
    const roots = await Promise.all(
      rawRoots.map(async (root) => {
        if (!path.isAbsolute(root)) throw new Error("macOS roots must be absolute paths");
        const resolved = await realpath(root);
        if (!(await stat(resolved)).isDirectory())
          throw new Error(`root is not a directory: ${root}`);
        return resolved;
      }),
    );
    return new MacOSRootGuard([...new Set(roots)]);
  }

  async existing(target: string): Promise<string> {
    if (!path.isAbsolute(target)) throw new Error("path must be absolute");
    const resolved = await realpath(target);
    this.assertAllowed(resolved);
    return resolved;
  }

  async writable(target: string): Promise<string> {
    if (!path.isAbsolute(target)) throw new Error("path must be absolute");
    try {
      const info = await lstat(target);
      if (info.isSymbolicLink()) throw new Error("writing through a symbolic link is forbidden");
      return await this.existing(target);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      const parent = await realpath(path.dirname(target));
      this.assertAllowed(parent);
      return path.join(parent, path.basename(target));
    }
  }

  private assertAllowed(target: string): void {
    const allowed = this.roots.some((root) => {
      const relative = path.relative(root, target);
      return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== "..");
    });
    if (!allowed) throw new Error("path is outside the configured macOS roots");
  }
}

export async function createMacOSNativePorts(
  options: MacOSNativePortOptions,
): Promise<MacOSNativePorts> {
  if (process.platform !== "darwin" && process.env["NODE_ENV"] !== "test") {
    throw new Error("macOS native ports can only run on macOS");
  }
  const guard = await MacOSRootGuard.create(options.roots);
  const ripgrepExecutable = await realpath(options.ripgrepExecutable);
  const allowedExecutables = new Set(
    await Promise.all(
      options.executableAllowlist.map(async (executable) => {
        if (!path.isAbsolute(executable)) throw new Error("allowed executables must be absolute");
        return await realpath(executable);
      }),
    ),
  );
  const environmentAllowlist = new Set(options.environmentAllowlist ?? []);
  const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const maxOutputBytes = options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  const maxProcessRuntimeMs = options.maxProcessRuntimeMs ?? DEFAULT_MAX_PROCESS_RUNTIME_MS;
  const maxSearchRuntimeMs = options.maxSearchRuntimeMs ?? DEFAULT_MAX_SEARCH_RUNTIME_MS;
  const maxSessions = options.maxSessions ?? DEFAULT_MAX_SESSIONS;
  for (const [name, value] of Object.entries({
    maxFileBytes,
    maxOutputBytes,
    maxProcessRuntimeMs,
    maxSearchRuntimeMs,
    maxSessions,
  })) {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error(`invalid ${name}`);
  }
  const processSessions = new Map<string, ProcessSession>();
  const searchSessions = new Map<string, SearchSession>();
  let closing = false;

  const filesystem: FilesystemPort = {
    getFileInfo: async (target): Promise<PlatformFileInfo> => {
      const resolved = await guard.existing(target);
      const info = await lstat(resolved);
      return {
        path: resolved,
        kind: info.isFile()
          ? "file"
          : info.isDirectory()
            ? "directory"
            : info.isSymbolicLink()
              ? "symlink"
              : "other",
        size: info.isFile() ? info.size : null,
        modifiedAt: info.mtime.toISOString(),
      };
    },
    readFile: async (target, offset, length) => {
      if (!Number.isSafeInteger(offset) || offset < 0) throw new Error("invalid read offset");
      if (!Number.isSafeInteger(length) || length < 1 || length > maxFileBytes) {
        throw new Error("invalid or excessive read length");
      }
      const resolved = await guard.existing(target);
      const info = await stat(resolved);
      if (!info.isFile()) throw new Error("read target is not a regular file");
      const boundedLength = Math.min(length, Math.max(0, info.size - offset));
      const handle = await open(resolved, "r");
      try {
        const value = Buffer.alloc(boundedLength);
        const { bytesRead } = await handle.read(value, 0, boundedLength, offset);
        return value.subarray(0, bytesRead);
      } finally {
        await handle.close();
      }
    },
    writeFile: async (target, value, overwrite) => {
      if (value.byteLength > maxFileBytes) throw new Error("file exceeds configured size limit");
      const resolved = await guard.writable(target);
      await writeFile(resolved, value, { flag: overwrite ? "w" : "wx", mode: 0o600 });
    },
    listDirectory: async (target) => {
      const resolved = await guard.existing(target);
      return (await readdir(resolved)).sort();
    },
  };

  const processPort: ProcessPort = {
    start: async (request) => {
      if (closing) throw new Error("macOS native ports are closing");
      if (request.args.length > 128 || request.args.some((argument) => argument.length > 4096)) {
        throw new Error("process arguments exceed configured bounds");
      }
      if (
        request.timeoutMs !== undefined &&
        (!Number.isSafeInteger(request.timeoutMs) || request.timeoutMs < 100)
      ) {
        throw new Error("invalid process timeout");
      }
      const activeProcesses = [...processSessions.values()].filter(
        (session) => session.status === "running",
      ).length;
      if (activeProcesses >= maxSessions) throw new Error("process session limit reached");
      const executable = await realpath(request.executable);
      if (!allowedExecutables.has(executable)) throw new Error("executable is not allowlisted");
      const cwd = await guard.existing(request.cwd);
      if (!(await stat(cwd)).isDirectory()) throw new Error("process cwd is not a directory");
      const env: NodeJS.ProcessEnv = {};
      for (const name of environmentAllowlist) {
        if (process.env[name] !== undefined) env[name] = process.env[name];
      }
      for (const [name, value] of Object.entries(request.env ?? {})) {
        if (!environmentAllowlist.has(name))
          throw new Error(`environment variable is not allowed: ${name}`);
        if (value.length > 4096) throw new Error("environment value is too large");
        env[name] = value;
      }
      const sessionId = randomUUID();
      const child = spawn(executable, request.args, {
        cwd,
        env,
        shell: false,
        detached: false,
        stdio: ["pipe", "pipe", "pipe"],
      });
      const timeoutMs = Math.min(request.timeoutMs ?? maxProcessRuntimeMs, maxProcessRuntimeMs);
      const timer = setTimeout(() => child.kill("SIGTERM"), timeoutMs);
      timer.unref();
      const session: ProcessSession = {
        child,
        status: "running",
        exitCode: null,
        outputBytes: 0,
        timer,
      };
      processSessions.set(sessionId, session);
      const drain = (chunk: unknown): void => {
        if (!(chunk instanceof Uint8Array)) return;
        session.outputBytes += chunk.byteLength;
        if (session.outputBytes > maxOutputBytes) child.kill("SIGTERM");
      };
      child.stdout?.on("data", drain);
      child.stderr?.on("data", drain);
      child.once("error", () => {
        clearTimeout(timer);
        session.status = "failed";
      });
      child.once("close", (code, signal) => {
        clearTimeout(timer);
        session.exitCode = code;
        if (session.status === "terminated" || signal === "SIGTERM" || signal === "SIGKILL") {
          session.status = "terminated";
        } else {
          session.status = code === 0 ? "complete" : "failed";
        }
      });
      return { sessionId, pid: child.pid ?? null };
    },
    read: async (sessionId) => {
      const session = requireProcessSession(processSessions, sessionId);
      return {
        sessionId,
        status: session.status,
        exitCode: session.exitCode,
        outputCursor: String(Math.min(session.outputBytes, maxOutputBytes)),
      };
    },
    interact: async (sessionId, input) => {
      const session = requireProcessSession(processSessions, sessionId);
      if (session.status !== "running" || !session.child.stdin || session.child.stdin.destroyed) {
        throw new Error("process input is unavailable");
      }
      if (Buffer.byteLength(input) > 64 * 1024) throw new Error("process input is too large");
      session.child.stdin.write(input);
    },
    terminate: async (sessionId, force) => {
      const session = requireProcessSession(processSessions, sessionId);
      if (session.status !== "running") return;
      session.status = "terminated";
      session.child.kill(force ? "SIGKILL" : "SIGTERM");
    },
  };

  const search: SearchPort = {
    start: async (request) => {
      if (closing) throw new Error("macOS native ports are closing");
      const activeSearches = [...searchSessions.values()].filter(
        (session) => session.status === "running" || session.status === "queued",
      ).length;
      if (activeSearches >= maxSessions) throw new Error("search session limit reached");
      validateSearchRequest(request);
      const filenameMatcher = request.mode === "files" ? createFilenameMatcher(request) : undefined;
      const root = await guard.existing(request.root);
      const searchId = randomUUID();
      const args = ripgrepArguments(request, root);
      const child = spawn(ripgrepExecutable, args, {
        shell: false,
        detached: false,
        stdio: ["ignore", "pipe", "pipe"],
      });
      const timer = setTimeout(() => child.kill("SIGTERM"), maxSearchRuntimeMs);
      timer.unref();
      const session: SearchSession = { child, status: "running", results: [], timer };
      searchSessions.set(searchId, session);
      child.stderr?.resume();
      let buffered = "";
      let bytes = 0;
      child.stdout?.setEncoding("utf8");
      child.stdout?.on("data", (chunk: string) => {
        if (session.results.length >= request.maxResults || bytes >= maxOutputBytes) return;
        bytes += Buffer.byteLength(chunk);
        buffered += chunk;
        const lines = buffered.split(/\r?\n/u);
        buffered = lines.pop() ?? "";
        for (const line of lines) {
          if (!line || session.results.length >= request.maxResults) continue;
          const result = parseRipgrepLine(line, request.mode, filenameMatcher);
          if (result !== undefined) session.results.push(result);
        }
        if (session.results.length >= request.maxResults || bytes >= maxOutputBytes) {
          child.kill("SIGTERM");
        }
      });
      child.once("error", () => {
        clearTimeout(timer);
        session.status = "failed";
      });
      child.once("close", (code, signal) => {
        clearTimeout(timer);
        if (buffered && session.results.length < request.maxResults) {
          const result = parseRipgrepLine(buffered, request.mode, filenameMatcher);
          if (result !== undefined) session.results.push(result);
        }
        if (session.status === "cancelled") return;
        const boundedCompletion =
          signal === "SIGTERM" &&
          (session.results.length >= request.maxResults || bytes >= maxOutputBytes);
        session.status = code === 0 || code === 1 || boundedCompletion ? "complete" : "failed";
      });
      return { searchId };
    },
    status: async (searchId) => {
      const session = requireSearchSession(searchSessions, searchId);
      return { searchId, status: session.status, resultCount: session.results.length };
    },
    results: async (searchId, cursor) => {
      const session = requireSearchSession(searchSessions, searchId);
      const offset = cursor === undefined ? 0 : Number.parseInt(cursor, 10);
      if (!Number.isSafeInteger(offset) || offset < 0) throw new Error("invalid search cursor");
      return session.results.slice(offset);
    },
    cancel: async (searchId) => {
      const session = requireSearchSession(searchSessions, searchId);
      if (session.status !== "running") return;
      session.status = "cancelled";
      session.child.kill("SIGTERM");
    },
  };

  return {
    filesystem,
    process: processPort,
    search,
    close: async () => {
      closing = true;
      for (const session of processSessions.values()) {
        clearTimeout(session.timer);
        if (session.status === "running") {
          session.status = "terminated";
          session.child.kill("SIGTERM");
        }
      }
      for (const session of searchSessions.values()) {
        clearTimeout(session.timer);
        if (session.status === "running") {
          session.status = "cancelled";
          session.child.kill("SIGTERM");
        }
      }
    },
  };
}

function requireProcessSession(sessions: Map<string, ProcessSession>, id: string): ProcessSession {
  const session = sessions.get(id);
  if (!session) throw new Error("process session was not found");
  return session;
}

function requireSearchSession(sessions: Map<string, SearchSession>, id: string): SearchSession {
  const session = sessions.get(id);
  if (!session) throw new Error("search session was not found");
  return session;
}

function validateSearchRequest(request: SearchRequest): void {
  if (!request.pattern || request.pattern.length > 512) throw new Error("invalid search pattern");
  if (
    !Number.isSafeInteger(request.maxResults) ||
    request.maxResults < 1 ||
    request.maxResults > 10_000
  ) {
    throw new Error("invalid search result limit");
  }
}

function createFilenameMatcher(request: SearchRequest): RegExp {
  const source = request.literal
    ? request.pattern.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")
    : request.pattern;
  try {
    return new RegExp(source, request.caseSensitive ? "u" : "iu");
  } catch {
    throw new Error("invalid filename search expression");
  }
}

function ripgrepArguments(request: SearchRequest, root: string): string[] {
  const sensitivity = request.caseSensitive ? ["--case-sensitive"] : ["--ignore-case"];
  const literal = request.literal ? ["--fixed-strings"] : [];
  if (request.mode === "files") {
    return ["--files", "--hidden", "--glob", "!.git", root];
  }
  return [
    "--json",
    "--hidden",
    "--glob",
    "!.git",
    ...sensitivity,
    ...literal,
    "--",
    request.pattern,
    root,
  ];
}

function parseRipgrepLine(
  line: string,
  mode: SearchRequest["mode"],
  filenameMatcher?: RegExp,
): Record<string, unknown> | undefined {
  if (mode === "files") return filenameMatcher?.test(line) ? { path: line } : undefined;
  try {
    const parsed = JSON.parse(line) as {
      type?: string;
      data?: { path?: { text?: string }; line_number?: number; lines?: { text?: string } };
    };
    if (parsed.type !== "match" || !parsed.data?.path?.text) return undefined;
    return {
      path: parsed.data.path.text,
      line: parsed.data.line_number ?? null,
      text: parsed.data.lines?.text?.replace(/\r?\n$/u, "") ?? "",
    };
  } catch {
    return undefined;
  }
}
