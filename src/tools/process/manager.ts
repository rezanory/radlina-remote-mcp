import { execFile as execFileCallback, spawn, type ChildProcess } from "node:child_process";
import { mkdir, open, stat } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";

import type { AppConfig, WorkspaceProfile } from "../../config/schema.js";
import { AppError } from "../../errors.js";
import type { Store } from "../../persistence/store.js";
import type { PolicyEngine } from "../../policy/engine.js";
import { decodeCursor, encodeCursor, sha256 } from "../../utils/json.js";
import { resolveWindowsExecutable } from "../../utils/windows-executable.js";
import type { SafePathResolver } from "../filesystem/safe-path.js";

const execFile = promisify(execFileCallback);

type ProcessCursor = { id: string; offset: number };
type ProcessRow = {
  id: string;
  subject: string;
  profile: string;
  pid: number | null;
  executable: string;
  output_path: string;
  status: string;
  started_at: number;
  ended_at: number | null;
  exit_code: number | null;
  start_identity: string;
};

export class ProcessManager {
  private readonly children = new Map<string, ChildProcess>();
  private readonly timers = new Map<string, NodeJS.Timeout>();
  private readonly directory: string;
  private shuttingDown = false;

  constructor(
    private readonly config: AppConfig,
    private readonly store: Store,
    private readonly policy: PolicyEngine,
  ) {
    this.directory = path.join(config.storage.directory, "process");
  }

  async reconcile(): Promise<{ interrupted: number }> {
    let interrupted = 0;
    const rows = this.store.db
      .prepare("SELECT * FROM process_sessions WHERE status='running'")
      .all() as ProcessRow[];
    for (const row of rows) {
      const identity = row.pid ? await this.processIdentity(row.pid) : undefined;
      if (!identity || identity !== row.start_identity) {
        const updated = this.store.db
          .prepare(
            "UPDATE process_sessions SET status='interrupted',ended_at=? WHERE id=? AND status='running'",
          )
          .run(Date.now(), row.id);
        interrupted += Number(updated.changes);
      }
    }
    return { interrupted };
  }

  async start(
    subject: string,
    profileName: string,
    profile: WorkspaceProfile,
    resolver: SafePathResolver,
    input: {
      executable: string;
      args: string[];
      cwd: string;
      env?: Record<string, string>;
      timeoutMs?: number;
    },
  ): Promise<unknown> {
    if (this.shuttingDown) throw new AppError("CONFLICT", "process manager is shutting down");
    const active = this.store.db
      .prepare("SELECT COUNT(*) AS count FROM process_sessions WHERE status='running'")
      .get() as { count: number };
    if (active.count >= this.config.policy.maxSessions)
      throw new AppError("LIMIT_EXCEEDED", "process session limit reached");
    const executable = await resolveWindowsExecutable(input.executable);
    if (!executable) {
      throw new AppError("NOT_FOUND", "executable was not found on PATH or at the specified path", {
        executable: input.executable.slice(0, 512),
      });
    }
    const commandDecision = this.policy.commandAllowed(profile, executable, input.args);
    if (!commandDecision.allowed) throw new AppError("POLICY_DENIED", commandDecision.reason);
    const cwd = await resolver.resolve(input.cwd, { mustExist: true });
    const env: NodeJS.ProcessEnv = {};
    for (const name of profile.envAllowlist)
      if (process.env[name] !== undefined) env[name] = process.env[name];
    for (const [name, value] of Object.entries(input.env ?? {})) {
      if (!profile.envAllowlist.includes(name))
        throw new AppError("POLICY_DENIED", `environment variable ${name} is not allowed`);
      if (value.length > 4096)
        throw new AppError("LIMIT_EXCEEDED", "environment value is too large");
      env[name] = value;
    }
    const id = randomUUID();
    await mkdir(this.directory, { recursive: true });
    const outputPath = path.join(this.directory, `${id}.log`);
    const outputHandle = await open(outputPath, "wx", 0o600);
    const output = outputHandle.createWriteStream({ autoClose: true });
    let child: ChildProcess;
    try {
      child = spawn(executable, input.args, {
        cwd,
        env,
        shell: false,
        windowsHide: true,
        detached: false,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (error) {
      output.destroy();
      throw error;
    }
    if (!child.pid) throw new AppError("INTERNAL_ERROR", "process did not return a PID");
    const pid = child.pid;
    const startedAt = Date.now();
    const provisionalIdentity = `${pid}:unverified:${executable.toLowerCase()}`;
    this.children.set(id, child);
    this.store.db
      .prepare(
        "INSERT INTO process_sessions(id,subject,profile,pid,executable,args_json,output_path,status,started_at,start_identity) VALUES(?,?,?,?,?,?,?,?,?,?)",
      )
      .run(
        id,
        subject,
        profileName,
        pid,
        executable,
        JSON.stringify({ count: input.args.length, sha256: sha256(JSON.stringify(input.args)) }),
        outputPath,
        "running",
        startedAt,
        provisionalIdentity,
      );
    const timeout = Math.min(
      input.timeoutMs ?? this.config.policy.maxProcessRuntimeMs,
      this.config.policy.maxProcessRuntimeMs,
    );
    let stopReason: "timed-out" | "output-limit" | undefined;
    const stopTrackedProcess = (reason: "timed-out" | "output-limit"): void => {
      if (stopReason) return;
      stopReason = reason;
      void execFile("taskkill.exe", ["/PID", String(pid), "/T"], {
        windowsHide: true,
        timeout: 10_000,
      }).catch(() => child.kill("SIGTERM"));
    };
    const maxOutputBytes = this.config.policy.maxOutputBytes;
    let outputBytes = 0;
    const recordOutput = (chunk: unknown): void => {
      if (!(chunk instanceof Uint8Array) || stopReason) return;
      const remaining = Math.max(0, maxOutputBytes - outputBytes);
      if (remaining > 0) {
        const selected = chunk.subarray(0, remaining);
        output.write(selected);
        outputBytes += selected.byteLength;
      }
      if (chunk.byteLength > remaining || outputBytes >= maxOutputBytes) {
        stopTrackedProcess("output-limit");
      }
    };
    child.stdout?.on("data", recordOutput);
    child.stderr?.on("data", recordOutput);
    const timer = setTimeout(() => stopTrackedProcess("timed-out"), timeout);
    timer.unref();
    this.timers.set(id, timer);
    let finalized = false;
    const finalize = (statusValue: string, code: number | null): void => {
      if (finalized) return;
      finalized = true;
      clearTimeout(timer);
      this.timers.delete(id);
      this.children.delete(id);
      output.end(() => {
        if (this.shuttingDown || !this.store.isOpen()) return;
        this.store.db
          .prepare(
            "UPDATE process_sessions SET status=?,ended_at=?,exit_code=? WHERE id=? AND status='running'",
          )
          .run(statusValue, Date.now(), code, id);
      });
    };
    child.on("error", () => finalize(stopReason ?? "error", null));
    child.on("close", (code) => {
      finalize(stopReason ?? "complete", code);
    });
    child.unref();
    const identity = await this.waitForIdentity(pid, child);
    if (identity) {
      this.store.db
        .prepare("UPDATE process_sessions SET start_identity=? WHERE id=? AND status='running'")
        .run(identity, id);
    }
    const state = this.store.db
      .prepare("SELECT status FROM process_sessions WHERE id=?")
      .get(id) as {
      status: string;
    };
    return {
      sessionId: id,
      pid,
      status: state.status,
      outputCursor: encodeCursor({ id, offset: 0 }),
    };
  }

  async readOutput(
    id: string,
    subject: string,
    cursor?: string,
    maxBytes = 64 * 1024,
  ): Promise<unknown> {
    const row = this.row(id, subject);
    const parsed = cursor ? decodeCursor<ProcessCursor>(cursor) : { id, offset: 0 };
    if (parsed.id !== id || !Number.isInteger(parsed.offset) || parsed.offset < 0)
      throw new AppError("INVALID_INPUT", "invalid process output cursor");
    const info = await stat(row.output_path);
    const bounded = Math.min(Math.max(maxBytes, 1), this.config.policy.maxOutputBytes, 1024 * 1024);
    const length = Math.min(bounded, Math.max(0, info.size - parsed.offset));
    const handle = await open(row.output_path, "r");
    try {
      const buffer = Buffer.alloc(length);
      const { bytesRead } = await handle.read(buffer, 0, length, parsed.offset);
      const nextOffset = parsed.offset + bytesRead;
      return {
        sessionId: id,
        status: row.status,
        output: buffer.subarray(0, bytesRead).toString("utf8"),
        bytesRead,
        nextCursor: encodeCursor({ id, offset: nextOffset }),
        hasMore: nextOffset < info.size || row.status === "running",
        exitCode: row.exit_code,
      };
    } finally {
      await handle.close();
    }
  }

  interact(id: string, subject: string, input: string): unknown {
    this.row(id, subject);
    const child = this.children.get(id);
    if (!child?.stdin || child.stdin.destroyed) {
      throw new AppError(
        "CONFLICT",
        "interactive input is unavailable after service restart or process exit",
      );
    }
    if (Buffer.byteLength(input) > 64 * 1024)
      throw new AppError("LIMIT_EXCEEDED", "interactive input is too large");
    child.stdin.write(input);
    return { sessionId: id, acceptedBytes: Buffer.byteLength(input) };
  }

  async terminate(id: string, subject: string, force: boolean): Promise<unknown> {
    const row = this.row(id, subject);
    if (row.status !== "running" || !row.pid)
      return { sessionId: id, status: row.status, terminated: false };
    const identity = await this.processIdentity(row.pid);
    if (!identity) {
      if (!(await this.processExists(row.pid))) {
        this.store.db
          .prepare(
            "UPDATE process_sessions SET status='terminated',ended_at=? WHERE id=? AND status='running'",
          )
          .run(Date.now(), id);
        return { sessionId: id, terminated: true, forced: force, alreadyExited: true };
      }
      throw new AppError("CONFLICT", "PID identity could not be verified; refusing termination");
    }
    if (identity !== row.start_identity) {
      this.store.db
        .prepare("UPDATE process_sessions SET status='identity-mismatch',ended_at=? WHERE id=?")
        .run(Date.now(), id);
      throw new AppError(
        "CONFLICT",
        "PID identity changed; refusing to terminate an unrelated process",
      );
    }
    const args = ["/PID", String(row.pid), "/T"];
    if (force) args.push("/F");
    try {
      await execFile("taskkill.exe", args, { windowsHide: true, timeout: 10_000 });
    } catch (error) {
      const after = await this.processIdentity(row.pid);
      if (!after && !(await this.processExists(row.pid))) {
        this.store.db
          .prepare(
            "UPDATE process_sessions SET status='terminated',ended_at=? WHERE id=? AND status='running'",
          )
          .run(Date.now(), id);
        return { sessionId: id, terminated: true, forced: force, alreadyExited: true };
      }
      if (after && after !== row.start_identity) {
        throw new AppError(
          "CONFLICT",
          "PID identity changed while termination was in progress; refusing further action",
        );
      }
      const code = (error as NodeJS.ErrnoException).code;
      throw new AppError(
        "CONFLICT",
        "process termination failed while the target was still running",
        {
          ...(code === undefined ? {} : { code: String(code).slice(0, 64) }),
        },
      );
    }
    this.store.db
      .prepare(
        "UPDATE process_sessions SET status='terminated',ended_at=? WHERE id=? AND status='running'",
      )
      .run(Date.now(), id);
    return { sessionId: id, terminated: true, forced: force, alreadyExited: false };
  }

  async listProcesses(limit = 100): Promise<unknown> {
    const bounded = Math.min(Math.max(limit, 1), 500);
    const script = `$ErrorActionPreference='SilentlyContinue'; Get-Process | Sort-Object Id | Select-Object -First ${bounded} Id,ProcessName,@{N='StartedAt';E={try{$_.StartTime.ToUniversalTime().ToString('o')}catch{$null}}} | ConvertTo-Json -Compress`;
    const { stdout } = await execFile(
      "powershell.exe",
      ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
      {
        windowsHide: true,
        timeout: 10_000,
        maxBuffer: 1024 * 1024,
      },
    );
    return { processes: JSON.parse(stdout || "[]") as unknown };
  }

  active(subject: string): unknown[] {
    return this.store.db
      .prepare(
        "SELECT id,pid,executable,status,started_at FROM process_sessions WHERE subject=? AND status='running' ORDER BY started_at DESC",
      )
      .all(subject);
  }

  shutdown(): void {
    if (this.shuttingDown) return;
    this.shuttingDown = true;
    for (const timer of this.timers.values()) clearTimeout(timer);
    this.timers.clear();
  }

  private row(id: string, subject: string): ProcessRow {
    const row = this.store.db
      .prepare("SELECT * FROM process_sessions WHERE id=? AND subject=?")
      .get(id, subject) as ProcessRow | undefined;
    if (!row) throw new AppError("SESSION_NOT_FOUND", "process session was not found");
    return row;
  }

  private async waitForIdentity(pid: number, child: ChildProcess): Promise<string | undefined> {
    for (let attempt = 0; attempt < 10; attempt += 1) {
      if (child.exitCode !== null || child.signalCode !== null) return undefined;
      const identity = await this.processIdentity(pid);
      if (identity) return identity;
      if (child.exitCode !== null || child.signalCode !== null) return undefined;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    return undefined;
  }

  private async processExists(pid: number): Promise<boolean> {
    if (!Number.isInteger(pid) || pid <= 0) return false;
    try {
      process.kill(pid, 0);
      return true;
    } catch (error) {
      return (error as NodeJS.ErrnoException).code === "EPERM";
    }
  }

  private async processIdentity(pid: number): Promise<string | undefined> {
    if (!Number.isInteger(pid) || pid <= 0) return undefined;
    const script = `$ErrorActionPreference='Stop'; $p=Get-Process -Id ${pid}; [Console]::Out.Write(($p.Id.ToString()+'|'+$p.StartTime.ToUniversalTime().Ticks.ToString()+'|'+$p.Path.ToLowerInvariant()))`;
    try {
      const { stdout } = await execFile(
        "powershell.exe",
        ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        {
          windowsHide: true,
          timeout: 5000,
          maxBuffer: 8192,
        },
      );
      return stdout.trim() || undefined;
    } catch {
      return undefined;
    }
  }
}
