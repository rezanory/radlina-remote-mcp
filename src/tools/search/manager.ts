import { spawn, type ChildProcess } from "node:child_process";
import { createWriteStream } from "node:fs";
import { mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";
import readline from "node:readline";

import type { AppConfig } from "../../config/schema.js";
import { AppError } from "../../errors.js";
import type { Store } from "../../persistence/store.js";
import { decodeCursor, encodeCursor, sha256 } from "../../utils/json.js";
import type { SafePathResolver } from "../filesystem/safe-path.js";

export type SearchQuery = {
  mode: "files" | "content";
  path: string;
  pattern: string;
  glob?: string[];
  caseSensitive?: boolean;
  literal?: boolean;
  maxResults?: number;
};

type SearchCursor = { id: string; index: number };
type SessionRow = {
  id: string;
  subject: string;
  profile: string;
  pid: number | null;
  result_path: string;
  status: string;
  started_at: number;
  ended_at: number | null;
  exit_code: number | null;
};

export class SearchManager {
  private readonly running = new Map<string, ChildProcess>();
  private readonly directory: string;

  constructor(
    private readonly config: AppConfig,
    private readonly store: Store,
  ) {
    this.directory = path.join(config.storage.directory, "search");
  }

  reconcile(): void {
    this.store.db
      .prepare("UPDATE search_sessions SET status='interrupted',ended_at=? WHERE status='running'")
      .run(Date.now());
  }

  async start(
    subject: string,
    profile: string,
    resolver: SafePathResolver,
    query: SearchQuery,
  ): Promise<unknown> {
    if (query.pattern.length === 0 || query.pattern.length > 512)
      throw new AppError("INVALID_INPUT", "search pattern length is invalid");
    let filenameMatcher: RegExp | undefined;
    if (query.mode === "files") {
      try {
        filenameMatcher = query.literal
          ? new RegExp(
              query.pattern.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"),
              query.caseSensitive ? "u" : "iu",
            )
          : new RegExp(query.pattern, query.caseSensitive ? "u" : "iu");
      } catch {
        throw new AppError(
          "INVALID_INPUT",
          "filename search pattern is not a valid regular expression",
        );
      }
    }
    const active = this.store.db
      .prepare("SELECT COUNT(*) AS count FROM search_sessions WHERE status='running'")
      .get() as { count: number };
    if (active.count >= this.config.policy.maxSessions)
      throw new AppError("LIMIT_EXCEEDED", "search session limit reached");
    const root = await resolver.resolve(query.path, { mustExist: true });
    const id = randomUUID();
    await mkdir(this.directory, { recursive: true });
    const resultPath = path.join(this.directory, `${id}.jsonl`);
    const args = this.rgArgs(root, query);
    const child = spawn(this.config.dependencies.ripgrepExecutable, args, {
      windowsHide: true,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });
    this.running.set(id, child);
    this.store.db
      .prepare(
        "INSERT INTO search_sessions(id,subject,profile,pid,query_json,result_path,status,started_at) VALUES(?,?,?,?,?,?,?,?)",
      )
      .run(
        id,
        subject,
        profile,
        child.pid ?? null,
        JSON.stringify({ ...query, pattern: `[sha256:${sha256(query.pattern)}]`, path: root }),
        resultPath,
        "running",
        Date.now(),
      );

    const output = createWriteStream(resultPath, { flags: "wx", encoding: "utf8", mode: 0o600 });
    const lines = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
    const maxResults = Math.min(Math.max(query.maxResults ?? 1000, 1), 10_000);
    let count = 0;
    let outputBytes = 0;
    let stderr = "";
    lines.on("line", (line) => {
      if (count >= maxResults || outputBytes >= this.config.policy.maxOutputBytes) return;
      const parsed = this.parseLine(line, query.mode, filenameMatcher);
      if (!parsed) return;
      const encoded = `${JSON.stringify(parsed)}\n`;
      if (outputBytes + Buffer.byteLength(encoded) > this.config.policy.maxOutputBytes) return;
      output.write(encoded);
      outputBytes += Buffer.byteLength(encoded);
      count += 1;
      if (count >= maxResults) child.kill("SIGTERM");
    });
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      if (stderr.length < 2048) stderr += chunk;
    });
    const timer = setTimeout(() => child.kill("SIGTERM"), this.config.policy.maxSearchRuntimeMs);
    timer.unref();
    child.on("error", () => {
      clearTimeout(timer);
      output.end();
      this.running.delete(id);
      this.store.db
        .prepare("UPDATE search_sessions SET status='error',ended_at=? WHERE id=?")
        .run(Date.now(), id);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      output.end();
      this.running.delete(id);
      const status = code === 0 || code === 1 || count >= maxResults ? "complete" : "error";
      this.store.db
        .prepare(
          "UPDATE search_sessions SET status=?,ended_at=?,exit_code=? WHERE id=? AND status='running'",
        )
        .run(status, Date.now(), code, id);
      if (stderr) this.store.set(`search:${id}:stderr`, stderr.slice(0, 512));
      this.store.set(`search:${id}:count`, String(count));
    });
    return {
      searchId: id,
      status: "running",
      pid: child.pid ?? null,
      resultCursor: encodeCursor({ id, index: 0 }),
    };
  }

  status(id: string, subject: string): unknown {
    const row = this.row(id, subject);
    return {
      searchId: row.id,
      status: row.status,
      startedAt: new Date(row.started_at).toISOString(),
      endedAt: row.ended_at ? new Date(row.ended_at).toISOString() : null,
      exitCode: row.exit_code,
      resultCount: Number(this.store.get(`search:${id}:count`) ?? "0"),
      error:
        row.status === "error" ? (this.store.get(`search:${id}:stderr`) ?? "search failed") : null,
    };
  }

  async results(id: string, subject: string, cursor?: string, limit = 100): Promise<unknown> {
    const row = this.row(id, subject);
    const parsed = cursor ? decodeCursor<SearchCursor>(cursor) : { id, index: 0 };
    if (parsed.id !== id || !Number.isInteger(parsed.index) || parsed.index < 0)
      throw new AppError("INVALID_INPUT", "invalid result cursor");
    let lines: string[] = [];
    try {
      lines = (await readFile(row.result_path, "utf8")).split(/\r?\n/u).filter(Boolean);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    const bounded = Math.min(Math.max(limit, 1), 500);
    const page = lines
      .slice(parsed.index, parsed.index + bounded)
      .map((line) => JSON.parse(line) as unknown);
    const next = parsed.index + page.length;
    const mayGrow = row.status === "running";
    return {
      searchId: id,
      results: page,
      nextCursor: next < lines.length || mayGrow ? encodeCursor({ id, index: next }) : null,
      status: row.status,
    };
  }

  cancel(id: string, subject: string): unknown {
    const row = this.row(id, subject);
    const child = this.running.get(id);
    if (child && !child.killed) child.kill("SIGTERM");
    this.store.db
      .prepare(
        "UPDATE search_sessions SET status='cancelled',ended_at=? WHERE id=? AND status='running'",
      )
      .run(Date.now(), id);
    return {
      searchId: row.id,
      cancelled: Boolean(child),
      status: child ? "cancelling" : row.status,
    };
  }

  active(subject: string): unknown[] {
    return this.store.db
      .prepare(
        "SELECT id,status,started_at FROM search_sessions WHERE subject=? AND status='running' ORDER BY started_at DESC",
      )
      .all(subject);
  }

  private rgArgs(root: string, query: SearchQuery): string[] {
    const args = ["--no-config", "--color", "never"];
    for (const glob of query.glob?.slice(0, 32) ?? []) args.push("--glob", glob);
    if (!query.caseSensitive) args.push("--ignore-case");
    if (query.mode === "files") return [...args, "--files", root];
    args.push(
      "--json",
      "--max-columns",
      "4096",
      "--max-count",
      String(Math.min(query.maxResults ?? 1000, 10_000)),
    );
    if (query.literal) args.push("--fixed-strings");
    return [...args, "--", query.pattern, root];
  }

  private parseLine(line: string, mode: SearchQuery["mode"], filenameMatcher?: RegExp): unknown {
    if (mode === "files") {
      if (!filenameMatcher?.test(path.basename(line))) return undefined;
      return { type: "file", path: line };
    }
    try {
      const event = JSON.parse(line) as {
        type?: string;
        data?: { path?: { text?: string }; line_number?: number; lines?: { text?: string } };
      };
      if (event.type !== "match") return undefined;
      return {
        type: "match",
        path: event.data?.path?.text,
        line: event.data?.line_number,
        text: event.data?.lines?.text?.replace(/\r?\n$/u, ""),
      };
    } catch {
      return undefined;
    }
  }

  private row(id: string, subject: string): SessionRow {
    const row = this.store.db
      .prepare("SELECT * FROM search_sessions WHERE id=? AND subject=?")
      .get(id, subject) as SessionRow | undefined;
    if (!row) throw new AppError("SESSION_NOT_FOUND", "search session was not found");
    return row;
  }
}
