import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import { AppError } from "../errors.js";

type IdempotencyRow = { subject: string; tool: string; args_hash: string; result_json: string };
type IdempotencyClaimRow = { key: string; subject: string; tool: string; args_hash: string };

export class Store {
  readonly db: DatabaseSync;
  private open = true;

  constructor(directory: string) {
    mkdirSync(directory, { recursive: true });
    this.db = new DatabaseSync(path.join(directory, "radlina.db"), {
      enableForeignKeyConstraints: true,
    });
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.migrate();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS idempotency (
        key TEXT PRIMARY KEY, subject TEXT NOT NULL, tool TEXT NOT NULL, args_hash TEXT NOT NULL,
        result_json TEXT NOT NULL, created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS idempotency_claims (
        key TEXT PRIMARY KEY, subject TEXT NOT NULL, tool TEXT NOT NULL, args_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS oauth_clients (
        client_id TEXT PRIMARY KEY, metadata_json TEXT NOT NULL, created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS oauth_codes (
        code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
        challenge TEXT NOT NULL, scope TEXT NOT NULL, resource TEXT NOT NULL,
        subject TEXT NOT NULL, expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS oauth_approvals (
        id TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
        challenge TEXT NOT NULL, scope TEXT NOT NULL, resource TEXT NOT NULL,
        state TEXT, subject TEXT, approved INTEGER NOT NULL DEFAULT 0,
        expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS oauth_refresh (
        token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, scope TEXT NOT NULL,
        resource TEXT NOT NULL, subject TEXT NOT NULL, expires_at INTEGER NOT NULL,
        consumed_at INTEGER, replacement_protected TEXT, replacement_expires_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS oauth_events (
        event_id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, client_hash TEXT NOT NULL,
        grant_type TEXT NOT NULL, status TEXT NOT NULL, latency_ms INTEGER NOT NULL,
        error_code TEXT
      );
      CREATE TABLE IF NOT EXISTS oauth_owner_enrollments (
        enrollment_id TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
        resource TEXT NOT NULL, scope TEXT NOT NULL, subject TEXT NOT NULL,
        created_at INTEGER NOT NULL, last_used_at INTEGER NOT NULL, revoked_at INTEGER,
        UNIQUE(client_id, redirect_uri, resource)
      );
      CREATE TABLE IF NOT EXISTS pairing_codes (
        code_hash TEXT PRIMARY KEY, subject TEXT NOT NULL, expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS process_sessions (
        id TEXT PRIMARY KEY, subject TEXT NOT NULL, profile TEXT NOT NULL, pid INTEGER,
        executable TEXT NOT NULL, args_json TEXT NOT NULL, output_path TEXT NOT NULL,
        status TEXT NOT NULL, started_at INTEGER NOT NULL, ended_at INTEGER, exit_code INTEGER,
        start_identity TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS search_sessions (
        id TEXT PRIMARY KEY, subject TEXT NOT NULL, profile TEXT NOT NULL, pid INTEGER,
        query_json TEXT NOT NULL, result_path TEXT NOT NULL, status TEXT NOT NULL,
        started_at INTEGER NOT NULL, ended_at INTEGER, exit_code INTEGER
      );
      CREATE TABLE IF NOT EXISTS reliability_events (
        event_id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, kind TEXT NOT NULL,
        status TEXT NOT NULL, details_json TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS errors (
        correlation_id TEXT PRIMARY KEY, code TEXT NOT NULL, message TEXT NOT NULL,
        detail_json TEXT NOT NULL, created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS operator_jobs (
        id TEXT PRIMARY KEY, subject TEXT NOT NULL, profile TEXT NOT NULL, title TEXT NOT NULL,
        status TEXT NOT NULL, cancel_requested INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
        started_at INTEGER, ended_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS operator_steps (
        job_id TEXT NOT NULL, step_id TEXT NOT NULL, ordinal INTEGER NOT NULL,
        capability TEXT NOT NULL, input_protected TEXT NOT NULL, input_sha256 TEXT NOT NULL,
        status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL,
        result_protected TEXT, error_protected TEXT, started_at INTEGER, ended_at INTEGER,
        PRIMARY KEY(job_id, step_id), UNIQUE(job_id, ordinal),
        FOREIGN KEY(job_id) REFERENCES operator_jobs(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS operator_jobs_subject_created
        ON operator_jobs(subject, created_at DESC);
      CREATE INDEX IF NOT EXISTS operator_steps_job_ordinal
        ON operator_steps(job_id, ordinal);
    `);
    const refreshColumns = new Set(
      (this.db.prepare("PRAGMA table_info(oauth_refresh)").all() as Array<{ name: string }>).map(
        (row) => row.name,
      ),
    );
    if (!refreshColumns.has("consumed_at"))
      this.db.exec("ALTER TABLE oauth_refresh ADD COLUMN consumed_at INTEGER");
    if (!refreshColumns.has("replacement_protected"))
      this.db.exec("ALTER TABLE oauth_refresh ADD COLUMN replacement_protected TEXT");
    if (!refreshColumns.has("replacement_expires_at"))
      this.db.exec("ALTER TABLE oauth_refresh ADD COLUMN replacement_expires_at INTEGER");
  }

  get(key: string): string | undefined {
    const row = this.db.prepare("SELECT value FROM kv WHERE key = ?").get(key) as
      { value: string } | undefined;
    return row?.value;
  }

  set(key: string, value: string): void {
    this.db
      .prepare(
        "INSERT INTO kv(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
      )
      .run(key, value, Date.now());
  }

  idempotentResult(key: string, subject: string, tool: string, argsHash: string): unknown {
    const row = this.db
      .prepare("SELECT subject,tool,args_hash,result_json FROM idempotency WHERE key=?")
      .get(key) as IdempotencyRow | undefined;
    if (!row) return undefined;
    if (row.subject !== subject || row.tool !== tool || row.args_hash !== argsHash) {
      throw new AppError("CONFLICT", "Idempotency key was already used with different arguments");
    }
    return JSON.parse(row.result_json) as unknown;
  }

  saveIdempotentResult(
    key: string,
    subject: string,
    tool: string,
    argsHash: string,
    result: unknown,
  ): void {
    const encoded = JSON.stringify(result);
    if (encoded === undefined) throw new AppError("INTERNAL_ERROR", "result is not serializable");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db
        .prepare(
          "INSERT INTO idempotency(key,subject,tool,args_hash,result_json,created_at) VALUES(?,?,?,?,?,?)",
        )
        .run(key, subject, tool, argsHash, encoded, Date.now());
      this.db.prepare("DELETE FROM idempotency_claims WHERE key=?").run(key);
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  claimIdempotency(key: string, subject: string, tool: string, argsHash: string): boolean {
    const inserted = this.db
      .prepare(
        "INSERT OR IGNORE INTO idempotency_claims(key,subject,tool,args_hash,created_at) VALUES(?,?,?,?,?)",
      )
      .run(key, subject, tool, argsHash, Date.now());
    if (Number(inserted.changes) === 1) return true;
    const existing = this.db
      .prepare("SELECT key,subject,tool,args_hash FROM idempotency_claims WHERE key=?")
      .get(key) as IdempotencyClaimRow | undefined;
    if (
      existing &&
      (existing.subject !== subject || existing.tool !== tool || existing.args_hash !== argsHash)
    ) {
      throw new AppError("CONFLICT", "Idempotency key is claimed by a different request");
    }
    return false;
  }

  pendingIdempotency(limit = 100): unknown[] {
    const bounded = Math.min(Math.max(limit, 1), 500);
    return this.db
      .prepare(
        "SELECT key,subject,tool,args_hash,created_at FROM idempotency_claims ORDER BY created_at DESC LIMIT ?",
      )
      .all(bounded);
  }

  clearIdempotencyClaim(key: string): boolean {
    const result = this.db.prepare("DELETE FROM idempotency_claims WHERE key=?").run(key);
    return Number(result.changes) === 1;
  }

  isOpen(): boolean {
    return this.open;
  }

  close(): void {
    if (!this.open) return;
    this.open = false;
    this.db.close();
  }
}
