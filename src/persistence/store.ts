import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import { AppError } from "../errors.js";

type IdempotencyRow = { subject: string; tool: string; args_hash: string; result_json: string };
type IdempotencyClaimRow = { key: string; subject: string; tool: string; args_hash: string };

export class Store {
  readonly db: DatabaseSync;

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
        resource TEXT NOT NULL, subject TEXT NOT NULL, expires_at INTEGER NOT NULL
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
      CREATE TABLE IF NOT EXISTS errors (
        correlation_id TEXT PRIMARY KEY, code TEXT NOT NULL, message TEXT NOT NULL,
        detail_json TEXT NOT NULL, created_at INTEGER NOT NULL
      );
    `);
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

  close(): void {
    this.db.close();
  }
}
