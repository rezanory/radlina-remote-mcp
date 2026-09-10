import { mkdtemp, mkdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import { afterEach, describe, expect, it } from "vitest";

import { Store } from "../../src/persistence/store.js";

const cleanup: string[] = [];

afterEach(async () => {
  for (const directory of cleanup.splice(0)) await rm(directory, { recursive: true, force: true });
});

describe("OAuth database migration", () => {
  it("adds replay receipt columns to an existing database without losing refresh rows", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "radlina-oauth-migration-"));
    cleanup.push(root);
    const state = path.join(root, ".state");
    await mkdir(state, { recursive: true });
    const legacy = new DatabaseSync(path.join(state, "radlina.db"));
    legacy.exec(`
      CREATE TABLE oauth_refresh (
        token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, scope TEXT NOT NULL,
        resource TEXT NOT NULL, subject TEXT NOT NULL, expires_at INTEGER NOT NULL
      );
      INSERT INTO oauth_refresh(token_hash,client_id,scope,resource,subject,expires_at)
      VALUES('legacy-hash','legacy-client','device:read','http://127.0.0.1:7337/mcp','legacy-subject',4102444800000);
    `);
    legacy.close();

    const store = new Store(state);
    try {
      const columns = new Set(
        (store.db.prepare("PRAGMA table_info(oauth_refresh)").all() as Array<{ name: string }>).map(
          (row) => row.name,
        ),
      );
      expect([...columns]).toEqual(
        expect.arrayContaining(["consumed_at", "replacement_protected", "replacement_expires_at"]),
      );
      expect(
        store.db
          .prepare("SELECT client_id FROM oauth_refresh WHERE token_hash='legacy-hash'")
          .get(),
      ).toEqual({ client_id: "legacy-client" });
      expect(
        (store.db.prepare("PRAGMA table_info(oauth_events)").all() as Array<{ name: string }>).map(
          (row) => row.name,
        ),
      ).toEqual([
        "event_id",
        "created_at",
        "client_hash",
        "grant_type",
        "status",
        "latency_ms",
        "error_code",
      ]);
    } finally {
      store.close();
    }
  });
});
