import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import { canonicalJson, sha256 } from "../../utils/json.js";
import {
  fleetPlanSchema,
  type FleetEvent,
  type FleetPlan,
  type FleetPlanState,
} from "./contracts.js";

type PlanRow = {
  plan_json: string;
  state: FleetPlanState;
  transition_count: number;
};

export type FleetPlanSnapshot = {
  plan: FleetPlan;
  state: FleetPlanState;
  transitionCount: number;
  eventCount: number;
};

export class FleetStoreConflict extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FleetStoreConflict";
  }
}

/** Dedicated V3 SQLite journal. No V2 release manifest or service is ever modified here. */
export class SqliteFleetStore {
  readonly db: DatabaseSync;

  constructor(databaseFile: string) {
    if (!path.isAbsolute(databaseFile)) {
      throw new FleetStoreConflict("absolute independent database path is required");
    }
    mkdirSync(path.dirname(databaseFile), { recursive: true });
    this.db = new DatabaseSync(databaseFile, { enableForeignKeyConstraints: true });
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS v3_fleet_plans (
        plan_id TEXT PRIMARY KEY,
        idempotency_key TEXT NOT NULL UNIQUE,
        plan_json TEXT NOT NULL,
        state TEXT NOT NULL,
        transition_count INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS v3_fleet_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        plan_id TEXT NOT NULL REFERENCES v3_fleet_plans(plan_id),
        event_json TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL
      );
    `);
  }

  private transaction<T>(execute: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const output = execute();
      this.db.exec("COMMIT");
      return output;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  create(rawPlan: FleetPlan, atMs: number): { snapshot: FleetPlanSnapshot; replayed: boolean } {
    const plan = fleetPlanSchema.parse(rawPlan);
    return this.transaction(() => {
      const existing = this.db
        .prepare("SELECT plan_id FROM v3_fleet_plans WHERE idempotency_key=?")
        .get(plan.idempotencyKey) as { plan_id: string } | undefined;
      if (existing) {
        const record = this.get(existing.plan_id);
        if (!record || canonicalJson(record.plan) !== canonicalJson(plan)) {
          throw new FleetStoreConflict("idempotency collision or plan identity mismatch");
        }
        return { snapshot: record, replayed: true };
      }
      const activeRows = this.db
        .prepare(
          "SELECT plan_json FROM v3_fleet_plans WHERE state IN ('planned','preflighting','ready','canary','rolling_out','rollback_pending','manual_intervention')",
        )
        .all() as Array<{ plan_json: string }>;
      const selected = new Set(plan.targetDeviceIds);
      for (const row of activeRows) {
        const other = fleetPlanSchema.parse(JSON.parse(row.plan_json));
        if (other.targetDeviceIds.some((id) => selected.has(id))) {
          throw new FleetStoreConflict(
            "another unresolved fleet plan already owns a selected device",
          );
        }
      }
      this.db
        .prepare(
          "INSERT INTO v3_fleet_plans(plan_id,idempotency_key,plan_json,state,transition_count) VALUES(?,?,?,'planned',0)",
        )
        .run(plan.planId, plan.idempotencyKey, canonicalJson(plan));
      this.appendEvent({ kind: "planned", planId: plan.planId, atMs });
      return { snapshot: this.get(plan.planId)!, replayed: false };
    });
  }

  get(planId: string): FleetPlanSnapshot | undefined {
    const row = this.db
      .prepare("SELECT plan_json,state,transition_count FROM v3_fleet_plans WHERE plan_id=?")
      .get(planId) as PlanRow | undefined;
    if (!row) return undefined;
    const events = this.db
      .prepare("SELECT COUNT(*) AS n FROM v3_fleet_events WHERE plan_id=?")
      .get(planId) as { n: number };
    return {
      plan: fleetPlanSchema.parse(JSON.parse(row.plan_json)),
      state: row.state,
      transitionCount: row.transition_count,
      eventCount: events.n,
    };
  }

  require(planId: string): FleetPlanSnapshot {
    const record = this.get(planId);
    if (!record) throw new FleetStoreConflict("fleet plan not found");
    return record;
  }

  /** Durable compare-and-swap; always journals state change in same transaction. */
  transition(
    planId: string,
    expected: FleetPlanState,
    next: FleetPlanState,
    atMs: number,
    detailsHash?: string,
  ): FleetPlanSnapshot {
    return this.transaction(() => {
      const current = this.require(planId);
      if (current.state !== expected) {
        throw new FleetStoreConflict(
          `fleet state conflict: expected ${expected}, got ${current.state}`,
        );
      }
      const changed = this.db
        .prepare(
          "UPDATE v3_fleet_plans SET state=?, transition_count=transition_count+1 WHERE plan_id=? AND state=?",
        )
        .run(next, planId, expected);
      if (Number(changed.changes) !== 1) throw new FleetStoreConflict("fleet state CAS failed");
      this.appendEvent({
        kind: `state.${expected}->${next}`,
        planId,
        atMs,
        ...(detailsHash ? { detailsHash } : {}),
      });
      return this.require(planId);
    });
  }

  record(event: FleetEvent): void {
    this.transaction(() => {
      this.require(event.planId);
      this.appendEvent(event);
    });
  }

  /** Hash-linked local chain. S03 must independently sign/anchor the final hash. */
  verifyAuditChain(): { valid: boolean; events: number; headHash: string } {
    const rows = this.db
      .prepare("SELECT event_json,previous_hash,event_hash FROM v3_fleet_events ORDER BY sequence")
      .all() as Array<{ event_json: string; previous_hash: string; event_hash: string }>;
    let previous = "0".repeat(64);
    for (const row of rows) {
      if (
        row.previous_hash !== previous ||
        row.event_hash !== sha256(previous + "|" + row.event_json)
      ) {
        return { valid: false, events: rows.length, headHash: previous };
      }
      previous = row.event_hash;
    }
    return { valid: true, events: rows.length, headHash: previous };
  }

  private appendEvent(event: FleetEvent): void {
    const last = this.db
      .prepare("SELECT event_hash FROM v3_fleet_events ORDER BY sequence DESC LIMIT 1")
      .get() as { event_hash: string } | undefined;
    const previous = last?.event_hash ?? "0".repeat(64);
    const json = canonicalJson(event);
    this.db
      .prepare(
        "INSERT INTO v3_fleet_events(plan_id,event_json,previous_hash,event_hash) VALUES(?,?,?,?)",
      )
      .run(event.planId, json, previous, sha256(previous + "|" + json));
  }

  close(): void {
    this.db.close();
  }
}
