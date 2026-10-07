import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import { canonicalJson, sha256 } from "../../utils/json.js";
import { parseWorkflowDefinition, type WorkflowDefinition } from "./contracts.js";

export type WorkflowTriggerInput = {
  source: string;
  eventId: string;
  subject: string;
  workflow: WorkflowDefinition;
  payload: unknown;
};

export interface TriggerWorkflowSubmitPort {
  submit(input: {
    subject: string;
    idempotencyKey: string;
    workflow: WorkflowDefinition;
    trigger: { source: string; eventId: string; payload: unknown };
  }): Promise<string>;
}

export type TriggerAcceptance = {
  executionId: string;
  replayed: boolean;
};

export class WorkflowTriggerConflict extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WorkflowTriggerConflict";
  }
}

export class WorkflowTriggerRuntime {
  readonly db: DatabaseSync;

  constructor(
    databaseFile: string,
    private readonly submitter: TriggerWorkflowSubmitPort,
  ) {
    mkdirSync(path.dirname(databaseFile), { recursive: true });
    this.db = new DatabaseSync(databaseFile, { enableForeignKeyConstraints: true });
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS v3_trigger_events(
        source TEXT NOT NULL,
        event_id TEXT NOT NULL,
        subject TEXT NOT NULL,
        payload_hash TEXT NOT NULL,
        status TEXT NOT NULL,
        execution_id TEXT,
        last_error TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY(source,event_id)
      );
    `);
  }

  async accept(input: WorkflowTriggerInput): Promise<TriggerAcceptance> {
    if (!input.source.trim() || !input.eventId.trim() || !input.subject.trim()) {
      throw new WorkflowTriggerConflict("source, eventId and subject are required");
    }
    const workflow = parseWorkflowDefinition(input.workflow);
    const payloadHash = sha256(
      canonicalJson({
        subject: input.subject,
        workflow,
        payload: input.payload,
      }),
    );
    const existing = this.row(input.source, input.eventId);
    if (existing && existing.payload_hash !== payloadHash) {
      throw new WorkflowTriggerConflict("trigger id was reused with different content");
    }
    if (existing?.status === "submitted" && existing.execution_id) {
      return { executionId: existing.execution_id, replayed: true };
    }

    const now = Date.now();
    if (!existing) {
      this.db
        .prepare(
          "INSERT INTO v3_trigger_events(source,event_id,subject,payload_hash,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
        )
        .run(input.source, input.eventId, input.subject, payloadHash, "accepted", now, now);
    }

    const idempotencyKey = `trigger:${sha256(`${input.source}\n${input.eventId}`)}`;
    try {
      const executionId = await this.submitter.submit({
        subject: input.subject,
        idempotencyKey,
        workflow,
        trigger: {
          source: input.source,
          eventId: input.eventId,
          payload: input.payload,
        },
      });
      this.db
        .prepare(
          "UPDATE v3_trigger_events SET status='submitted',execution_id=?,last_error=NULL,updated_at=? WHERE source=? AND event_id=?",
        )
        .run(executionId, Date.now(), input.source, input.eventId);
      return { executionId, replayed: existing !== undefined };
    } catch (error) {
      this.db
        .prepare(
          "UPDATE v3_trigger_events SET status='failed',last_error=?,updated_at=? WHERE source=? AND event_id=?",
        )
        .run(
          error instanceof Error ? error.message.slice(0, 1000) : "submit failed",
          Date.now(),
          input.source,
          input.eventId,
        );
      throw error;
    }
  }

  status(source: string, eventId: string) {
    return this.row(source, eventId);
  }

  close(): void {
    this.db.close();
  }

  private row(
    source: string,
    eventId: string,
  ):
    | {
        source: string;
        event_id: string;
        subject: string;
        payload_hash: string;
        status: string;
        execution_id: string | null;
        last_error: string | null;
      }
    | undefined {
    return this.db
      .prepare(
        "SELECT source,event_id,subject,payload_hash,status,execution_id,last_error FROM v3_trigger_events WHERE source=? AND event_id=?",
      )
      .get(source, eventId) as
      | {
          source: string;
          event_id: string;
          subject: string;
          payload_hash: string;
          status: string;
          execution_id: string | null;
          last_error: string | null;
        }
      | undefined;
  }
}
