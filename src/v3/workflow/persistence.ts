import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import { canonicalJson, sha256 } from "../../utils/json.js";
import {
  parseWorkflowDefinition,
  type NodeState,
  type WorkflowDefinition,
  type WorkflowState,
} from "./contracts.js";
import { transitionNode, transitionWorkflow } from "./state-machine.js";

export interface WorkflowPayloadCodec {
  encode(plaintext: string): Promise<string>;
  decode(encoded: string): Promise<string>;
}

export type WorkflowSnapshot = {
  executionId: string;
  subject: string;
  status: WorkflowState;
  definitionSha256: string;
  nodes: Array<{ id: string; status: NodeState; attempts: number; maxAttempts: number }>;
};

export class WorkflowPersistenceConflict extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WorkflowPersistenceConflict";
  }
}

export class WorkflowSqliteStore {
  readonly db: DatabaseSync;

  constructor(
    databaseFile: string,
    private readonly codec: WorkflowPayloadCodec,
  ) {
    mkdirSync(path.dirname(databaseFile), { recursive: true });
    this.db = new DatabaseSync(databaseFile, { enableForeignKeyConstraints: true });
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS v3_workflows(
        execution_id TEXT PRIMARY KEY, subject TEXT NOT NULL, idempotency_key TEXT NOT NULL,
        status TEXT NOT NULL, definition_encoded TEXT NOT NULL, definition_sha256 TEXT NOT NULL,
        created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
        UNIQUE(subject,idempotency_key)
      );
      CREATE TABLE IF NOT EXISTS v3_workflow_nodes(
        execution_id TEXT NOT NULL, node_id TEXT NOT NULL, ordinal INTEGER NOT NULL,
        status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL,
        PRIMARY KEY(execution_id,node_id), UNIQUE(execution_id,ordinal),
        FOREIGN KEY(execution_id) REFERENCES v3_workflows(execution_id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS v3_workflow_events(
        sequence INTEGER PRIMARY KEY AUTOINCREMENT, execution_id TEXT NOT NULL, node_id TEXT,
        kind TEXT NOT NULL, from_state TEXT, to_state TEXT NOT NULL, created_at INTEGER NOT NULL,
        FOREIGN KEY(execution_id) REFERENCES v3_workflows(execution_id) ON DELETE CASCADE
      );
    `);
  }

  async create(
    executionId: string,
    subject: string,
    idempotencyKey: string,
    rawDefinition: WorkflowDefinition,
  ): Promise<{ executionId: string; replayed: boolean }> {
    if (!executionId.trim() || !subject.trim() || !idempotencyKey.trim()) {
      throw new WorkflowPersistenceConflict("executionId, subject and idempotencyKey are required");
    }
    const definition = parseWorkflowDefinition(rawDefinition);
    const canonical = canonicalJson(definition);
    const definitionSha256 = sha256(canonical);
    const existing = this.db
      .prepare(
        "SELECT execution_id,definition_sha256 FROM v3_workflows WHERE subject=? AND idempotency_key=?",
      )
      .get(subject, idempotencyKey) as
      { execution_id: string; definition_sha256: string } | undefined;
    if (existing) {
      if (existing.definition_sha256 !== definitionSha256) {
        throw new WorkflowPersistenceConflict("idempotency key conflicts with another definition");
      }
      return { executionId: existing.execution_id, replayed: true };
    }

    const encoded = await this.codec.encode(canonical);
    const now = Date.now();
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db
        .prepare(
          "INSERT INTO v3_workflows(execution_id,subject,idempotency_key,status,definition_encoded,definition_sha256,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
        )
        .run(executionId, subject, idempotencyKey, "queued", encoded, definitionSha256, now, now);
      const insertNode = this.db.prepare(
        "INSERT INTO v3_workflow_nodes(execution_id,node_id,ordinal,status,attempts,max_attempts) VALUES(?,?,?,?,?,?)",
      );
      definition.nodes.forEach((node, ordinal) => {
        insertNode.run(executionId, node.id, ordinal, "pending", 0, node.maxAttempts);
      });
      this.event(executionId, null, "workflow.created", null, "queued", now);
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
    return { executionId, replayed: false };
  }

  async definition(executionId: string): Promise<WorkflowDefinition> {
    const row = this.db
      .prepare("SELECT definition_encoded FROM v3_workflows WHERE execution_id=?")
      .get(executionId) as { definition_encoded: string } | undefined;
    if (!row) throw new WorkflowPersistenceConflict("workflow execution was not found");
    return parseWorkflowDefinition(JSON.parse(await this.codec.decode(row.definition_encoded)));
  }

  snapshot(executionId: string): WorkflowSnapshot {
    const workflow = this.db
      .prepare(
        "SELECT execution_id,subject,status,definition_sha256 FROM v3_workflows WHERE execution_id=?",
      )
      .get(executionId) as
      | { execution_id: string; subject: string; status: string; definition_sha256: string }
      | undefined;
    if (!workflow) throw new WorkflowPersistenceConflict("workflow execution was not found");
    const nodes = this.db
      .prepare(
        "SELECT node_id,status,attempts,max_attempts FROM v3_workflow_nodes WHERE execution_id=? ORDER BY ordinal",
      )
      .all(executionId) as Array<{
      node_id: string;
      status: string;
      attempts: number;
      max_attempts: number;
    }>;
    return {
      executionId: workflow.execution_id,
      subject: workflow.subject,
      status: workflow.status as WorkflowState,
      definitionSha256: workflow.definition_sha256,
      nodes: nodes.map((node) => ({
        id: node.node_id,
        status: node.status as NodeState,
        attempts: node.attempts,
        maxAttempts: node.max_attempts,
      })),
    };
  }

  transitionWorkflow(executionId: string, to: WorkflowState): WorkflowState {
    const from = this.snapshot(executionId).status;
    transitionWorkflow(from, to);
    this.atomicStateChange(executionId, null, "v3_workflows", "execution_id", from, to);
    return to;
  }

  transitionNode(executionId: string, nodeId: string, to: NodeState): NodeState {
    const row = this.db
      .prepare("SELECT status FROM v3_workflow_nodes WHERE execution_id=? AND node_id=?")
      .get(executionId, nodeId) as { status: string } | undefined;
    if (!row) throw new WorkflowPersistenceConflict("workflow node was not found");
    const from = row.status as NodeState;
    transitionNode(from, to);
    this.atomicStateChange(executionId, nodeId, "v3_workflow_nodes", "node_id", from, to);
    return to;
  }

  events(executionId: string): unknown[] {
    return this.db
      .prepare(
        "SELECT sequence,node_id,kind,from_state,to_state,created_at FROM v3_workflow_events WHERE execution_id=? ORDER BY sequence",
      )
      .all(executionId);
  }

  close(): void {
    this.db.close();
  }

  private atomicStateChange(
    executionId: string,
    nodeId: string | null,
    table: "v3_workflows" | "v3_workflow_nodes",
    identityColumn: "execution_id" | "node_id",
    from: string,
    to: string,
  ): void {
    const now = Date.now();
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const statement =
        table === "v3_workflows"
          ? "UPDATE v3_workflows SET status=?,updated_at=? WHERE execution_id=? AND status=?"
          : "UPDATE v3_workflow_nodes SET status=? WHERE execution_id=? AND node_id=? AND status=?";
      const result =
        identityColumn === "execution_id"
          ? this.db.prepare(statement).run(to, now, executionId, from)
          : this.db.prepare(statement).run(to, executionId, nodeId, from);
      if (Number(result.changes) !== 1)
        throw new WorkflowPersistenceConflict("state changed concurrently");
      if (nodeId !== null) {
        this.db
          .prepare("UPDATE v3_workflows SET updated_at=? WHERE execution_id=?")
          .run(now, executionId);
      }
      this.event(
        executionId,
        nodeId,
        nodeId === null ? "workflow.transition" : "node.transition",
        from,
        to,
        now,
      );
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  private event(
    executionId: string,
    nodeId: string | null,
    kind: string,
    from: string | null,
    to: string,
    at: number,
  ): void {
    this.db
      .prepare(
        "INSERT INTO v3_workflow_events(execution_id,node_id,kind,from_state,to_state,created_at) VALUES(?,?,?,?,?,?)",
      )
      .run(executionId, nodeId, kind, from, to, at);
  }
}
