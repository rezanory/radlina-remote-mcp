import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import type { WorkflowDefinition } from "../../../src/v3/workflow/contracts.js";
import {
  WorkflowPersistenceConflict,
  WorkflowSqliteStore,
  type WorkflowPayloadCodec,
} from "../../../src/v3/workflow/persistence.js";

class Base64Codec implements WorkflowPayloadCodec {
  async encode(plaintext: string): Promise<string> {
    return Buffer.from(plaintext, "utf8").toString("base64");
  }

  async decode(encoded: string): Promise<string> {
    return Buffer.from(encoded, "base64").toString("utf8");
  }
}

const roots: string[] = [];

async function store(): Promise<{ root: string; store: WorkflowSqliteStore }> {
  const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-workflow-"));
  roots.push(root);
  return {
    root,
    store: new WorkflowSqliteStore(path.join(root, "workflow.sqlite3"), new Base64Codec()),
  };
}

function definition(title = "Persistence acceptance"): WorkflowDefinition {
  return {
    workflowId: "persistence.acceptance",
    definitionVersion: "1.0.0",
    title,
    nodes: [
      {
        id: "health",
        capability: "device.health",
        input: { secret: "secret-value" },
        dependsOn: [],
        target: { deviceId: "windows-main" },
        maxAttempts: 1,
        timeoutMs: 5_000,
        executionPolicy: {
          failureMode: "fail-workflow",
          allowDynamicReroute: false,
          unknownOutcome: "manual-resume",
        },
        expectedOutput: {
          contractId: "device.health/v1",
          artifactMode: "inline",
          maxBytes: 65_536,
        },
      },
    ],
  };
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("V3 WorkflowSqliteStore", () => {
  it("persists and reloads an encoded canonical workflow definition", async () => {
    const runtime = await store();
    await expect(runtime.store.create("wf-1", "owner", "idem-1", definition())).resolves.toEqual({
      executionId: "wf-1",
      replayed: false,
    });

    const loaded = await runtime.store.definition("wf-1");
    expect(loaded.nodes[0]?.input).toEqual({ secret: "secret-value" });
    expect(runtime.store.snapshot("wf-1")).toMatchObject({
      executionId: "wf-1",
      subject: "owner",
      status: "queued",
      nodes: [{ id: "health", status: "pending", attempts: 0, maxAttempts: 1 }],
    });

    const raw = runtime.store.db
      .prepare("SELECT definition_encoded FROM v3_workflows WHERE execution_id=?")
      .get("wf-1") as { definition_encoded: string };
    expect(raw.definition_encoded).not.toContain("secret-value");
    runtime.store.close();
  });

  it("replays an identical idempotent create and rejects conflicting reuse", async () => {
    const runtime = await store();
    await runtime.store.create("wf-1", "owner", "idem-1", definition());
    await expect(runtime.store.create("wf-2", "owner", "idem-1", definition())).resolves.toEqual({
      executionId: "wf-1",
      replayed: true,
    });
    await expect(
      runtime.store.create("wf-3", "owner", "idem-1", definition("Different")),
    ).rejects.toThrow(WorkflowPersistenceConflict);
    runtime.store.close();
  });

  it("persists valid workflow and node transitions with durable ordered events", async () => {
    const runtime = await store();
    await runtime.store.create("wf-1", "owner", "idem-1", definition());

    expect(runtime.store.transitionWorkflow("wf-1", "running")).toBe("running");
    expect(runtime.store.transitionNode("wf-1", "health", "ready")).toBe("ready");
    expect(runtime.store.transitionNode("wf-1", "health", "running")).toBe("running");
    expect(runtime.store.transitionNode("wf-1", "health", "completed")).toBe("completed");
    expect(runtime.store.transitionWorkflow("wf-1", "completed")).toBe("completed");

    expect(runtime.store.snapshot("wf-1")).toMatchObject({
      status: "completed",
      nodes: [{ id: "health", status: "completed" }],
    });
    const events = runtime.store.events("wf-1") as Array<{ sequence: number; to_state: string }>;
    expect(events.map((event) => event.sequence)).toEqual([1, 2, 3, 4, 5, 6]);
    expect(events.at(-1)?.to_state).toBe("completed");
    runtime.store.close();
  });

  it("leaves durable state unchanged when a transition is invalid", async () => {
    const runtime = await store();
    await runtime.store.create("wf-1", "owner", "idem-1", definition());
    runtime.store.transitionWorkflow("wf-1", "running");
    runtime.store.transitionWorkflow("wf-1", "completed");

    expect(() => runtime.store.transitionWorkflow("wf-1", "running")).toThrow(
      /invalid workflow transition/u,
    );
    expect(runtime.store.snapshot("wf-1").status).toBe("completed");
    expect(runtime.store.events("wf-1")).toHaveLength(3);
    runtime.store.close();
  });

  it("fails closed for missing execution and node identities", async () => {
    const runtime = await store();
    expect(() => runtime.store.snapshot("missing")).toThrow(WorkflowPersistenceConflict);
    await runtime.store.create("wf-1", "owner", "idem-1", definition());
    expect(() => runtime.store.transitionNode("wf-1", "missing", "ready")).toThrow(
      WorkflowPersistenceConflict,
    );
    runtime.store.close();
  });
});
