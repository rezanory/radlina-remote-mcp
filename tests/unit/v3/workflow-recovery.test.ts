import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import type { WorkflowDefinition } from "../../../src/v3/workflow/contracts.js";
import {
  WorkflowSqliteStore,
  type WorkflowPayloadCodec,
} from "../../../src/v3/workflow/persistence.js";
import {
  WorkflowRecoveryEngine,
  WorkflowRecoveryError,
  type RecoveryReceipt,
} from "../../../src/v3/workflow/recovery.js";

class Codec implements WorkflowPayloadCodec {
  async encode(value: string): Promise<string> {
    return Buffer.from(value).toString("base64");
  }
  async decode(value: string): Promise<string> {
    return Buffer.from(value, "base64").toString("utf8");
  }
}

const roots: string[] = [];

async function runtime(maxAttempts = 2, receipt: RecoveryReceipt = undefined, idempotent = true) {
  const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-recovery-"));
  roots.push(root);
  const store = new WorkflowSqliteStore(path.join(root, "workflow.sqlite3"), new Codec());
  const definition: WorkflowDefinition = {
    workflowId: "recovery.acceptance",
    definitionVersion: "1.0.0",
    title: "Recovery acceptance",
    nodes: [
      {
        id: "step",
        capability: "example.run",
        input: {},
        dependsOn: [],
        target: { deviceId: "windows-main" },
        maxAttempts,
        timeoutMs: 5_000,
        executionPolicy: {
          failureMode: "fail-workflow",
          allowDynamicReroute: false,
          unknownOutcome: "manual-resume",
        },
        expectedOutput: {
          contractId: "example/v1",
          artifactMode: "inline",
          maxBytes: 1024,
        },
      },
    ],
  };
  await store.create("wf-1", "owner", "idem-1", definition);
  store.transitionWorkflow("wf-1", "running");
  store.transitionNode("wf-1", "step", "ready");
  store.transitionNode("wf-1", "step", "running");
  return {
    store,
    recovery: new WorkflowRecoveryEngine(
      store,
      { lookup: async () => receipt },
      { isIdempotent: () => idempotent },
    ),
  };
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("V3 workflow recovery", () => {
  it("reconciles a durable running node from a completed device receipt", async () => {
    const { store, recovery } = await runtime(2, { terminalState: "completed" });
    await expect(
      recovery.reconcileRunning("wf-1", [{ nodeId: "step", attempt: 1 }]),
    ).resolves.toEqual([{ nodeId: "step", action: "completed-from-receipt" }]);
    expect(store.snapshot("wf-1").nodes[0]?.status).toBe("completed");
    store.close();
  });

  it("marks a running node interrupted when outcome is unknown", async () => {
    const { store, recovery } = await runtime();
    await recovery.reconcileRunning("wf-1", [{ nodeId: "step", attempt: 1 }]);
    expect(store.snapshot("wf-1").nodes[0]?.status).toBe("interrupted");
    store.close();
  });

  it("permits an explicit idempotent resume within retry budget", async () => {
    const { store, recovery } = await runtime(3, undefined, true);
    await recovery.reconcileRunning("wf-1", [{ nodeId: "step", attempt: 1 }]);
    await expect(recovery.resumeNode("wf-1", "step", 1)).resolves.toBe("ready");
    expect(store.snapshot("wf-1").nodes[0]?.status).toBe("ready");
    store.close();
  });

  it("forbids retry of a non-idempotent unknown outcome", async () => {
    const { store, recovery } = await runtime(3, undefined, false);
    await recovery.reconcileRunning("wf-1", [{ nodeId: "step", attempt: 1 }]);
    await expect(recovery.resumeNode("wf-1", "step", 1)).rejects.toThrow(
      /non-idempotent unknown outcome/u,
    );
    expect(store.snapshot("wf-1").nodes[0]?.status).toBe("interrupted");
    store.close();
  });

  it("permits retry after a known failed outcome even when non-idempotent", async () => {
    const { store, recovery } = await runtime(3, { terminalState: "failed" }, false);
    await recovery.reconcileRunning("wf-1", [{ nodeId: "step", attempt: 1 }]);
    await expect(recovery.resumeNode("wf-1", "step", 1)).resolves.toBe("ready");
    store.close();
  });

  it("fails closed when retry budget is exhausted", async () => {
    const { store, recovery } = await runtime(1, { terminalState: "failed" });
    await recovery.reconcileRunning("wf-1", [{ nodeId: "step", attempt: 1 }]);
    await expect(recovery.resumeNode("wf-1", "step", 1)).rejects.toThrow(WorkflowRecoveryError);
    store.close();
  });
});
