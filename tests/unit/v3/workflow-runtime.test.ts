import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import type { WorkflowDefinition } from "../../../src/v3/workflow/contracts.js";
import { InMemoryWorkflowTelemetry } from "../../../src/v3/workflow/observability.js";
import {
  WorkflowSqliteStore,
  type WorkflowPayloadCodec,
} from "../../../src/v3/workflow/persistence.js";
import { WorkflowRecoveryEngine } from "../../../src/v3/workflow/recovery.js";
import {
  CanonicalWorkflowRuntime,
  WorkflowRuntimeError,
  type ExecutionDispatchPort,
  type WorkflowDispatchInput,
} from "../../../src/v3/workflow/runtime.js";
import { WorkflowScheduler } from "../../../src/v3/workflow/scheduler.js";

class Codec implements WorkflowPayloadCodec {
  async encode(value: string): Promise<string> {
    return Buffer.from(value, "utf8").toString("base64");
  }

  async decode(value: string): Promise<string> {
    return Buffer.from(value, "base64").toString("utf8");
  }
}

const roots: string[] = [];
const hash = "a".repeat(64);

function node(id: string, dependsOn: string[] = []) {
  return {
    id,
    capability: "device.health",
    input: { id },
    dependsOn,
    target: { deviceId: "windows-main" as const },
    maxAttempts: 2,
    timeoutMs: 5_000,
    executionPolicy: {
      failureMode: "fail-workflow" as const,
      allowDynamicReroute: false,
      unknownOutcome: "manual-resume" as const,
    },
    expectedOutput: {
      contractId: "device.health/v1",
      artifactMode: "inline" as const,
      maxBytes: 4096,
    },
  };
}

function definition(nodes = [node("health")]): WorkflowDefinition {
  return {
    workflowId: "runtime.acceptance",
    definitionVersion: "1.0.0",
    title: "Runtime acceptance",
    nodes,
  };
}

function receipt(
  input: WorkflowDispatchInput,
  terminalState: "completed" | "failed" | "cancelled" | "interrupted" = "completed",
) {
  return {
    workflowExecutionId: input.workflowExecutionId,
    nodeId: input.node.id,
    attempt: input.attempt,
    resolvedDeviceId: "windows-main",
    capability: input.node.capability,
    inputSha256: hash,
    startedAt: "2026-10-07T18:30:00+03:00",
    terminalState,
    outputSha256: terminalState === "completed" ? hash : null,
    localAuditReceiptHash: hash,
    globalCorrelationId: "corr",
    traceId: "trace",
  };
}

async function harness(dispatch: ExecutionDispatchPort, idempotent = true) {
  const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-runtime-"));
  roots.push(root);
  const store = new WorkflowSqliteStore(path.join(root, "workflow.sqlite3"), new Codec());
  const scheduler = new WorkflowScheduler(store);
  const recovery = new WorkflowRecoveryEngine(
    store,
    { lookup: async () => undefined },
    { isIdempotent: () => idempotent },
  );
  const telemetry = new InMemoryWorkflowTelemetry();
  let now = 1000;
  const runtime = new CanonicalWorkflowRuntime(
    store,
    scheduler,
    recovery,
    telemetry,
    dispatch,
    () => (now += 10),
    () => "generated-execution-id",
  );
  return { root, store, scheduler, recovery, telemetry, runtime };
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("V3 canonical workflow runtime", () => {
  it("executes independent roots in parallel, releases the join, and persists attempts", async () => {
    const seen: string[] = [];
    const dispatch: ExecutionDispatchPort = {
      execute: async (input) => {
        seen.push(`${input.node.id}:${input.attempt}`);
        return { receipt: receipt(input), output: { ok: true } };
      },
    };
    const value = await harness(dispatch);
    await value.runtime.submit({
      executionId: "wf-1",
      subject: "owner",
      idempotencyKey: "idem-1",
      definition: definition([node("a"), node("b"), node("join", ["a", "b"])]),
    });

    const result = await value.runtime.runUntilIdle("wf-1");
    expect(result.snapshot.status).toBe("completed");
    expect(result.dispatchedNodes).toBe(3);
    expect(result.snapshot.nodes.map((entry) => [entry.id, entry.status, entry.attempts])).toEqual([
      ["a", "completed", 1],
      ["b", "completed", 1],
      ["join", "completed", 1],
    ]);
    expect(new Set(seen)).toEqual(new Set(["a:1", "b:1", "join:1"]));
    expect(value.telemetry.snapshot().counters).toMatchObject({
      "node.dispatched": 3,
      "node.completed": 3,
      "workflow.completed": 1,
    });
    value.store.close();
  });

  it("replays an identical submit without creating a second execution", async () => {
    const value = await harness({
      execute: async (input) => ({ receipt: receipt(input) }),
    });
    const request = {
      subject: "owner",
      idempotencyKey: "idem-1",
      definition: definition(),
    };
    await expect(value.runtime.submit(request)).resolves.toEqual({
      executionId: "generated-execution-id",
      replayed: false,
    });
    await expect(value.runtime.submit(request)).resolves.toEqual({
      executionId: "generated-execution-id",
      replayed: true,
    });
    value.store.close();
  });

  it("fails closed on a mismatched dispatch receipt and durably interrupts the workflow", async () => {
    const value = await harness({
      execute: async (input) => ({
        receipt: { ...receipt(input), nodeId: "other" },
      }),
    });
    await value.runtime.submit({
      executionId: "wf-1",
      subject: "owner",
      idempotencyKey: "idem-1",
      definition: definition(),
    });

    await expect(value.runtime.runUntilIdle("wf-1")).rejects.toThrow(WorkflowRuntimeError);
    expect(value.runtime.status("wf-1")).toMatchObject({
      status: "interrupted",
      nodes: [{ id: "health", status: "interrupted", attempts: 1 }],
    });
    value.store.close();
  });

  it("marks the workflow failed when a fail-workflow node returns a failed receipt", async () => {
    const value = await harness({
      execute: async (input) => ({ receipt: receipt(input, "failed") }),
    });
    await value.runtime.submit({
      executionId: "wf-1",
      subject: "owner",
      idempotencyKey: "idem-1",
      definition: definition(),
    });
    const result = await value.runtime.runUntilIdle("wf-1");
    expect(result.snapshot).toMatchObject({
      status: "failed",
      nodes: [{ id: "health", status: "failed", attempts: 1 }],
    });
    value.store.close();
  });

  it("recovers an interrupted idempotent node and persists the second attempt", async () => {
    let run = 0;
    const value = await harness({
      execute: async (input) => {
        run += 1;
        return { receipt: receipt(input, run === 1 ? "interrupted" : "completed") };
      },
    });
    await value.runtime.submit({
      executionId: "wf-1",
      subject: "owner",
      idempotencyKey: "idem-1",
      definition: definition(),
    });

    expect((await value.runtime.runUntilIdle("wf-1")).snapshot.status).toBe("interrupted");
    await value.runtime.resumeNode("wf-1", "health");
    const result = await value.runtime.runUntilIdle("wf-1");
    expect(result.snapshot).toMatchObject({
      status: "completed",
      nodes: [{ id: "health", status: "completed", attempts: 2 }],
    });
    value.store.close();
  });

  it("cancels a queued workflow without dispatching executable scope", async () => {
    let dispatched = 0;
    const value = await harness({
      execute: async (input) => {
        dispatched += 1;
        return { receipt: receipt(input) };
      },
    });
    await value.runtime.submit({
      executionId: "wf-1",
      subject: "owner",
      idempotencyKey: "idem-1",
      definition: definition(),
    });
    const result = await value.runtime.cancel("wf-1");
    expect(result).toMatchObject({
      status: "cancelled",
      nodes: [{ id: "health", status: "cancelled", attempts: 0 }],
    });
    expect(dispatched).toBe(0);
    value.store.close();
  });
});
