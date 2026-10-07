import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import type { WorkflowDefinition } from "../../../src/v3/workflow/contracts.js";
import {
  WorkflowSqliteStore,
  type WorkflowPayloadCodec,
} from "../../../src/v3/workflow/persistence.js";
import { WorkflowScheduler } from "../../../src/v3/workflow/scheduler.js";

class Codec implements WorkflowPayloadCodec {
  async encode(value: string): Promise<string> {
    return Buffer.from(value).toString("base64");
  }
  async decode(value: string): Promise<string> {
    return Buffer.from(value, "base64").toString("utf8");
  }
}

const roots: string[] = [];

async function runtime(definition: WorkflowDefinition) {
  const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-scheduler-"));
  roots.push(root);
  const store = new WorkflowSqliteStore(path.join(root, "workflow.sqlite3"), new Codec());
  await store.create("wf-1", "owner", "idem-1", definition);
  return { store, scheduler: new WorkflowScheduler(store) };
}

function node(id: string, dependsOn: string[] = []) {
  return {
    id,
    capability: "device.health",
    input: {},
    dependsOn,
    target: { deviceId: "windows-main" as const },
    maxAttempts: 1,
    timeoutMs: 5_000,
    executionPolicy: {
      failureMode: "fail-workflow" as const,
      allowDynamicReroute: false,
      unknownOutcome: "manual-resume" as const,
    },
    expectedOutput: {
      contractId: "device.health/v1",
      artifactMode: "inline" as const,
      maxBytes: 65_536,
    },
  };
}

function definition(nodes: ReturnType<typeof node>[]): WorkflowDefinition {
  return {
    workflowId: "scheduler.acceptance",
    definitionVersion: "1.0.0",
    title: "Scheduler acceptance",
    nodes,
  };
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("V3 WorkflowScheduler", () => {
  it("admits independent root nodes in maximum-safe parallelism", async () => {
    const { store, scheduler } = await runtime(
      definition([node("a"), node("b"), node("join", ["a", "b"])]),
    );
    await expect(scheduler.reconcile("wf-1")).resolves.toEqual({
      ready: ["a", "b"],
      blocked: [],
      waiting: ["join"],
    });
    expect(store.snapshot("wf-1").nodes.map((entry) => [entry.id, entry.status])).toEqual([
      ["a", "ready"],
      ["b", "ready"],
      ["join", "pending"],
    ]);
    store.close();
  });

  it("releases a dependency join only after all prerequisites complete", async () => {
    const { store, scheduler } = await runtime(
      definition([node("a"), node("b"), node("join", ["a", "b"])]),
    );
    await scheduler.reconcile("wf-1");
    for (const id of ["a", "b"]) {
      store.transitionNode("wf-1", id, "running");
      store.transitionNode("wf-1", id, "completed");
    }
    expect(await scheduler.reconcile("wf-1")).toEqual({
      ready: ["join"],
      blocked: [],
      waiting: [],
    });
    store.close();
  });

  it("blocks a dependent node when a prerequisite is cancelled", async () => {
    const { store, scheduler } = await runtime(definition([node("a"), node("join", ["a"])]));
    await scheduler.reconcile("wf-1");
    store.transitionNode("wf-1", "a", "cancelled");
    expect(await scheduler.reconcile("wf-1")).toEqual({
      ready: [],
      blocked: ["join"],
      waiting: [],
    });
    store.close();
  });

  it("unblocks a node after a retryable prerequisite eventually completes", async () => {
    const { store, scheduler } = await runtime(definition([node("a"), node("join", ["a"])]));
    await scheduler.reconcile("wf-1");
    store.transitionNode("wf-1", "a", "running");
    store.transitionNode("wf-1", "a", "failed");
    expect((await scheduler.reconcile("wf-1")).blocked).toEqual(["join"]);
    store.transitionNode("wf-1", "a", "ready");
    store.transitionNode("wf-1", "a", "running");
    store.transitionNode("wf-1", "a", "completed");
    expect((await scheduler.reconcile("wf-1")).ready).toEqual(["join"]);
    store.close();
  });

  it("respects a configured ready-batch limit without inventing hidden dependencies", async () => {
    const { store, scheduler } = await runtime(definition([node("a"), node("b"), node("c")]));
    expect(await scheduler.reconcile("wf-1", 2)).toEqual({
      ready: ["a", "b"],
      blocked: [],
      waiting: ["c"],
    });
    expect(store.snapshot("wf-1").nodes.find((entry) => entry.id === "c")?.status).toBe("pending");
    store.close();
  });
});
