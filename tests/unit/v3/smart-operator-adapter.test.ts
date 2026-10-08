import { readFile } from "node:fs/promises";

import { describe, expect, it, vi } from "vitest";

import type { OperatorPlan } from "../../../src/operator/types.js";
import {
  SmartOperatorAdapter,
  type OperatorWorkflowPort,
} from "../../../src/v3/operator/adapter.js";
import type { WorkflowSnapshot } from "../../../src/v3/workflow/persistence.js";

function plan(): OperatorPlan {
  return {
    title: "Legacy operator",
    steps: [
      { id: "one", capability: "device.health", input: { a: 1 }, maxAttempts: 2 },
      { id: "two", capability: "filesystem.info", input: { b: 2 }, maxAttempts: 1 },
      { id: "three", capability: "process.exec", input: { c: 3 }, maxAttempts: 1 },
    ],
  };
}

function snapshot(
  status: WorkflowSnapshot["status"] = "queued",
  subject = "owner",
  nodeStatuses: Array<WorkflowSnapshot["nodes"][number]["status"]> = [
    "pending",
    "pending",
    "pending",
  ],
): WorkflowSnapshot {
  return {
    executionId: "wf-operator-1",
    subject,
    status,
    definitionSha256: "a".repeat(64),
    nodes: ["one", "two", "three"].map((id, index) => ({
      id,
      status: nodeStatuses[index] ?? "pending",
      attempts: index === 0 ? 1 : 0,
      maxAttempts: index === 0 ? 2 : 1,
    })),
  };
}

function runtime(initial = snapshot()) {
  let current = initial;
  const submit = vi.fn<OperatorWorkflowPort["submit"]>(async ({ executionId }) => {
    current = { ...current, executionId: executionId ?? current.executionId };
    return { executionId: current.executionId, replayed: false };
  });
  const status = vi.fn<OperatorWorkflowPort["status"]>(() => current);
  const resumeNode = vi.fn<OperatorWorkflowPort["resumeNode"]>(async (_id, nodeId) => {
    current = {
      ...current,
      status: "queued",
      nodes: current.nodes.map((node) =>
        node.id === nodeId ? { ...node, status: "ready" } : node,
      ),
    };
    return current;
  });
  const cancel = vi.fn<OperatorWorkflowPort["cancel"]>(async () => {
    current = { ...current, status: "cancelled" };
    return current;
  });
  return {
    port: { submit, status, resumeNode, cancel } satisfies OperatorWorkflowPort,
    submit,
    status,
    resumeNode,
    cancel,
    current: () => current,
  };
}

describe("V3 SmartOperatorAdapter", () => {
  it("translates the V2 ordered plan to one authoritative DAG chain", () => {
    const value = runtime();
    const adapter = new SmartOperatorAdapter(
      value.port,
      { launch: vi.fn() },
      { isIdempotent: () => true },
      { defaultTarget: { deviceId: "windows-main" } },
      () => "wf-operator-1",
    );

    const definition = adapter.translate(plan());
    expect(definition.workflowId).toBe("operator.legacy");
    expect(definition.nodes.map((node) => [node.id, node.dependsOn])).toEqual([
      ["one", []],
      ["two", ["one"]],
      ["three", ["two"]],
    ]);
    expect(definition.nodes.every((node) => node.target.deviceId === "windows-main")).toBe(true);
    expect(
      definition.nodes.every((node) => node.executionPolicy.allowDynamicReroute === false),
    ).toBe(true);
  });

  it("preserves the non-idempotent maxAttempts=1 safety rule", () => {
    const adapter = new SmartOperatorAdapter(
      runtime().port,
      { launch: vi.fn() },
      {
        isIdempotent: (capability) => capability !== "device.health",
      },
      { defaultTarget: { deviceId: "windows-main" } },
    );
    expect(() => adapter.translate(plan())).toThrow(/non-idempotent capability/u);
  });

  it("submits only through the canonical workflow port and returns its execution id as jobId", async () => {
    const value = runtime();
    const launch = vi.fn();
    const adapter = new SmartOperatorAdapter(
      value.port,
      { launch },
      { isIdempotent: () => true },
      { defaultTarget: { deviceId: "windows-main" } },
      () => "wf-operator-1",
    );

    await expect(adapter.submit(undefined, "owner", "radlina", plan())).resolves.toEqual({
      jobId: "wf-operator-1",
      status: "queued",
      steps: 3,
    });
    expect(value.submit).toHaveBeenCalledWith(
      expect.objectContaining({
        executionId: "wf-operator-1",
        subject: "owner",
        idempotencyKey: "operator:wf-operator-1",
      }),
    );
    expect(launch).toHaveBeenCalledWith("wf-operator-1");
  });

  it("projects durable workflow state and enforces caller ownership", async () => {
    const value = runtime(snapshot("running", "owner", ["completed", "running", "pending"]));
    const adapter = new SmartOperatorAdapter(
      value.port,
      { launch: vi.fn() },
      { isIdempotent: () => true },
      { defaultTarget: { deviceId: "windows-main" } },
    );

    await expect(adapter.status("owner", "wf-operator-1")).resolves.toEqual({
      jobId: "wf-operator-1",
      status: "running",
      steps: [
        { id: "one", status: "completed", attempts: 1, maxAttempts: 2 },
        { id: "two", status: "running", attempts: 0, maxAttempts: 1 },
        { id: "three", status: "pending", attempts: 0, maxAttempts: 1 },
      ],
    });
    await expect(adapter.status("other", "wf-operator-1")).rejects.toThrow(/not found/u);
  });

  it("delegates resume and cancel to canonical runtime without owning retry or workflow state", async () => {
    const value = runtime(
      snapshot("interrupted", "owner", ["completed", "interrupted", "pending"]),
    );
    const launch = vi.fn();
    const adapter = new SmartOperatorAdapter(
      value.port,
      { launch },
      { isIdempotent: () => true },
      { defaultTarget: { deviceId: "windows-main" } },
    );

    await expect(adapter.resume(undefined, "owner", "wf-operator-1")).resolves.toEqual({
      jobId: "wf-operator-1",
      status: "queued",
    });
    expect(value.resumeNode).toHaveBeenCalledWith("wf-operator-1", "two");
    expect(launch).toHaveBeenCalledWith("wf-operator-1");

    await expect(adapter.cancel("owner", "wf-operator-1")).resolves.toEqual({
      jobId: "wf-operator-1",
      status: "cancelled",
      requested: true,
    });
    expect(value.cancel).toHaveBeenCalledWith("wf-operator-1");
  });

  it("remains a thin adapter with no workflow store, scheduler, or retry engine imports", async () => {
    const source = await readFile(
      new URL("../../../src/v3/operator/adapter.ts", import.meta.url),
      "utf8",
    );
    expect(source).not.toContain("WorkflowSqliteStore");
    expect(source).not.toContain("WorkflowScheduler");
    expect(source).not.toContain("WorkflowRecoveryEngine");
    expect(source).not.toContain("node:sqlite");
  });
});
