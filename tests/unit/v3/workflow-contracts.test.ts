import { describe, expect, it } from "vitest";

import {
  dispatchReceiptSchema,
  legacySequentialDependencies,
  parseWorkflowDefinition,
} from "../../../src/v3/workflow/contracts.js";

function node(id: string, dependsOn: string[] = []) {
  return {
    id,
    capability: "device.health",
    input: {},
    dependsOn,
    target: { deviceId: "windows-main" },
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

describe("V3 workflow contracts", () => {
  it("accepts a valid DAG and preserves explicit dependency authority", () => {
    const definition = parseWorkflowDefinition({
      workflowId: "acceptance.cross-device",
      definitionVersion: "1.0.0",
      title: "Cross-device acceptance",
      nodes: [node("health-windows"), node("join", ["health-windows"])],
    });

    expect(definition.nodes[1]?.dependsOn).toEqual(["health-windows"]);
  });

  it("rejects duplicate node ids", () => {
    expect(() =>
      parseWorkflowDefinition({
        workflowId: "duplicate",
        definitionVersion: "1.0.0",
        title: "duplicate",
        nodes: [node("same"), node("same")],
      }),
    ).toThrow(/duplicate node id/u);
  });

  it("rejects missing dependencies and dependency cycles", () => {
    expect(() =>
      parseWorkflowDefinition({
        workflowId: "missing",
        definitionVersion: "1.0.0",
        title: "missing",
        nodes: [node("one", ["unknown"])],
      }),
    ).toThrow(/missing dependency/u);

    expect(() =>
      parseWorkflowDefinition({
        workflowId: "cycle",
        definitionVersion: "1.0.0",
        title: "cycle",
        nodes: [node("one", ["two"]), node("two", ["one"])],
      }),
    ).toThrow(/dependency cycle/u);
  });

  it("requires exactly one primary device selector", () => {
    const invalid = node("one");
    invalid.target = {} as typeof invalid.target;

    expect(() =>
      parseWorkflowDefinition({
        workflowId: "selector",
        definitionVersion: "1.0.0",
        title: "selector",
        nodes: [invalid],
      }),
    ).toThrow(/exactly one primary selector/u);

    const ambiguous = node("one");
    ambiguous.target = {
      deviceId: "windows-main",
      platform: "windows",
    } as typeof ambiguous.target;

    expect(() =>
      parseWorkflowDefinition({
        workflowId: "selector-two",
        definitionVersion: "1.0.0",
        title: "selector-two",
        nodes: [ambiguous],
      }),
    ).toThrow(/exactly one primary selector/u);
  });

  it("forbids silent reroute for exact-device targets", () => {
    const invalid = node("one");
    invalid.executionPolicy.allowDynamicReroute = true;

    expect(() =>
      parseWorkflowDefinition({
        workflowId: "reroute",
        definitionVersion: "1.0.0",
        title: "reroute",
        nodes: [invalid],
      }),
    ).toThrow(/exact-device execution/u);
  });

  it("freezes the V2 ordered-plan compatibility dependency projection", () => {
    expect(
      legacySequentialDependencies({
        title: "legacy",
        steps: [
          { id: "one", capability: "device.health", input: {}, maxAttempts: 1 },
          { id: "two", capability: "filesystem.info", input: {}, maxAttempts: 2 },
          { id: "three", capability: "process.exec", input: {}, maxAttempts: 1 },
        ],
      }),
    ).toEqual([
      { id: "one", dependsOn: [] },
      { id: "two", dependsOn: ["one"] },
      { id: "three", dependsOn: ["two"] },
    ]);
  });

  it("requires resolved-device and integrity fields on dispatch receipts", () => {
    const hash = "a".repeat(64);
    expect(
      dispatchReceiptSchema.parse({
        workflowExecutionId: "wf-1",
        nodeId: "health",
        attempt: 1,
        resolvedDeviceId: "windows-main",
        capability: "device.health",
        inputSha256: hash,
        startedAt: "2026-10-07T00:00:00Z",
        terminalState: "completed",
        outputSha256: hash,
        localAuditReceiptHash: hash,
        globalCorrelationId: "corr-1",
        traceId: "trace-1",
      }).resolvedDeviceId,
    ).toBe("windows-main");

    expect(() =>
      dispatchReceiptSchema.parse({
        workflowExecutionId: "wf-1",
        nodeId: "health",
        attempt: 1,
        capability: "device.health",
        inputSha256: hash,
        startedAt: "2026-10-07T00:00:00Z",
        terminalState: "completed",
        outputSha256: hash,
        localAuditReceiptHash: hash,
        globalCorrelationId: "corr-1",
        traceId: "trace-1",
      }),
    ).toThrow();
  });
});
