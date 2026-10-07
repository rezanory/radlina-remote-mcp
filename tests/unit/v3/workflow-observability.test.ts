import { describe, expect, it } from "vitest";

import {
  InMemoryWorkflowTelemetry,
  WorkflowTraceTimer,
} from "../../../src/v3/workflow/observability.js";

describe("V3 workflow observability", () => {
  it("records deterministic counters and duration summaries", () => {
    const telemetry = new InMemoryWorkflowTelemetry();
    telemetry.emit({ type: "node.ready", workflowExecutionId: "wf-1", nodeId: "a", at: 1 });
    telemetry.emit({
      type: "node.completed",
      workflowExecutionId: "wf-1",
      nodeId: "a",
      at: 11,
      durationMs: 10,
    });
    telemetry.emit({
      type: "node.completed",
      workflowExecutionId: "wf-1",
      nodeId: "b",
      at: 31,
      durationMs: 20,
    });

    expect(telemetry.snapshot()).toEqual({
      counters: {
        "node.completed": 2,
        "node.ready": 1,
      },
      observations: {
        "node.completed.duration_ms": {
          count: 2,
          min: 10,
          max: 20,
          average: 15,
        },
      },
    });
  });

  it("correlates dispatch metrics with the exact resolved device", () => {
    const telemetry = new InMemoryWorkflowTelemetry();
    telemetry.emit({
      type: "node.dispatched",
      workflowExecutionId: "wf-1",
      nodeId: "health",
      deviceId: "windows-main",
      at: 1,
    });
    expect(telemetry.snapshot().counters).toMatchObject({
      "node.dispatched": 1,
      "node.dispatched.device.windows-main": 1,
    });
  });

  it("retains bounded recent events in emission order", () => {
    const telemetry = new InMemoryWorkflowTelemetry();
    telemetry.emit({ type: "workflow.submitted", workflowExecutionId: "wf-1", at: 1 });
    telemetry.emit({ type: "workflow.recovery", workflowExecutionId: "wf-1", at: 2 });
    telemetry.emit({ type: "workflow.submitted", workflowExecutionId: "wf-2", at: 3 });
    expect(telemetry.recent(2).map((event) => event.at)).toEqual([2, 3]);
  });

  it("measures workflow and node execution without owning workflow state", () => {
    let current = 100;
    const telemetry = new InMemoryWorkflowTelemetry();
    const timer = new WorkflowTraceTimer(() => current, telemetry);

    const workflowDuration = timer.startWorkflow("wf-1");
    current = 125;
    expect(workflowDuration()).toBe(25);

    const node = timer.startNode("wf-1", "health", "windows-main");
    current = 165;
    node.complete();

    expect(telemetry.recent(3)).toEqual([
      { type: "workflow.submitted", workflowExecutionId: "wf-1", at: 100 },
      {
        type: "node.dispatched",
        workflowExecutionId: "wf-1",
        nodeId: "health",
        deviceId: "windows-main",
        at: 125,
      },
      {
        type: "node.completed",
        workflowExecutionId: "wf-1",
        nodeId: "health",
        at: 165,
        durationMs: 40,
      },
    ]);
  });

  it("rejects invalid observations", () => {
    const telemetry = new InMemoryWorkflowTelemetry();
    expect(() =>
      telemetry.emit({
        type: "node.failed",
        workflowExecutionId: "wf-1",
        nodeId: "a",
        at: 1,
        durationMs: Number.NaN,
      }),
    ).toThrow(/must be finite/u);
  });
});
