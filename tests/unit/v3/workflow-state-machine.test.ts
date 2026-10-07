import { describe, expect, it } from "vitest";

import {
  canTransitionNode,
  canTransitionWorkflow,
  isNodeTerminal,
  isWorkflowTerminal,
  nodeTransitionTargets,
  transitionNode,
  transitionWorkflow,
  WorkflowTransitionError,
  workflowTransitionTargets,
} from "../../../src/v3/workflow/state-machine.js";

describe("V3 workflow state machine", () => {
  it("permits the normal workflow lifecycle", () => {
    expect(transitionWorkflow("queued", "running")).toBe("running");
    expect(transitionWorkflow("running", "completed")).toBe("completed");
    expect(isWorkflowTerminal("completed")).toBe(true);
  });

  it("forbids transitions out of completed or cancelled workflows", () => {
    expect(workflowTransitionTargets("completed")).toEqual([]);
    expect(workflowTransitionTargets("cancelled")).toEqual([]);
    expect(() => transitionWorkflow("completed", "running")).toThrow(WorkflowTransitionError);
    expect(() => transitionWorkflow("cancelled", "queued")).toThrow(/invalid workflow transition/u);
  });

  it("allows explicit recovery to re-queue failed or interrupted workflows", () => {
    expect(canTransitionWorkflow("failed", "queued")).toBe(true);
    expect(canTransitionWorkflow("interrupted", "queued")).toBe(true);
    expect(transitionWorkflow("failed", "queued")).toBe("queued");
  });

  it("does not treat failed or interrupted workflows as terminal", () => {
    expect(isWorkflowTerminal("failed")).toBe(false);
    expect(isWorkflowTerminal("interrupted")).toBe(false);
  });

  it("permits dependency readiness and execution for nodes", () => {
    expect(transitionNode("pending", "ready")).toBe("ready");
    expect(transitionNode("ready", "running")).toBe("running");
    expect(transitionNode("running", "completed")).toBe("completed");
  });

  it("permits retry/recovery only through an explicit ready transition", () => {
    expect(canTransitionNode("failed", "ready")).toBe(true);
    expect(canTransitionNode("interrupted", "ready")).toBe(true);
    expect(canTransitionNode("failed", "running")).toBe(false);
    expect(() => transitionNode("failed", "running")).toThrow(/invalid node transition/u);
  });

  it("models blocked nodes without making blocked terminal", () => {
    expect(nodeTransitionTargets("pending")).toContain("blocked");
    expect(canTransitionNode("blocked", "ready")).toBe(true);
    expect(isNodeTerminal("blocked")).toBe(false);
  });

  it("keeps completed and cancelled nodes terminal", () => {
    expect(isNodeTerminal("completed")).toBe(true);
    expect(isNodeTerminal("cancelled")).toBe(true);
    expect(nodeTransitionTargets("completed")).toEqual([]);
    expect(() => transitionNode("completed", "ready")).toThrow(WorkflowTransitionError);
  });

  it("forbids silent same-state transitions", () => {
    expect(canTransitionWorkflow("running", "running")).toBe(false);
    expect(canTransitionNode("ready", "ready")).toBe(false);
  });
});
