import type { NodeState, WorkflowState } from "./contracts.js";

export type TransitionScope = "workflow" | "node";

const WORKFLOW_TRANSITIONS: Readonly<Record<WorkflowState, readonly WorkflowState[]>> = {
  queued: ["running", "cancelled", "interrupted", "failed"],
  running: ["completed", "failed", "cancelled", "interrupted"],
  completed: [],
  failed: ["queued", "cancelled"],
  cancelled: [],
  interrupted: ["queued", "failed", "cancelled"],
};

const NODE_TRANSITIONS: Readonly<Record<NodeState, readonly NodeState[]>> = {
  pending: ["ready", "blocked", "cancelled"],
  ready: ["running", "blocked", "cancelled"],
  running: ["completed", "failed", "cancelled", "interrupted"],
  completed: [],
  failed: ["ready", "cancelled"],
  cancelled: [],
  interrupted: ["ready", "failed", "cancelled"],
  blocked: ["ready", "cancelled"],
};

const WORKFLOW_TERMINAL = new Set<WorkflowState>(["completed", "cancelled"]);
const NODE_TERMINAL = new Set<NodeState>(["completed", "cancelled"]);

export class WorkflowTransitionError extends Error {
  readonly scope: TransitionScope;
  readonly from: WorkflowState | NodeState;
  readonly to: WorkflowState | NodeState;

  constructor(
    scope: TransitionScope,
    from: WorkflowState | NodeState,
    to: WorkflowState | NodeState,
  ) {
    super(`invalid ${scope} transition: ${from} -> ${to}`);
    this.name = "WorkflowTransitionError";
    this.scope = scope;
    this.from = from;
    this.to = to;
  }
}

export function canTransitionWorkflow(from: WorkflowState, to: WorkflowState): boolean {
  return WORKFLOW_TRANSITIONS[from].includes(to);
}

export function transitionWorkflow(from: WorkflowState, to: WorkflowState): WorkflowState {
  if (!canTransitionWorkflow(from, to)) {
    throw new WorkflowTransitionError("workflow", from, to);
  }
  return to;
}

export function isWorkflowTerminal(state: WorkflowState): boolean {
  return WORKFLOW_TERMINAL.has(state);
}

export function canTransitionNode(from: NodeState, to: NodeState): boolean {
  return NODE_TRANSITIONS[from].includes(to);
}

export function transitionNode(from: NodeState, to: NodeState): NodeState {
  if (!canTransitionNode(from, to)) {
    throw new WorkflowTransitionError("node", from, to);
  }
  return to;
}

export function isNodeTerminal(state: NodeState): boolean {
  return NODE_TERMINAL.has(state);
}

export function workflowTransitionTargets(state: WorkflowState): readonly WorkflowState[] {
  return WORKFLOW_TRANSITIONS[state];
}

export function nodeTransitionTargets(state: NodeState): readonly NodeState[] {
  return NODE_TRANSITIONS[state];
}
