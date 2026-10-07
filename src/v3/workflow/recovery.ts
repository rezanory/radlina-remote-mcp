import type { WorkflowDefinition } from "./contracts.js";
import type { WorkflowSqliteStore } from "./persistence.js";

export type RecoveryReceipt =
  | { terminalState: "completed" }
  | { terminalState: "failed" | "cancelled"; errorCode?: string }
  | undefined;

export interface RecoveryReceiptPort {
  lookup(workflowExecutionId: string, nodeId: string, attempt: number): Promise<RecoveryReceipt>;
}

export interface CapabilityIdempotencyPort {
  isIdempotent(capability: string): boolean;
}

export type RecoveryObservation = {
  nodeId: string;
  attempt: number;
  outcomeKnownFailed?: boolean;
};

export type RecoveryAction =
  | { nodeId: string; action: "completed-from-receipt" }
  | { nodeId: string; action: "failed-from-receipt" }
  | { nodeId: string; action: "cancelled-from-receipt" }
  | { nodeId: string; action: "interrupted-unknown-outcome" }
  | { nodeId: string; action: "unchanged" };

export class WorkflowRecoveryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WorkflowRecoveryError";
  }
}

export class WorkflowRecoveryEngine {
  constructor(
    private readonly store: WorkflowSqliteStore,
    private readonly receipts: RecoveryReceiptPort,
    private readonly idempotency: CapabilityIdempotencyPort,
  ) {}

  async reconcileRunning(
    executionId: string,
    observations: RecoveryObservation[],
  ): Promise<RecoveryAction[]> {
    const snapshot = this.store.snapshot(executionId);
    const byId = new Map(snapshot.nodes.map((node) => [node.id, node] as const));
    const actions: RecoveryAction[] = [];

    for (const observation of observations) {
      const node = byId.get(observation.nodeId);
      if (!node) throw new WorkflowRecoveryError(`unknown node: ${observation.nodeId}`);
      if (node.status !== "running") {
        actions.push({ nodeId: node.id, action: "unchanged" });
        continue;
      }

      const receipt = await this.receipts.lookup(executionId, node.id, observation.attempt);
      if (receipt?.terminalState === "completed") {
        this.store.transitionNode(executionId, node.id, "completed");
        actions.push({ nodeId: node.id, action: "completed-from-receipt" });
      } else if (receipt?.terminalState === "failed") {
        this.store.transitionNode(executionId, node.id, "failed");
        actions.push({ nodeId: node.id, action: "failed-from-receipt" });
      } else if (receipt?.terminalState === "cancelled") {
        this.store.transitionNode(executionId, node.id, "cancelled");
        actions.push({ nodeId: node.id, action: "cancelled-from-receipt" });
      } else {
        this.store.transitionNode(executionId, node.id, "interrupted");
        actions.push({ nodeId: node.id, action: "interrupted-unknown-outcome" });
      }
    }

    return actions;
  }

  async resumeNode(
    executionId: string,
    nodeId: string,
    attempt: number,
    options: { outcomeKnownFailed?: boolean } = {},
  ): Promise<"ready"> {
    const definition = await this.store.definition(executionId);
    const nodeDefinition = this.requireNode(definition, nodeId);
    const snapshotNode = this.store.snapshot(executionId).nodes.find((node) => node.id === nodeId);
    if (!snapshotNode) throw new WorkflowRecoveryError(`unknown node: ${nodeId}`);
    if (snapshotNode.status !== "failed" && snapshotNode.status !== "interrupted") {
      throw new WorkflowRecoveryError(
        `node ${nodeId} is not recoverable from state ${snapshotNode.status}`,
      );
    }
    if (attempt >= nodeDefinition.maxAttempts) {
      throw new WorkflowRecoveryError(
        `node ${nodeId} exhausted retry budget ${nodeDefinition.maxAttempts}`,
      );
    }

    const safeKnownFailure =
      snapshotNode.status === "failed" || options.outcomeKnownFailed === true;
    const safeIdempotentRetry = this.idempotency.isIdempotent(nodeDefinition.capability);
    if (!safeKnownFailure && !safeIdempotentRetry) {
      throw new WorkflowRecoveryError(
        `automatic retry forbidden for non-idempotent unknown outcome: ${nodeId}`,
      );
    }

    this.store.transitionNode(executionId, nodeId, "ready");
    return "ready";
  }

  private requireNode(definition: WorkflowDefinition, nodeId: string) {
    const node = definition.nodes.find((candidate) => candidate.id === nodeId);
    if (!node) throw new WorkflowRecoveryError(`node definition not found: ${nodeId}`);
    return node;
  }
}
