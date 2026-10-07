import type { NodeState } from "./contracts.js";
import type { WorkflowSqliteStore } from "./persistence.js";

export type SchedulerDecision = {
  ready: string[];
  blocked: string[];
  waiting: string[];
};

const BLOCKING_DEPENDENCY_STATES = new Set<NodeState>([
  "failed",
  "cancelled",
  "interrupted",
  "blocked",
]);

export class WorkflowScheduler {
  constructor(private readonly store: WorkflowSqliteStore) {}

  async reconcile(
    executionId: string,
    maxReady = Number.POSITIVE_INFINITY,
  ): Promise<SchedulerDecision> {
    if (!(maxReady > 0)) throw new Error("maxReady must be greater than zero");

    const definition = await this.store.definition(executionId);
    const snapshot = this.store.snapshot(executionId);
    const stateById = new Map(snapshot.nodes.map((node) => [node.id, node.status] as const));

    const ready: string[] = [];
    const blocked: string[] = [];
    const waiting: string[] = [];

    for (const node of definition.nodes) {
      const current = stateById.get(node.id);
      if (current === undefined) throw new Error(`persisted node is missing: ${node.id}`);
      if (!new Set<NodeState>(["pending", "blocked", "ready"]).has(current)) continue;

      const dependencyStates = node.dependsOn.map((dependency) => {
        const state = stateById.get(dependency);
        if (state === undefined) throw new Error(`persisted dependency is missing: ${dependency}`);
        return state;
      });

      const allCompleted = dependencyStates.every((state) => state === "completed");
      if (allCompleted) {
        if (ready.length >= maxReady) {
          waiting.push(node.id);
          continue;
        }
        if (current === "pending" || current === "blocked") {
          this.store.transitionNode(executionId, node.id, "ready");
          stateById.set(node.id, "ready");
        }
        ready.push(node.id);
        continue;
      }

      const hasBlockingDependency = dependencyStates.some((state) =>
        BLOCKING_DEPENDENCY_STATES.has(state),
      );
      if (hasBlockingDependency) {
        if (current === "pending" || current === "ready") {
          this.store.transitionNode(executionId, node.id, "blocked");
          stateById.set(node.id, "blocked");
        }
        blocked.push(node.id);
      } else {
        waiting.push(node.id);
      }
    }

    return { ready, blocked, waiting };
  }
}
