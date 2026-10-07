import { randomUUID } from "node:crypto";

import {
  dispatchReceiptSchema,
  parseWorkflowDefinition,
  type DispatchReceipt,
  type WorkflowDefinition,
  type WorkflowNode,
} from "./contracts.js";
import type { WorkflowTelemetrySink } from "./observability.js";
import type { WorkflowSqliteStore, WorkflowSnapshot } from "./persistence.js";
import type { WorkflowRecoveryEngine } from "./recovery.js";
import type { WorkflowScheduler } from "./scheduler.js";

export type WorkflowSubmitRequest = {
  executionId?: string;
  subject: string;
  idempotencyKey: string;
  definition: WorkflowDefinition;
};

export type WorkflowDispatchInput = {
  workflowExecutionId: string;
  subject: string;
  node: WorkflowNode;
  attempt: number;
};

export type WorkflowDispatchResult = {
  receipt: DispatchReceipt;
  output?: unknown;
};

export interface ExecutionDispatchPort {
  execute(input: WorkflowDispatchInput): Promise<WorkflowDispatchResult>;
  cancel?(input: { workflowExecutionId: string; nodeId: string; attempt: number }): Promise<void>;
}

export type WorkflowRunResult = {
  executionId: string;
  dispatchedNodes: number;
  cycles: number;
  snapshot: WorkflowSnapshot;
};

export class WorkflowRuntimeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WorkflowRuntimeError";
  }
}

export class CanonicalWorkflowRuntime {
  private readonly startedAt = new Map<string, number>();

  constructor(
    private readonly store: WorkflowSqliteStore,
    private readonly scheduler: WorkflowScheduler,
    private readonly recovery: WorkflowRecoveryEngine,
    private readonly telemetry: WorkflowTelemetrySink,
    private readonly dispatch: ExecutionDispatchPort,
    private readonly now: () => number = () => Date.now(),
    private readonly executionIdFactory: () => string = () => randomUUID(),
  ) {}

  async submit(request: WorkflowSubmitRequest): Promise<{
    executionId: string;
    replayed: boolean;
  }> {
    if (!request.subject.trim() || !request.idempotencyKey.trim()) {
      throw new WorkflowRuntimeError("subject and idempotencyKey are required");
    }
    const definition = parseWorkflowDefinition(request.definition);
    const executionId = request.executionId ?? this.executionIdFactory();
    const created = await this.store.create(
      executionId,
      request.subject,
      request.idempotencyKey,
      definition,
    );
    if (!created.replayed) {
      const startedAt = this.now();
      this.startedAt.set(created.executionId, startedAt);
      this.telemetry.emit({
        type: "workflow.submitted",
        workflowExecutionId: created.executionId,
        at: startedAt,
      });
    }
    return created;
  }

  status(executionId: string): WorkflowSnapshot {
    return this.store.snapshot(executionId);
  }

  async runUntilIdle(executionId: string, maxCycles = 1024): Promise<WorkflowRunResult> {
    if (!Number.isInteger(maxCycles) || maxCycles < 1) {
      throw new WorkflowRuntimeError("maxCycles must be a positive integer");
    }

    let snapshot = this.store.snapshot(executionId);
    if (snapshot.status === "queued") {
      this.store.transitionWorkflow(executionId, "running");
      snapshot = this.store.snapshot(executionId);
    }
    if (snapshot.status !== "running") {
      return { executionId, dispatchedNodes: 0, cycles: 0, snapshot };
    }

    const definition = await this.store.definition(executionId);
    const nodeById = new Map(definition.nodes.map((node) => [node.id, node] as const));
    let dispatchedNodes = 0;
    let cycles = 0;

    while (cycles < maxCycles) {
      cycles += 1;
      const decision = await this.scheduler.reconcile(executionId);
      if (decision.ready.length === 0) break;

      await Promise.all(
        decision.ready.map(async (nodeId) => {
          const node = nodeById.get(nodeId);
          if (!node) throw new WorkflowRuntimeError(`node definition not found: ${nodeId}`);
          const attempt = this.store.beginNodeAttempt(executionId, nodeId);
          dispatchedNodes += 1;
          const startedAt = this.now();
          this.telemetry.emit({
            type: "node.dispatched",
            workflowExecutionId: executionId,
            nodeId,
            deviceId: this.targetLabel(node),
            at: startedAt,
          });

          try {
            const result = await this.dispatch.execute({
              workflowExecutionId: executionId,
              subject: snapshot.subject,
              node,
              attempt,
            });
            const receipt = dispatchReceiptSchema.parse(result.receipt);
            this.assertReceiptMatches(executionId, node, attempt, receipt);
            this.applyReceipt(executionId, nodeId, receipt, startedAt);
          } catch (error) {
            const current = this.store
              .snapshot(executionId)
              .nodes.find((item) => item.id === nodeId);
            if (current?.status === "running") {
              this.store.transitionNode(executionId, nodeId, "interrupted");
              const endedAt = this.now();
              this.telemetry.emit({
                type: "node.failed",
                workflowExecutionId: executionId,
                nodeId,
                at: endedAt,
                durationMs: Math.max(0, endedAt - startedAt),
              });
            }
            const workflow = this.store.snapshot(executionId);
            if (workflow.status === "running") {
              this.store.transitionWorkflow(executionId, "interrupted");
            }
            throw error;
          }
        }),
      );
    }

    snapshot = this.finalizeWorkflow(executionId, definition);
    return { executionId, dispatchedNodes, cycles, snapshot };
  }

  async resumeNode(executionId: string, nodeId: string): Promise<WorkflowSnapshot> {
    const snapshot = this.store.snapshot(executionId);
    const node = snapshot.nodes.find((entry) => entry.id === nodeId);
    if (!node) throw new WorkflowRuntimeError(`node not found: ${nodeId}`);
    await this.recovery.resumeNode(executionId, nodeId, node.attempts);
    const workflow = this.store.snapshot(executionId);
    if (workflow.status === "failed" || workflow.status === "interrupted") {
      this.store.transitionWorkflow(executionId, "queued");
    }
    this.telemetry.emit({
      type: "workflow.recovery",
      workflowExecutionId: executionId,
      at: this.now(),
    });
    return this.store.snapshot(executionId);
  }

  async cancel(executionId: string): Promise<WorkflowSnapshot> {
    const snapshot = this.store.snapshot(executionId);
    if (snapshot.status === "completed" || snapshot.status === "cancelled") return snapshot;

    for (const node of snapshot.nodes) {
      if (node.status === "running") {
        await this.dispatch.cancel?.({
          workflowExecutionId: executionId,
          nodeId: node.id,
          attempt: node.attempts,
        });
        this.store.transitionNode(executionId, node.id, "cancelled");
      } else if (
        node.status === "pending" ||
        node.status === "ready" ||
        node.status === "blocked"
      ) {
        this.store.transitionNode(executionId, node.id, "cancelled");
      }
    }
    const current = this.store.snapshot(executionId);
    if (current.status !== "cancelled") {
      this.store.transitionWorkflow(executionId, "cancelled");
    }
    return this.store.snapshot(executionId);
  }

  triggerSubmitPort(): {
    submit: (input: {
      subject: string;
      idempotencyKey: string;
      workflow: WorkflowDefinition;
    }) => Promise<string>;
  } {
    return {
      submit: async ({ subject, idempotencyKey, workflow }) => {
        const result = await this.submit({ subject, idempotencyKey, definition: workflow });
        return result.executionId;
      },
    };
  }

  private applyReceipt(
    executionId: string,
    nodeId: string,
    receipt: DispatchReceipt,
    startedAt: number,
  ): void {
    const endedAt = this.now();
    if (receipt.terminalState === "completed") {
      this.store.transitionNode(executionId, nodeId, "completed");
      this.telemetry.emit({
        type: "node.completed",
        workflowExecutionId: executionId,
        nodeId,
        at: endedAt,
        durationMs: Math.max(0, endedAt - startedAt),
      });
      return;
    }

    if (receipt.terminalState === "cancelled") {
      this.store.transitionNode(executionId, nodeId, "cancelled");
      return;
    }
    if (receipt.terminalState === "interrupted") {
      this.store.transitionNode(executionId, nodeId, "interrupted");
      return;
    }

    this.store.transitionNode(executionId, nodeId, "failed");
    this.telemetry.emit({
      type: "node.failed",
      workflowExecutionId: executionId,
      nodeId,
      at: endedAt,
      durationMs: Math.max(0, endedAt - startedAt),
    });
  }

  private finalizeWorkflow(executionId: string, definition: WorkflowDefinition): WorkflowSnapshot {
    let snapshot = this.store.snapshot(executionId);
    if (snapshot.status !== "running") return snapshot;

    if (snapshot.nodes.every((node) => node.status === "completed")) {
      this.store.transitionWorkflow(executionId, "completed");
      const endedAt = this.now();
      const startedAt = this.startedAt.get(executionId) ?? endedAt;
      this.telemetry.emit({
        type: "workflow.completed",
        workflowExecutionId: executionId,
        at: endedAt,
        durationMs: Math.max(0, endedAt - startedAt),
      });
      this.startedAt.delete(executionId);
      return this.store.snapshot(executionId);
    }

    if (snapshot.nodes.some((node) => node.status === "interrupted")) {
      this.store.transitionWorkflow(executionId, "interrupted");
      return this.store.snapshot(executionId);
    }

    const failedIds = new Set(
      snapshot.nodes.filter((node) => node.status === "failed").map((node) => node.id),
    );
    if (failedIds.size > 0) {
      const mustFail = definition.nodes.some(
        (node) => failedIds.has(node.id) && node.executionPolicy.failureMode === "fail-workflow",
      );
      if (mustFail || snapshot.nodes.every((node) => node.status !== "running")) {
        this.store.transitionWorkflow(executionId, "failed");
        return this.store.snapshot(executionId);
      }
    }

    if (
      snapshot.nodes.length > 0 &&
      snapshot.nodes.every((node) => node.status === "completed" || node.status === "cancelled") &&
      snapshot.nodes.some((node) => node.status === "cancelled")
    ) {
      this.store.transitionWorkflow(executionId, "cancelled");
      snapshot = this.store.snapshot(executionId);
    }
    return snapshot;
  }

  private assertReceiptMatches(
    executionId: string,
    node: WorkflowNode,
    attempt: number,
    receipt: DispatchReceipt,
  ): void {
    if (
      receipt.workflowExecutionId !== executionId ||
      receipt.nodeId !== node.id ||
      receipt.attempt !== attempt ||
      receipt.capability !== node.capability
    ) {
      throw new WorkflowRuntimeError("dispatch receipt identity mismatch");
    }
  }

  private targetLabel(node: WorkflowNode): string {
    return (
      node.target.deviceId ??
      node.target.platform ??
      node.target.capability ??
      node.target.approvedTag ??
      "dynamic"
    );
  }
}
