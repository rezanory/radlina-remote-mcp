import { randomUUID } from "node:crypto";

import type { AuthInfo } from "@modelcontextprotocol/server";

import { AppError } from "../../errors.js";
import type { OperatorPlan } from "../../operator/types.js";
import {
  legacyOperatorPlanSchema,
  legacySequentialDependencies,
  parseWorkflowDefinition,
  type DeviceTarget,
  type WorkflowDefinition,
} from "../workflow/contracts.js";
import type { WorkflowSnapshot } from "../workflow/persistence.js";

export interface OperatorWorkflowPort {
  submit(input: {
    executionId?: string;
    subject: string;
    idempotencyKey: string;
    definition: WorkflowDefinition;
  }): Promise<{ executionId: string; replayed: boolean }>;
  status(executionId: string): WorkflowSnapshot;
  resumeNode(executionId: string, nodeId: string): Promise<WorkflowSnapshot>;
  cancel(executionId: string): Promise<WorkflowSnapshot>;
}

export interface OperatorWorkflowLauncher {
  launch(executionId: string): void;
}

export interface OperatorCapabilityMetadataPort {
  isIdempotent(capability: string): boolean;
}

export type SmartOperatorAdapterOptions = {
  defaultTarget: DeviceTarget;
  nodeTimeoutMs?: number;
  maxOutputBytes?: number;
  workflowId?: string;
};

export type OperatorCompatibilityStatus = {
  jobId: string;
  status: WorkflowSnapshot["status"];
  steps: Array<{
    id: string;
    status: WorkflowSnapshot["nodes"][number]["status"];
    attempts: number;
    maxAttempts: number;
  }>;
};

export class SmartOperatorAdapter {
  private readonly nodeTimeoutMs: number;
  private readonly maxOutputBytes: number;
  private readonly workflowId: string;

  constructor(
    private readonly workflow: OperatorWorkflowPort,
    private readonly launcher: OperatorWorkflowLauncher,
    private readonly capabilities: OperatorCapabilityMetadataPort,
    private readonly options: SmartOperatorAdapterOptions,
    private readonly executionIdFactory: () => string = () => randomUUID(),
  ) {
    this.nodeTimeoutMs = options.nodeTimeoutMs ?? 60_000;
    this.maxOutputBytes = options.maxOutputBytes ?? 1_048_576;
    this.workflowId = options.workflowId ?? "operator.legacy";

    if (!(this.nodeTimeoutMs >= 100 && this.nodeTimeoutMs <= 86_400_000)) {
      throw new AppError("INVALID_INPUT", "operator node timeout is outside allowed bounds");
    }
    if (!(this.maxOutputBytes > 0 && this.maxOutputBytes <= 1_073_741_824)) {
      throw new AppError("INVALID_INPUT", "operator output bound is outside allowed limits");
    }
  }

  translate(plan: OperatorPlan): WorkflowDefinition {
    const parsed = legacyOperatorPlanSchema.parse(plan);
    const dependencies = legacySequentialDependencies(parsed);
    const dependencyById = new Map(
      dependencies.map((entry) => [entry.id, entry.dependsOn] as const),
    );

    for (const step of parsed.steps) {
      if (!this.capabilities.isIdempotent(step.capability) && step.maxAttempts !== 1) {
        throw new AppError(
          "INVALID_INPUT",
          `non-idempotent capability ${step.capability} must use maxAttempts=1`,
        );
      }
    }

    return parseWorkflowDefinition({
      workflowId: this.workflowId,
      definitionVersion: "1.0.0",
      title: parsed.title,
      nodes: parsed.steps.map((step) => ({
        id: step.id,
        capability: step.capability,
        input: step.input,
        dependsOn: dependencyById.get(step.id) ?? [],
        target: this.options.defaultTarget,
        maxAttempts: step.maxAttempts,
        timeoutMs: this.nodeTimeoutMs,
        executionPolicy: {
          failureMode: "fail-workflow",
          allowDynamicReroute: false,
          unknownOutcome: "manual-resume",
        },
        expectedOutput: {
          contractId: `${step.capability}/operator-result-v1`,
          artifactMode: "either",
          maxBytes: this.maxOutputBytes,
        },
      })),
    });
  }

  async submit(
    _auth: AuthInfo | undefined,
    subject: string,
    _profile: string,
    plan: OperatorPlan,
  ): Promise<{ jobId: string; status: "queued"; steps: number }> {
    if (!subject.trim()) throw new AppError("INVALID_INPUT", "operator subject is required");

    const executionId = this.executionIdFactory();
    const definition = this.translate(plan);
    const created = await this.workflow.submit({
      executionId,
      subject,
      idempotencyKey: `operator:${executionId}`,
      definition,
    });

    this.launcher.launch(created.executionId);
    return {
      jobId: created.executionId,
      status: "queued",
      steps: definition.nodes.length,
    };
  }

  async status(subject: string, jobId: string): Promise<OperatorCompatibilityStatus> {
    const snapshot = this.ownedSnapshot(subject, jobId);
    return this.project(snapshot);
  }

  async resume(
    _auth: AuthInfo | undefined,
    subject: string,
    jobId: string,
  ): Promise<{ jobId: string; status: "queued" }> {
    const snapshot = this.ownedSnapshot(subject, jobId);
    if (snapshot.status !== "failed" && snapshot.status !== "interrupted") {
      throw new AppError("CONFLICT", `operator job in status ${snapshot.status} cannot be resumed`);
    }

    const recoverable = snapshot.nodes.find(
      (node) => node.status === "failed" || node.status === "interrupted",
    );
    if (!recoverable) {
      throw new AppError("CONFLICT", "operator job has no recoverable node");
    }

    await this.workflow.resumeNode(jobId, recoverable.id);
    this.launcher.launch(jobId);
    return { jobId, status: "queued" };
  }

  async cancel(
    subject: string,
    jobId: string,
  ): Promise<{ jobId: string; status: string; requested: boolean }> {
    const snapshot = this.ownedSnapshot(subject, jobId);
    if (
      snapshot.status === "completed" ||
      snapshot.status === "failed" ||
      snapshot.status === "cancelled"
    ) {
      return { jobId, status: snapshot.status, requested: false };
    }

    const cancelled = await this.workflow.cancel(jobId);
    return { jobId, status: cancelled.status, requested: true };
  }

  reconcile(): { interruptedJobs: number; interruptedSteps: number } {
    return { interruptedJobs: 0, interruptedSteps: 0 };
  }

  async shutdown(): Promise<void> {
    // Canonical workflow runtime owns execution lifecycle and recovery.
  }

  private ownedSnapshot(subject: string, jobId: string): WorkflowSnapshot {
    const snapshot = this.workflow.status(jobId);
    if (snapshot.subject !== subject) {
      throw new AppError("NOT_FOUND", "operator job was not found");
    }
    return snapshot;
  }

  private project(snapshot: WorkflowSnapshot): OperatorCompatibilityStatus {
    return {
      jobId: snapshot.executionId,
      status: snapshot.status,
      steps: snapshot.nodes.map((node) => ({
        id: node.id,
        status: node.status,
        attempts: node.attempts,
        maxAttempts: node.maxAttempts,
      })),
    };
  }
}
