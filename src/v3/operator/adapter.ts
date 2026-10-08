import type { AuthInfo } from "@modelcontextprotocol/server";
import type { DatabaseSync } from "node:sqlite";

import type { CapabilityRegistry } from "../../components/registry.js";
import { AppError } from "../../errors.js";
import type { PolicyEngine } from "../../policy/engine.js";
import {
  deviceTargetSchema,
  legacyOperatorPlanSchema,
  type DeviceTarget,
  type DispatchReceipt,
  type LegacyOperatorPlan,
  type WorkflowDefinition,
} from "../workflow/contracts.js";
import type { WorkflowSnapshot } from "../workflow/persistence.js";

export type OperatorBoundContext = {
  subject: string;
  profile: string;
  clientId: string | null;
  scopes: string[];
};

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

export interface OperatorReceiptReader {
  attemptReceipt(executionId: string, nodeId: string, attempt: number): DispatchReceipt | undefined;
}

type BindingRow = {
  job_id: string;
  subject: string;
  profile: string;
  title: string;
  idempotency_key: string;
  client_id: string | null;
  scopes_json: string;
  step_meta_json: string;
  created_at: number;
};

type StepMeta = {
  id: string;
  capability: string;
  maxAttempts: number;
};

export type OperatorStatusProjection = {
  jobId: string;
  title: string;
  profile: string;
  status: WorkflowSnapshot["status"];
  createdAt: string;
  steps: Array<{
    id: string;
    capability: string;
    status: "pending" | "running" | "completed" | "failed" | "cancelled" | "interrupted";
    attempts: number;
    maxAttempts: number;
    receipt: DispatchReceipt | null;
  }>;
};

export class SmartOperatorAdapter {
  constructor(
    private readonly db: DatabaseSync,
    private readonly policy: PolicyEngine,
    private readonly capabilities: CapabilityRegistry,
    private readonly workflow: OperatorWorkflowPort,
    private readonly receipts: OperatorReceiptReader,
    private readonly defaultTarget: DeviceTarget = { deviceId: "windows-main" },
  ) {
    deviceTargetSchema.parse(defaultTarget);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS v3_operator_bindings (
        job_id TEXT PRIMARY KEY,
        subject TEXT NOT NULL,
        profile TEXT NOT NULL,
        title TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        client_id TEXT,
        scopes_json TEXT NOT NULL,
        step_meta_json TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        UNIQUE(subject,idempotency_key)
      );
      CREATE INDEX IF NOT EXISTS v3_operator_bindings_subject_created
        ON v3_operator_bindings(subject,created_at DESC,job_id DESC);
    `);
  }

  async submit(
    auth: AuthInfo | undefined,
    subject: string,
    profile: string,
    rawPlan: LegacyOperatorPlan,
    idempotencyKey: string,
    target: DeviceTarget = this.defaultTarget,
  ): Promise<{ jobId: string; status: string; steps: number; replayed: boolean }> {
    if (!subject.trim() || !profile.trim() || !idempotencyKey.trim()) {
      throw new AppError("INVALID_INPUT", "subject, profile and idempotencyKey are required");
    }
    const plan = legacyOperatorPlanSchema.parse(rawPlan);
    const selectedTarget = deviceTargetSchema.parse(target);
    this.preflight(auth, profile, plan);

    const existing = this.bindingByIdempotency(subject, idempotencyKey);
    if (existing && existing.profile !== profile) {
      throw new AppError(
        "CONFLICT",
        "operator idempotency key is already bound to a different profile",
      );
    }

    const definition = this.translate(plan, selectedTarget);
    const submitted = await this.workflow.submit({
      subject,
      idempotencyKey,
      definition,
    });

    if (existing && existing.job_id !== submitted.executionId) {
      throw new AppError(
        "CONFLICT",
        "operator compatibility binding does not match canonical workflow execution",
      );
    }
    if (!existing) {
      const stepMeta: StepMeta[] = plan.steps.map((step) => ({
        id: step.id,
        capability: step.capability,
        maxAttempts: step.maxAttempts,
      }));
      const scopes = [...new Set(auth?.scopes ?? [])].sort();
      this.db
        .prepare(
          `INSERT INTO v3_operator_bindings(
            job_id,subject,profile,title,idempotency_key,client_id,scopes_json,step_meta_json,created_at
          ) VALUES(?,?,?,?,?,?,?,?,?)`,
        )
        .run(
          submitted.executionId,
          subject,
          profile,
          plan.title,
          idempotencyKey,
          auth?.clientId ?? null,
          JSON.stringify(scopes),
          JSON.stringify(stepMeta),
          Date.now(),
        );
    }

    return {
      jobId: submitted.executionId,
      status: this.workflow.status(submitted.executionId).status,
      steps: plan.steps.length,
      replayed: submitted.replayed,
    };
  }

  status(subject: string, jobId: string): OperatorStatusProjection {
    return this.project(this.binding(jobId, subject));
  }

  recent(subject: string, limit = 20): OperatorStatusProjection[] {
    const bounded = Math.min(Math.max(Math.trunc(limit), 1), 100);
    const rows = this.db
      .prepare(
        "SELECT * FROM v3_operator_bindings WHERE subject=? ORDER BY created_at DESC,job_id DESC LIMIT ?",
      )
      .all(subject, bounded) as BindingRow[];
    return rows.map((row) => this.project(row));
  }

  async resume(
    auth: AuthInfo | undefined,
    subject: string,
    jobId: string,
  ): Promise<{ jobId: string; status: string }> {
    const binding = this.binding(jobId, subject);
    this.assertBoundAuth(auth, binding);
    const snapshot = this.workflow.status(jobId);
    const node = snapshot.nodes.find(
      (candidate) => candidate.status === "failed" || candidate.status === "interrupted",
    );
    if (!node) {
      throw new AppError("CONFLICT", "operator job has no failed/interrupted step to resume");
    }
    const resumed = await this.workflow.resumeNode(jobId, node.id);
    return { jobId, status: resumed.status };
  }

  async cancel(
    auth: AuthInfo | undefined,
    subject: string,
    jobId: string,
  ): Promise<{ jobId: string; status: string; requested: boolean }> {
    const binding = this.binding(jobId, subject);
    this.assertBoundAuth(auth, binding);
    const before = this.workflow.status(jobId);
    if (before.status === "completed" || before.status === "cancelled") {
      return { jobId, status: before.status, requested: false };
    }
    const after = await this.workflow.cancel(jobId);
    return { jobId, status: after.status, requested: true };
  }

  context(subject: string, jobId: string): OperatorBoundContext {
    const row = this.binding(jobId, subject);
    return {
      subject: row.subject,
      profile: row.profile,
      clientId: row.client_id,
      scopes: JSON.parse(row.scopes_json) as string[],
    };
  }

  translate(
    plan: LegacyOperatorPlan,
    target: DeviceTarget = this.defaultTarget,
  ): WorkflowDefinition {
    const parsed = legacyOperatorPlanSchema.parse(plan);
    const selectedTarget = deviceTargetSchema.parse(target);
    return {
      workflowId: "operator.plan",
      definitionVersion: "1.0.0",
      title: parsed.title,
      nodes: parsed.steps.map((step, index) => ({
        id: step.id,
        capability: step.capability,
        input: step.input,
        dependsOn: index === 0 ? [] : [parsed.steps[index - 1]!.id],
        target: selectedTarget,
        maxAttempts: step.maxAttempts,
        timeoutMs: 86_400_000,
        executionPolicy: {
          failureMode: "fail-workflow",
          allowDynamicReroute: false,
          unknownOutcome: "manual-resume",
        },
        expectedOutput: {
          contractId: `${step.capability}/result-v1`,
          artifactMode: "either",
          maxBytes: 1_073_741_824,
        },
      })),
    };
  }

  private preflight(auth: AuthInfo | undefined, profile: string, plan: LegacyOperatorPlan): void {
    for (const step of plan.steps) {
      const provider = this.capabilities.resolve(step.capability);
      if (!provider.idempotent && step.maxAttempts !== 1) {
        throw new AppError(
          "INVALID_INPUT",
          `non-idempotent capability ${step.capability} must use maxAttempts=1`,
        );
      }
      const decision = this.policy.decide(
        auth,
        "operator_submit",
        provider.requiredScope,
        profile,
        provider.risk,
      );
      if (!decision.allowed) {
        throw new AppError("POLICY_DENIED", decision.reason, {
          capability: step.capability,
          requiredScope: provider.requiredScope,
        });
      }
    }
  }

  private assertBoundAuth(auth: AuthInfo | undefined, binding: BindingRow): void {
    if (!auth) throw new AppError("POLICY_DENIED", "missing authenticated identity");
    const boundScopes = JSON.parse(binding.scopes_json) as string[];
    const current = new Set(auth.scopes);
    for (const scope of boundScopes) {
      if (!current.has(scope) && !current.has("admin")) {
        throw new AppError("POLICY_DENIED", `bound scope ${scope} is no longer granted`);
      }
    }
    if (binding.client_id !== null && auth.clientId !== binding.client_id) {
      throw new AppError("POLICY_DENIED", "operator job is bound to a different OAuth client");
    }
  }

  private project(binding: BindingRow): OperatorStatusProjection {
    const snapshot = this.workflow.status(binding.job_id);
    const metadata = JSON.parse(binding.step_meta_json) as StepMeta[];
    const byId = new Map(snapshot.nodes.map((node) => [node.id, node] as const));
    return {
      jobId: binding.job_id,
      title: binding.title,
      profile: binding.profile,
      status: snapshot.status,
      createdAt: new Date(binding.created_at).toISOString(),
      steps: metadata.map((meta) => {
        const node = byId.get(meta.id);
        if (!node) throw new AppError("INTERNAL_ERROR", `workflow node ${meta.id} is missing`);
        return {
          id: meta.id,
          capability: meta.capability,
          status: this.legacyStepStatus(node.status),
          attempts: node.attempts,
          maxAttempts: meta.maxAttempts,
          receipt:
            node.attempts > 0
              ? (this.receipts.attemptReceipt(binding.job_id, meta.id, node.attempts) ?? null)
              : null,
        };
      }),
    };
  }

  private binding(jobId: string, subject: string): BindingRow {
    const row = this.db
      .prepare("SELECT * FROM v3_operator_bindings WHERE job_id=? AND subject=?")
      .get(jobId, subject) as BindingRow | undefined;
    if (!row) throw new AppError("NOT_FOUND", "operator job was not found");
    return row;
  }

  private bindingByIdempotency(subject: string, idempotencyKey: string): BindingRow | undefined {
    return this.db
      .prepare("SELECT * FROM v3_operator_bindings WHERE subject=? AND idempotency_key=?")
      .get(subject, idempotencyKey) as BindingRow | undefined;
  }

  private legacyStepStatus(
    status: WorkflowSnapshot["nodes"][number]["status"],
  ): "pending" | "running" | "completed" | "failed" | "cancelled" | "interrupted" {
    if (status === "ready" || status === "blocked") return "pending";
    return status;
  }
}
