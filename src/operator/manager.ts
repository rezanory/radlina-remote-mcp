import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

import type { AuthInfo } from "@modelcontextprotocol/server";

import { protectBytes, unprotectBytes } from "../auth/dpapi.js";
import type { CapabilityRegistry } from "../components/registry.js";
import { AppError } from "../errors.js";
import type { Store } from "../persistence/store.js";
import type { PolicyEngine } from "../policy/engine.js";
import { sha256 } from "../utils/json.js";
import type { OperatorPlan } from "./types.js";

type JobRow = {
  id: string;
  subject: string;
  profile: string;
  title: string;
  status: string;
  cancel_requested: number;
  created_at: number;
  updated_at: number;
  started_at: number | null;
  ended_at: number | null;
};

type StepRow = {
  job_id: string;
  step_id: string;
  ordinal: number;
  capability: string;
  input_protected: string;
  input_sha256: string;
  status: string;
  attempts: number;
  max_attempts: number;
  result_protected: string | null;
  error_protected: string | null;
  started_at: number | null;
  ended_at: number | null;
};

const STEP_ID_PATTERN = /^[A-Za-z][A-Za-z0-9._-]{0,63}$/u;
const MAX_STEPS = 16;
const MAX_PLAN_BYTES = 64 * 1024;

export class OperatorManager {
  private readonly runners = new Map<string, Promise<void>>();
  private shuttingDown = false;

  constructor(
    private readonly store: Store,
    private readonly policy: PolicyEngine,
    private readonly capabilities: CapabilityRegistry,
  ) {}

  reconcile(): { interruptedJobs: number; interruptedSteps: number } {
    const now = Date.now();
    this.store.db.exec("BEGIN IMMEDIATE");
    try {
      const steps = this.store.db
        .prepare("UPDATE operator_steps SET status='interrupted',ended_at=? WHERE status='running'")
        .run(now);
      const jobs = this.store.db
        .prepare(
          "UPDATE operator_jobs SET status='interrupted',updated_at=?,ended_at=? WHERE status IN ('queued','running')",
        )
        .run(now, now);
      this.store.db.exec("COMMIT");
      return {
        interruptedJobs: Number(jobs.changes),
        interruptedSteps: Number(steps.changes),
      };
    } catch (error) {
      this.store.db.exec("ROLLBACK");
      throw error;
    }
  }

  async shutdown(): Promise<void> {
    this.shuttingDown = true;
    await Promise.allSettled([...this.runners.values()]);
    this.reconcile();
  }

  async submit(
    auth: AuthInfo | undefined,
    subject: string,
    profile: string,
    plan: OperatorPlan,
  ): Promise<{ jobId: string; status: string; steps: number }> {
    this.validatePlan(plan);
    this.authorize(
      auth,
      profile,
      plan.steps.map((step) => step.capability),
    );
    const prepared: Array<{
      step: OperatorPlan["steps"][number];
      inputProtected: string;
      inputSha256: string;
    }> = [];
    for (const step of plan.steps) {
      const provider = this.capabilities.resolve(step.capability);
      if (!provider.idempotent && step.maxAttempts !== 1) {
        throw new AppError(
          "INVALID_INPUT",
          `non-idempotent capability ${step.capability} must use maxAttempts=1`,
        );
      }
      const encodedInput = JSON.stringify(step.input);
      if (encodedInput === undefined) {
        throw new AppError("INVALID_INPUT", "operator step input is not serializable");
      }
      prepared.push({
        step,
        inputProtected: await protectBytes(Buffer.from(encodedInput, "utf8")),
        inputSha256: sha256(encodedInput),
      });
    }
    const jobId = randomUUID();
    const now = Date.now();
    this.store.db.exec("BEGIN IMMEDIATE");
    try {
      this.store.db
        .prepare(
          "INSERT INTO operator_jobs(id,subject,profile,title,status,cancel_requested,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
        )
        .run(jobId, subject, profile, plan.title, "queued", 0, now, now);
      const insert = this.store.db.prepare(
        "INSERT INTO operator_steps(job_id,step_id,ordinal,capability,input_protected,input_sha256,status,attempts,max_attempts) VALUES(?,?,?,?,?,?,?,?,?)",
      );
      prepared.forEach(({ step, inputProtected, inputSha256 }, ordinal) => {
        insert.run(
          jobId,
          step.id,
          ordinal,
          step.capability,
          inputProtected,
          inputSha256,
          "pending",
          0,
          step.maxAttempts,
        );
      });
      this.store.db.exec("COMMIT");
    } catch (error) {
      this.store.db.exec("ROLLBACK");
      throw error;
    }
    this.launch(jobId, auth);
    return { jobId, status: "queued", steps: plan.steps.length };
  }

  resume(
    auth: AuthInfo | undefined,
    subject: string,
    jobId: string,
  ): { jobId: string; status: string } {
    const job = this.job(jobId, subject);
    if (!new Set(["failed", "interrupted"]).has(job.status)) {
      throw new AppError("CONFLICT", `operator job in status ${job.status} cannot be resumed`);
    }
    const steps = this.steps(jobId);
    const retryable: StepRow[] = [];
    for (const step of steps) {
      if (step.status === "completed") continue;
      const provider = this.capabilities.resolve(step.capability);
      if (step.status === "pending") continue;
      if (!provider.idempotent) {
        throw new AppError(
          "CONFLICT",
          `step ${step.step_id} has a non-idempotent unknown/failed outcome; inspect it before submitting a new plan`,
        );
      }
      if (step.attempts >= step.max_attempts) {
        throw new AppError(
          "CONFLICT",
          `step ${step.step_id} exhausted its configured retry budget`,
        );
      }
      retryable.push(step);
    }
    this.authorize(
      auth,
      job.profile,
      steps.filter((step) => step.status !== "completed").map((step) => step.capability),
    );
    this.store.db.exec("BEGIN IMMEDIATE");
    try {
      const reset = this.store.db.prepare(
        "UPDATE operator_steps SET status='pending',error_protected=NULL,ended_at=NULL WHERE job_id=? AND step_id=?",
      );
      for (const step of retryable) reset.run(jobId, step.step_id);
      this.store.db
        .prepare(
          "UPDATE operator_jobs SET status='queued',cancel_requested=0,updated_at=?,ended_at=NULL WHERE id=?",
        )
        .run(Date.now(), jobId);
      this.store.db.exec("COMMIT");
    } catch (error) {
      this.store.db.exec("ROLLBACK");
      throw error;
    }
    this.launch(jobId, auth);
    return { jobId, status: "queued" };
  }

  cancel(subject: string, jobId: string): { jobId: string; status: string; requested: boolean } {
    const job = this.job(jobId, subject);
    if (new Set(["completed", "failed", "cancelled"]).has(job.status)) {
      return { jobId, status: job.status, requested: false };
    }
    const now = Date.now();
    if (job.status === "running") {
      this.store.db
        .prepare("UPDATE operator_jobs SET cancel_requested=1,updated_at=? WHERE id=?")
        .run(now, jobId);
      return { jobId, status: "running", requested: true };
    }
    this.store.db.exec("BEGIN IMMEDIATE");
    try {
      this.store.db
        .prepare(
          "UPDATE operator_jobs SET status='cancelled',cancel_requested=1,updated_at=?,ended_at=? WHERE id=?",
        )
        .run(now, now, jobId);
      this.store.db
        .prepare(
          "UPDATE operator_steps SET status='cancelled',ended_at=? WHERE job_id=? AND status='pending'",
        )
        .run(now, jobId);
      this.store.db.exec("COMMIT");
    } catch (error) {
      this.store.db.exec("ROLLBACK");
      throw error;
    }
    return { jobId, status: "cancelled", requested: true };
  }

  async status(subject: string, jobId: string): Promise<unknown> {
    const job = this.job(jobId, subject);
    return await this.render(job, this.steps(jobId));
  }

  async recent(subject: string, limit = 20): Promise<unknown[]> {
    const bounded = Math.min(Math.max(Math.trunc(limit), 1), 100);
    const rows = this.store.db
      .prepare(
        "SELECT * FROM operator_jobs WHERE subject=? ORDER BY created_at DESC,id DESC LIMIT ?",
      )
      .all(subject, bounded) as JobRow[];
    return await Promise.all(rows.map((job) => this.render(job, this.steps(job.id))));
  }

  private launch(jobId: string, auth: AuthInfo | undefined): void {
    if (this.shuttingDown) throw new AppError("CONFLICT", "operator manager is shutting down");
    if (this.runners.has(jobId)) throw new AppError("CONFLICT", "operator job is already running");
    const runner = Promise.resolve()
      .then(() => this.run(jobId, auth))
      .catch(async (error: unknown) => {
        if (this.shuttingDown) {
          this.interruptJob(jobId);
          return;
        }
        const now = Date.now();
        let protectedError: string | null = null;
        try {
          protectedError = await this.protectText(this.errorJson(error));
        } catch {
          // Never fall back to plaintext persistence when local protection is unavailable.
        }
        this.store.db
          .prepare(
            "UPDATE operator_jobs SET status='failed',updated_at=?,ended_at=? WHERE id=? AND status NOT IN ('completed','cancelled')",
          )
          .run(now, now, jobId);
        this.store.db
          .prepare(
            "UPDATE operator_steps SET status='failed',error_protected=?,ended_at=? WHERE job_id=? AND status='running'",
          )
          .run(protectedError, now, jobId);
      })
      .finally(() => {
        this.runners.delete(jobId);
      });
    this.runners.set(jobId, runner);
  }

  private async run(jobId: string, auth: AuthInfo | undefined): Promise<void> {
    const initial = this.jobById(jobId);
    if (this.shuttingDown) {
      this.interruptJob(jobId);
      return;
    }
    this.authorize(
      auth,
      initial.profile,
      this.steps(jobId)
        .filter((step) => step.status !== "completed")
        .map((step) => step.capability),
    );
    const now = Date.now();
    this.store.db
      .prepare(
        "UPDATE operator_jobs SET status='running',updated_at=?,started_at=COALESCE(started_at,?),ended_at=NULL WHERE id=?",
      )
      .run(now, now, jobId);

    for (const original of this.steps(jobId)) {
      if (original.status === "completed") continue;
      if (this.cancelRequested(jobId)) {
        this.finishCancelled(jobId);
        return;
      }
      if (this.shuttingDown) {
        this.interruptJob(jobId);
        return;
      }
      const provider = this.capabilities.resolve(original.capability);
      if (original.status === "interrupted" && !provider.idempotent) {
        throw new AppError(
          "CONFLICT",
          `step ${original.step_id} cannot be replayed because its previous outcome is unknown`,
        );
      }
      let step = this.step(jobId, original.step_id);
      while (step.attempts < step.max_attempts) {
        const attempt = step.attempts + 1;
        this.store.db
          .prepare(
            "UPDATE operator_steps SET status='running',attempts=?,started_at=COALESCE(started_at,?),ended_at=NULL WHERE job_id=? AND step_id=?",
          )
          .run(attempt, Date.now(), jobId, step.step_id);
        try {
          const inputText = (await unprotectBytes(step.input_protected)).toString("utf8");
          if (sha256(inputText) !== step.input_sha256) {
            throw new AppError("INTERNAL_ERROR", "operator step input integrity check failed");
          }
          const result = await provider.execute(
            {
              subject: initial.subject,
              profile: initial.profile,
              auth,
              isCancelled: () => this.shuttingDown || this.cancelRequested(jobId),
            },
            JSON.parse(inputText) as unknown,
          );
          if (this.cancelRequested(jobId)) {
            this.store.db
              .prepare(
                "UPDATE operator_steps SET status='cancelled',ended_at=? WHERE job_id=? AND step_id=?",
              )
              .run(Date.now(), jobId, step.step_id);
            this.finishCancelled(jobId);
            return;
          }
          if (this.shuttingDown) {
            this.interruptJob(jobId, step.step_id);
            return;
          }
          const protectedResult = await this.protectText(this.resultJson(result));
          this.store.db
            .prepare(
              "UPDATE operator_steps SET status='completed',result_protected=?,error_protected=NULL,ended_at=? WHERE job_id=? AND step_id=?",
            )
            .run(protectedResult, Date.now(), jobId, step.step_id);
          break;
        } catch (error) {
          const protectedError = await this.protectText(this.errorJson(error));
          if (this.cancelRequested(jobId)) {
            this.store.db
              .prepare(
                "UPDATE operator_steps SET status='cancelled',error_protected=?,ended_at=? WHERE job_id=? AND step_id=?",
              )
              .run(protectedError, Date.now(), jobId, step.step_id);
            this.finishCancelled(jobId);
            return;
          }
          if (this.shuttingDown) {
            this.interruptJob(jobId, step.step_id);
            return;
          }
          if (provider.idempotent && attempt < step.max_attempts) {
            this.store.db
              .prepare(
                "UPDATE operator_steps SET status='pending',error_protected=?,ended_at=? WHERE job_id=? AND step_id=?",
              )
              .run(protectedError, Date.now(), jobId, step.step_id);
            await delay(Math.min(100 * 2 ** (attempt - 1), 1_000));
            step = this.step(jobId, step.step_id);
            continue;
          }
          const failedAt = Date.now();
          this.store.db.exec("BEGIN IMMEDIATE");
          try {
            this.store.db
              .prepare(
                "UPDATE operator_steps SET status='failed',error_protected=?,ended_at=? WHERE job_id=? AND step_id=?",
              )
              .run(protectedError, failedAt, jobId, step.step_id);
            this.store.db
              .prepare(
                "UPDATE operator_jobs SET status='failed',updated_at=?,ended_at=? WHERE id=?",
              )
              .run(failedAt, failedAt, jobId);
            this.store.db.exec("COMMIT");
          } catch (transactionError) {
            this.store.db.exec("ROLLBACK");
            throw transactionError;
          }
          return;
        }
      }
      const completed = this.step(jobId, original.step_id);
      if (completed.status !== "completed") return;
    }
    if (this.shuttingDown) {
      this.interruptJob(jobId);
      return;
    }
    const finishedAt = Date.now();
    this.store.db
      .prepare(
        "UPDATE operator_jobs SET status='completed',updated_at=?,ended_at=? WHERE id=? AND cancel_requested=0",
      )
      .run(finishedAt, finishedAt, jobId);
    if (this.cancelRequested(jobId)) this.finishCancelled(jobId);
  }

  private interruptJob(jobId: string, stepId?: string): void {
    const now = Date.now();
    this.store.db.exec("BEGIN IMMEDIATE");
    try {
      if (stepId) {
        this.store.db
          .prepare(
            "UPDATE operator_steps SET status='interrupted',ended_at=? WHERE job_id=? AND step_id=? AND status='running'",
          )
          .run(now, jobId, stepId);
      } else {
        this.store.db
          .prepare(
            "UPDATE operator_steps SET status='interrupted',ended_at=? WHERE job_id=? AND status='running'",
          )
          .run(now, jobId);
      }
      this.store.db
        .prepare(
          "UPDATE operator_jobs SET status='interrupted',updated_at=?,ended_at=? WHERE id=? AND status IN ('queued','running')",
        )
        .run(now, now, jobId);
      this.store.db.exec("COMMIT");
    } catch (error) {
      this.store.db.exec("ROLLBACK");
      throw error;
    }
  }

  private authorize(auth: AuthInfo | undefined, profile: string, capabilityIds: string[]): void {
    for (const capabilityId of capabilityIds) {
      const provider = this.capabilities.resolve(capabilityId);
      const decision = this.policy.decide(
        auth,
        "operator_submit",
        provider.requiredScope,
        profile,
        provider.risk,
      );
      if (!decision.allowed) {
        throw new AppError("POLICY_DENIED", decision.reason, {
          capability: capabilityId,
          requiredScope: provider.requiredScope,
        });
      }
    }
  }

  private validatePlan(plan: OperatorPlan): void {
    if (typeof plan.title !== "string" || plan.title.trim().length < 1 || plan.title.length > 128) {
      throw new AppError("INVALID_INPUT", "operator plan title must be 1-128 characters");
    }
    if (!Array.isArray(plan.steps) || plan.steps.length < 1 || plan.steps.length > MAX_STEPS) {
      throw new AppError("INVALID_INPUT", `operator plan must contain 1-${MAX_STEPS} steps`);
    }
    const ids = new Set<string>();
    for (const step of plan.steps) {
      if (!STEP_ID_PATTERN.test(step.id) || ids.has(step.id)) {
        throw new AppError("INVALID_INPUT", "operator step ids must be unique and well formed");
      }
      ids.add(step.id);
      this.capabilities.resolve(step.capability);
      if (!Number.isInteger(step.maxAttempts) || step.maxAttempts < 1 || step.maxAttempts > 3) {
        throw new AppError("INVALID_INPUT", "maxAttempts must be between 1 and 3");
      }
      const encoded = JSON.stringify(step.input);
      if (encoded === undefined)
        throw new AppError("INVALID_INPUT", "operator step input is not serializable");
    }
    if (Buffer.byteLength(JSON.stringify(plan)) > MAX_PLAN_BYTES) {
      throw new AppError("LIMIT_EXCEEDED", "operator plan exceeds the size limit");
    }
  }

  private cancelRequested(jobId: string): boolean {
    const row = this.store.db
      .prepare("SELECT cancel_requested FROM operator_jobs WHERE id=?")
      .get(jobId) as { cancel_requested?: number } | undefined;
    return row?.cancel_requested === 1;
  }

  private finishCancelled(jobId: string): void {
    const now = Date.now();
    this.store.db.exec("BEGIN IMMEDIATE");
    try {
      this.store.db
        .prepare(
          "UPDATE operator_jobs SET status='cancelled',cancel_requested=1,updated_at=?,ended_at=? WHERE id=?",
        )
        .run(now, now, jobId);
      this.store.db
        .prepare(
          "UPDATE operator_steps SET status='cancelled',ended_at=? WHERE job_id=? AND status='pending'",
        )
        .run(now, jobId);
      this.store.db.exec("COMMIT");
    } catch (error) {
      this.store.db.exec("ROLLBACK");
      throw error;
    }
  }

  private job(jobId: string, subject: string): JobRow {
    const row = this.store.db
      .prepare("SELECT * FROM operator_jobs WHERE id=? AND subject=?")
      .get(jobId, subject) as JobRow | undefined;
    if (!row) throw new AppError("NOT_FOUND", "operator job was not found");
    return row;
  }

  private jobById(jobId: string): JobRow {
    const row = this.store.db.prepare("SELECT * FROM operator_jobs WHERE id=?").get(jobId) as
      JobRow | undefined;
    if (!row) throw new AppError("NOT_FOUND", "operator job was not found");
    return row;
  }

  private steps(jobId: string): StepRow[] {
    return this.store.db
      .prepare("SELECT * FROM operator_steps WHERE job_id=? ORDER BY ordinal ASC")
      .all(jobId) as StepRow[];
  }

  private step(jobId: string, stepId: string): StepRow {
    const row = this.store.db
      .prepare("SELECT * FROM operator_steps WHERE job_id=? AND step_id=?")
      .get(jobId, stepId) as StepRow | undefined;
    if (!row) throw new AppError("NOT_FOUND", "operator step was not found");
    return row;
  }

  private async render(job: JobRow, steps: StepRow[]): Promise<unknown> {
    return {
      jobId: job.id,
      title: job.title,
      profile: job.profile,
      status: job.status,
      cancelRequested: job.cancel_requested === 1,
      createdAt: new Date(job.created_at).toISOString(),
      updatedAt: new Date(job.updated_at).toISOString(),
      startedAt: job.started_at === null ? null : new Date(job.started_at).toISOString(),
      endedAt: job.ended_at === null ? null : new Date(job.ended_at).toISOString(),
      steps: await Promise.all(
        steps.map(async (step) => ({
          id: step.step_id,
          ordinal: step.ordinal,
          capability: step.capability,
          status: step.status,
          attempts: step.attempts,
          maxAttempts: step.max_attempts,
          inputSha256: step.input_sha256,
          result: await this.unprotectJson(step.result_protected),
          error: await this.unprotectJson(step.error_protected),
          startedAt: step.started_at === null ? null : new Date(step.started_at).toISOString(),
          endedAt: step.ended_at === null ? null : new Date(step.ended_at).toISOString(),
        })),
      ),
    };
  }

  private async protectText(value: string): Promise<string> {
    return await protectBytes(Buffer.from(value, "utf8"));
  }

  private async unprotectJson(value: string | null): Promise<unknown> {
    if (!value) return null;
    return JSON.parse((await unprotectBytes(value)).toString("utf8")) as unknown;
  }

  private resultJson(result: unknown): string {
    const encoded = JSON.stringify(result);
    if (encoded === undefined)
      throw new AppError("INTERNAL_ERROR", "operator result is not serializable");
    if (Buffer.byteLength(encoded) > 128 * 1024) {
      throw new AppError("LIMIT_EXCEEDED", "operator result exceeds the persistence limit");
    }
    return encoded;
  }

  private errorJson(error: unknown): string {
    const payload =
      error instanceof AppError
        ? { code: error.code, message: error.message }
        : {
            code: "INTERNAL_ERROR",
            message:
              error instanceof Error ? error.message.slice(0, 512) : "unknown operator failure",
          };
    return JSON.stringify(payload);
  }
}
