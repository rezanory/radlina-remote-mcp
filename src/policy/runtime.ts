import { randomUUID } from "node:crypto";
import os from "node:os";

import type { AuthInfo, CallToolResult } from "@modelcontextprotocol/server";

import type { AuditChain } from "../audit/chain.js";
import { AppError, errorPayload } from "../errors.js";
import type { Store } from "../persistence/store.js";
import { canonicalJson, sha256 } from "../utils/json.js";
import { type Risk, PolicyEngine } from "./engine.js";

type RunOptions<T> = {
  auth: AuthInfo | undefined;
  tool: string;
  scope: string;
  profile?: string;
  risk?: Risk;
  args: unknown;
  auditArgs?: unknown;
  idempotencyKey?: string;
  signal?: AbortSignal;
  handler: () => Promise<T>;
};

export class ToolRuntime {
  private readonly inFlight = new Map<string, { argsHash: string; promise: Promise<unknown> }>();

  constructor(
    private readonly policy: PolicyEngine,
    private readonly audit: AuditChain,
    private readonly store: Store,
  ) {}

  async run<T>(options: RunOptions<T>): Promise<CallToolResult> {
    const started = performance.now();
    const correlationId = randomUUID();
    const subjectValue = options.auth?.extra?.["sub"];
    const subject =
      typeof subjectValue === "string" ? subjectValue : (options.auth?.clientId ?? "unknown");
    const decision = this.policy.decide(
      options.auth,
      options.tool,
      options.scope,
      options.profile,
      options.risk,
    );
    let exitState = "denied";
    try {
      if (!decision.allowed)
        throw new AppError("POLICY_DENIED", decision.reason, { requiredScope: options.scope });
      if (options.signal?.aborted) throw new AppError("INVALID_INPUT", "request was cancelled");
      const argsHash = sha256(canonicalJson(options.args));
      if (options.idempotencyKey) {
        const cached = this.store.idempotentResult(
          options.idempotencyKey,
          subject,
          options.tool,
          argsHash,
        );
        if (cached !== undefined) {
          exitState = "idempotent-replay";
          return this.success(cached, correlationId, true);
        }
        const inFlightKey = `${subject}\0${options.tool}\0${options.idempotencyKey}`;
        const running = this.inFlight.get(inFlightKey);
        if (running) {
          if (running.argsHash !== argsHash) {
            throw new AppError(
              "CONFLICT",
              "Idempotency key is in progress with different arguments",
            );
          }
          const result = await running.promise;
          exitState = "idempotent-replay";
          return this.success(result, correlationId, true);
        }
        if (!this.store.claimIdempotency(options.idempotencyKey, subject, options.tool, argsHash)) {
          throw new AppError(
            "CONFLICT",
            "A previous attempt has an unknown outcome; inspect it locally before clearing the durable idempotency claim",
          );
        }
        const pending = Promise.resolve().then(options.handler);
        this.inFlight.set(inFlightKey, { argsHash, promise: pending });
        try {
          const result = await pending;
          this.store.saveIdempotentResult(
            options.idempotencyKey,
            subject,
            options.tool,
            argsHash,
            result,
          );
          exitState = "success";
          return this.success(result, correlationId, false);
        } finally {
          this.inFlight.delete(inFlightKey);
        }
      }
      const result = await options.handler();
      exitState = "success";
      return this.success(result, correlationId, false);
    } catch (error) {
      exitState = error instanceof AppError ? error.code : "INTERNAL_ERROR";
      if (error instanceof AppError) {
        this.store.db
          .prepare(
            "INSERT OR REPLACE INTO errors(correlation_id,code,message,detail_json,created_at) VALUES(?,?,?,?,?)",
          )
          .run(
            correlationId,
            error.code,
            error.message,
            JSON.stringify(error.details ?? {}),
            Date.now(),
          );
      }
      return errorPayload(error, correlationId);
    } finally {
      await this.audit.append({
        correlationId,
        subject,
        deviceId: os.hostname(),
        tool: options.tool,
        args: options.auditArgs ?? options.args,
        decision:
          exitState === "denied" || exitState === "POLICY_DENIED"
            ? "deny"
            : exitState === "success" || exitState === "idempotent-replay"
              ? "allow"
              : "error",
        durationMs: Math.round(performance.now() - started),
        exitState,
      });
    }
  }

  private success(value: unknown, correlationId: string, replayed: boolean): CallToolResult {
    const structured = { result: value, correlationId, replayed } as never;
    return {
      content: [{ type: "text", text: JSON.stringify(structured) }],
      structuredContent: structured,
    };
  }
}
