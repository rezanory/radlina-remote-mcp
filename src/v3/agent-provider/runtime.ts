import { randomUUID } from "node:crypto";

import type { AuthInfo } from "@modelcontextprotocol/server";
import * as z from "zod/v4";

import { AppError } from "../../errors.js";
import type { PolicyEngine, Risk } from "../../policy/engine.js";
import { canonicalJson, sha256 } from "../../utils/json.js";
import type { DistributedAuditSigner } from "../audit/distributed.js";

const providerIdSchema = z
  .string()
  .min(1)
  .max(100)
  .regex(/^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/u);

export const agentProviderManifestSchema = z.object({
  providerId: providerIdSchema,
  version: z.string().min(1).max(64),
  description: z.string().min(1).max(500),
  requiredScope: z.string().min(1).max(128),
  risk: z.enum(["low", "medium", "high", "critical"]),
  maxInputBytes: z.number().int().positive().max(16 * 1024 * 1024),
  maxOutputBytes: z.number().int().positive().max(64 * 1024 * 1024),
  maxTimeoutMs: z.number().int().min(100).max(300_000),
});

export type AgentProviderManifest = z.infer<typeof agentProviderManifestSchema>;

export interface AgentProviderHost {
  invoke(input: {
    invocationId: string;
    payload: unknown;
    context: {
      subject: string;
      profile: string;
      signal: AbortSignal;
    };
  }): Promise<unknown>;
  cancel(invocationId: string): Promise<void>;
  shutdown(): Promise<void>;
}

export type AgentProviderInvocationReceipt = {
  providerId: string;
  providerVersion: string;
  invocationId: string;
  subject: string;
  profile: string;
  inputSha256: string;
  outputSha256: string | null;
  terminalState: "completed" | "failed" | "cancelled" | "timed_out";
  errorCode: string | null;
  startedAt: string;
  endedAt: string;
  globalCorrelationId: string;
  traceId: string;
  recordHash: string;
  signature: string;
};

export type AgentProviderOutcome =
  | {
      ok: true;
      result: unknown;
      receipt: AgentProviderInvocationReceipt;
    }
  | {
      ok: false;
      error: { code: string; message: string };
      receipt: AgentProviderInvocationReceipt;
    };

type RegisteredProvider = {
  manifest: AgentProviderManifest;
  host: AgentProviderHost;
};

class ProviderTimeoutError extends Error {
  constructor() {
    super("agent provider invocation timed out");
    this.name = "ProviderTimeoutError";
  }
}

class ProviderCancelledError extends Error {
  constructor() {
    super("agent provider invocation was cancelled");
    this.name = "ProviderCancelledError";
  }
}

export class AgentProviderRuntime {
  private readonly providers = new Map<string, RegisteredProvider>();

  constructor(
    private readonly policy: PolicyEngine,
    private readonly signer: DistributedAuditSigner,
    private readonly now: () => string = () => new Date().toISOString(),
    private readonly invocationIdFactory: () => string = () => randomUUID(),
  ) {}

  register(rawManifest: AgentProviderManifest, host: AgentProviderHost): void {
    const manifest = agentProviderManifestSchema.parse(rawManifest);
    if (this.providers.has(manifest.providerId)) {
      throw new AppError("CONFLICT", `agent provider ${manifest.providerId} is already registered`);
    }
    this.providers.set(manifest.providerId, { manifest, host });
  }

  async unregister(providerId: string): Promise<boolean> {
    const provider = this.providers.get(providerId);
    if (!provider) return false;
    this.providers.delete(providerId);
    await provider.host.shutdown();
    return true;
  }

  list(): AgentProviderManifest[] {
    return [...this.providers.values()]
      .map((entry) => entry.manifest)
      .sort((left, right) => left.providerId.localeCompare(right.providerId));
  }

  async invoke(
    input: {
      providerId: string;
      payload: unknown;
      timeoutMs: number;
      globalCorrelationId: string;
      traceId: string;
      signal?: AbortSignal;
    },
    context: {
      auth: AuthInfo | undefined;
      subject: string;
      profile: string;
    },
  ): Promise<AgentProviderOutcome> {
    const provider = this.providers.get(input.providerId);
    if (!provider) throw new AppError("NOT_FOUND", `agent provider ${input.providerId} is not registered`);
    if (!context.subject.trim() || !context.profile.trim()) {
      throw new AppError("INVALID_INPUT", "subject and profile are required");
    }
    const timeoutMs = Math.min(
      Math.max(Math.trunc(input.timeoutMs), 100),
      provider.manifest.maxTimeoutMs,
    );

    const decision = this.policy.decide(
      context.auth,
      "agent_provider.invoke",
      provider.manifest.requiredScope,
      context.profile,
      provider.manifest.risk as Risk,
    );
    if (!decision.allowed) throw new AppError("POLICY_DENIED", decision.reason);

    const inputJson = canonicalJson(input.payload);
    if (Buffer.byteLength(inputJson) > provider.manifest.maxInputBytes) {
      throw new AppError("LIMIT_EXCEEDED", "agent provider input exceeds configured limit");
    }

    const invocationId = this.invocationIdFactory();
    const startedAt = this.now();
    const inputSha256 = sha256(inputJson);
    const controller = new AbortController();
    let externallyCancelled = false;
    const onAbort = () => {
      externallyCancelled = true;
      controller.abort();
    };
    input.signal?.addEventListener("abort", onAbort, { once: true });

    let timer: NodeJS.Timeout | undefined;
    try {
      const timeout = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new ProviderTimeoutError());
        }, timeoutMs);
      });

      const execution = provider.host.invoke({
        invocationId,
        payload: input.payload,
        context: {
          subject: context.subject,
          profile: context.profile,
          signal: controller.signal,
        },
      });

      const result = await Promise.race([
        execution,
        timeout,
        new Promise<never>((_resolve, reject) => {
          controller.signal.addEventListener(
            "abort",
            () => {
              if (externallyCancelled) reject(new ProviderCancelledError());
            },
            { once: true },
          );
        }),
      ]);

      const outputJson = canonicalJson(result ?? null);
      if (Buffer.byteLength(outputJson) > provider.manifest.maxOutputBytes) {
        throw new AppError("LIMIT_EXCEEDED", "agent provider output exceeds configured limit");
      }

      return {
        ok: true,
        result,
        receipt: this.receipt(
          provider.manifest,
          {
            invocationId,
            subject: context.subject,
            profile: context.profile,
            inputSha256,
            outputSha256: sha256(outputJson),
            terminalState: "completed",
            errorCode: null,
            startedAt,
            endedAt: this.now(),
            globalCorrelationId: input.globalCorrelationId,
            traceId: input.traceId,
          },
        ),
      };
    } catch (error) {
      const timedOut = error instanceof ProviderTimeoutError;
      const cancelled = error instanceof ProviderCancelledError || externallyCancelled;
      if (timedOut || cancelled) {
        await provider.host.cancel(invocationId).catch(() => undefined);
      }
      const terminalState = timedOut ? "timed_out" : cancelled ? "cancelled" : "failed";
      const code =
        error instanceof Error && error.name
          ? error.name.slice(0, 128)
          : "AGENT_PROVIDER_FAILED";
      const message = error instanceof Error ? error.message.slice(0, 1000) : "agent provider failed";
      return {
        ok: false,
        error: { code, message },
        receipt: this.receipt(
          provider.manifest,
          {
            invocationId,
            subject: context.subject,
            profile: context.profile,
            inputSha256,
            outputSha256: null,
            terminalState,
            errorCode: code,
            startedAt,
            endedAt: this.now(),
            globalCorrelationId: input.globalCorrelationId,
            traceId: input.traceId,
          },
        ),
      };
    } finally {
      if (timer) clearTimeout(timer);
      input.signal?.removeEventListener("abort", onAbort);
    }
  }

  verifyReceipt(receipt: AgentProviderInvocationReceipt): boolean {
    const { recordHash, signature, ...payload } = receipt;
    return (
      recordHash === sha256(canonicalJson(payload)) &&
      this.signer.verify(recordHash, signature)
    );
  }

  private receipt(
    manifest: AgentProviderManifest,
    payload: Omit<
      AgentProviderInvocationReceipt,
      "providerId" | "providerVersion" | "recordHash" | "signature"
    >,
  ): AgentProviderInvocationReceipt {
    const body = {
      providerId: manifest.providerId,
      providerVersion: manifest.version,
      ...payload,
    };
    const recordHash = sha256(canonicalJson(body));
    return {
      ...body,
      recordHash,
      signature: this.signer.sign(recordHash),
    };
  }
}
