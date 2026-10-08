import { randomUUID } from "node:crypto";

import type { AuthInfo } from "@modelcontextprotocol/server";
import * as z from "zod/v4";

import type { PolicyEngine, Risk } from "../../policy/engine.js";
import { canonicalJson, sha256 } from "../../utils/json.js";
import type { DistributedAuditSigner } from "../audit/distributed.js";

const hashSchema = z.string().regex(/^[0-9a-f]{64}$/u);

export const agentProviderDescriptorSchema = z.object({
  id: z.string().regex(/^[a-z][a-z0-9-]{1,63}$/u),
  version: z.string().min(1).max(64),
  description: z.string().min(1).max(500),
  requiredScope: z.string().min(1).max(128),
  risk: z.enum(["low", "medium", "high", "critical"]),
});

export type AgentProviderDescriptor = z.infer<typeof agentProviderDescriptorSchema>;

export type AgentProviderInvocationContext = {
  invocationId: string;
  subject: string;
  profile: string;
  signal: AbortSignal;
};

export interface AgentProvider {
  descriptor: AgentProviderDescriptor;
  invoke(payload: unknown, context: AgentProviderInvocationContext): Promise<unknown>;
  cancel?(invocationId: string): Promise<void>;
}

export interface AgentProviderPolicyPort {
  authorize(input: {
    auth: AuthInfo | undefined;
    profile: string;
    providerId: string;
    requiredScope: string;
    risk: Risk;
  }): { allowed: boolean; reason: string };
}

export class PolicyEngineAgentProviderPolicy implements AgentProviderPolicyPort {
  constructor(private readonly policy: PolicyEngine) {}

  authorize(input: {
    auth: AuthInfo | undefined;
    profile: string;
    providerId: string;
    requiredScope: string;
    risk: Risk;
  }): { allowed: boolean; reason: string } {
    const decision = this.policy.decide(
      input.auth,
      "agent_provider.invoke",
      input.requiredScope,
      input.profile,
      input.risk,
    );
    return { allowed: decision.allowed, reason: decision.reason };
  }
}

export const agentProviderReceiptSchema = z.object({
  invocationId: z.string().uuid(),
  providerId: z.string().min(1).max(64),
  providerVersion: z.string().min(1).max(64),
  workflowExecutionId: z.string().min(1).max(200),
  nodeId: z.string().min(1).max(128),
  attempt: z.number().int().positive(),
  subject: z.string().min(1).max(200),
  profile: z.string().min(1).max(100),
  globalCorrelationId: z.string().min(1).max(200),
  traceId: z.string().min(1).max(200),
  inputSha256: hashSchema,
  outputSha256: hashSchema.nullable(),
  requestedAt: z.string().min(1).max(128),
  endedAt: z.string().min(1).max(128),
  terminalState: z.enum(["completed", "failed", "cancelled"]),
  errorCode: z.string().min(1).max(128).nullable(),
  policyReason: z.string().min(1).max(1000),
  recordHash: hashSchema,
  signature: hashSchema,
});

export type AgentProviderReceipt = z.infer<typeof agentProviderReceiptSchema>;

export type AgentProviderInvocationRequest = {
  invocationId?: string;
  auth: AuthInfo | undefined;
  subject: string;
  profile: string;
  workflowExecutionId: string;
  nodeId: string;
  attempt: number;
  providerId: string;
  payload: unknown;
  globalCorrelationId: string;
  traceId: string;
};

export type AgentProviderInvocationOutcome =
  | { ok: true; output: unknown; receipt: AgentProviderReceipt }
  | { ok: false; error: { code: string; message: string }; receipt: AgentProviderReceipt };

type ActiveInvocation = {
  provider: AgentProvider;
  controller: AbortController;
};

export class AgentProviderRuntimeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AgentProviderRuntimeError";
  }
}

export class AgentProviderRuntime {
  private readonly providers = new Map<string, AgentProvider>();
  private readonly active = new Map<string, ActiveInvocation>();

  constructor(
    private readonly policy: AgentProviderPolicyPort,
    private readonly signer: DistributedAuditSigner,
    private readonly now: () => string = () => new Date().toISOString(),
    private readonly invocationIdFactory: () => string = () => randomUUID(),
  ) {}

  register(provider: AgentProvider): void {
    const descriptor = agentProviderDescriptorSchema.parse(provider.descriptor);
    if (this.providers.has(descriptor.id)) {
      throw new AgentProviderRuntimeError(`agent provider already registered: ${descriptor.id}`);
    }
    this.providers.set(descriptor.id, { ...provider, descriptor });
  }

  unregister(providerId: string): boolean {
    if ([...this.active.values()].some((entry) => entry.provider.descriptor.id === providerId)) {
      throw new AgentProviderRuntimeError(`agent provider has active invocations: ${providerId}`);
    }
    return this.providers.delete(providerId);
  }

  list(): AgentProviderDescriptor[] {
    return [...this.providers.values()]
      .map((provider) => provider.descriptor)
      .sort((a, b) => a.id.localeCompare(b.id));
  }

  async invoke(request: AgentProviderInvocationRequest): Promise<AgentProviderInvocationOutcome> {
    const provider = this.providers.get(request.providerId);
    if (!provider) {
      throw new AgentProviderRuntimeError(
        `agent provider is not registered: ${request.providerId}`,
      );
    }
    if (
      !request.subject.trim() ||
      !request.profile.trim() ||
      !request.workflowExecutionId.trim() ||
      !request.nodeId.trim() ||
      !request.globalCorrelationId.trim() ||
      !request.traceId.trim() ||
      !Number.isInteger(request.attempt) ||
      request.attempt < 1
    ) {
      throw new AgentProviderRuntimeError("agent provider invocation identity is invalid");
    }

    const policy = this.policy.authorize({
      auth: request.auth,
      profile: request.profile,
      providerId: provider.descriptor.id,
      requiredScope: provider.descriptor.requiredScope,
      risk: provider.descriptor.risk,
    });
    if (!policy.allowed) {
      throw new AgentProviderRuntimeError(`agent provider policy denied: ${policy.reason}`);
    }

    const invocationId = request.invocationId ?? this.invocationIdFactory();
    if (this.active.has(invocationId)) {
      throw new AgentProviderRuntimeError(
        `agent provider invocation already active: ${invocationId}`,
      );
    }

    const controller = new AbortController();
    this.active.set(invocationId, { provider, controller });
    const requestedAt = this.now();
    const inputSha256 = sha256(canonicalJson(request.payload));

    try {
      const output = await provider.invoke(request.payload, {
        invocationId,
        subject: request.subject,
        profile: request.profile,
        signal: controller.signal,
      });
      if (controller.signal.aborted) {
        return {
          ok: false,
          error: { code: "CANCELLED", message: "agent provider invocation was cancelled" },
          receipt: this.createReceipt({
            request,
            provider,
            invocationId,
            inputSha256,
            outputSha256: null,
            requestedAt,
            terminalState: "cancelled",
            errorCode: "CANCELLED",
            policyReason: policy.reason,
          }),
        };
      }

      return {
        ok: true,
        output,
        receipt: this.createReceipt({
          request,
          provider,
          invocationId,
          inputSha256,
          outputSha256: sha256(canonicalJson(output ?? null)),
          requestedAt,
          terminalState: "completed",
          errorCode: null,
          policyReason: policy.reason,
        }),
      };
    } catch (error) {
      const cancelled = controller.signal.aborted;
      const code = cancelled
        ? "CANCELLED"
        : error instanceof Error && error.name
          ? error.name.slice(0, 128)
          : "AGENT_PROVIDER_FAILED";
      return {
        ok: false,
        error: {
          code,
          message: cancelled
            ? "agent provider invocation was cancelled"
            : error instanceof Error
              ? error.message.slice(0, 1000)
              : "agent provider invocation failed",
        },
        receipt: this.createReceipt({
          request,
          provider,
          invocationId,
          inputSha256,
          outputSha256: null,
          requestedAt,
          terminalState: cancelled ? "cancelled" : "failed",
          errorCode: code,
          policyReason: policy.reason,
        }),
      };
    } finally {
      this.active.delete(invocationId);
    }
  }

  async cancel(invocationId: string): Promise<boolean> {
    const active = this.active.get(invocationId);
    if (!active) return false;
    active.controller.abort();
    if (active.provider.cancel) {
      await active.provider.cancel(invocationId);
    }
    return true;
  }

  verifyReceipt(receipt: AgentProviderReceipt): boolean {
    const parsed = agentProviderReceiptSchema.parse(receipt);
    const { recordHash, signature, ...payload } = parsed;
    return (
      recordHash === sha256(canonicalJson(payload)) && this.signer.verify(recordHash, signature)
    );
  }

  private createReceipt(input: {
    request: AgentProviderInvocationRequest;
    provider: AgentProvider;
    invocationId: string;
    inputSha256: string;
    outputSha256: string | null;
    requestedAt: string;
    terminalState: "completed" | "failed" | "cancelled";
    errorCode: string | null;
    policyReason: string;
  }): AgentProviderReceipt {
    const payload = {
      invocationId: input.invocationId,
      providerId: input.provider.descriptor.id,
      providerVersion: input.provider.descriptor.version,
      workflowExecutionId: input.request.workflowExecutionId,
      nodeId: input.request.nodeId,
      attempt: input.request.attempt,
      subject: input.request.subject,
      profile: input.request.profile,
      globalCorrelationId: input.request.globalCorrelationId,
      traceId: input.request.traceId,
      inputSha256: input.inputSha256,
      outputSha256: input.outputSha256,
      requestedAt: input.requestedAt,
      endedAt: this.now(),
      terminalState: input.terminalState,
      errorCode: input.errorCode,
      policyReason: input.policyReason,
    };
    const recordHash = sha256(canonicalJson(payload));
    return agentProviderReceiptSchema.parse({
      ...payload,
      recordHash,
      signature: this.signer.sign(recordHash),
    });
  }
}
