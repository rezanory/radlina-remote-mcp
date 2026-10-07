import type { AuthInfo } from "@modelcontextprotocol/server";

import type { CapabilityRegistry } from "../../components/registry.js";
import { canonicalJson, sha256 } from "../../utils/json.js";
import {
  createDistributedAuditRecord,
  type DistributedAuditSigner,
  type SignedDistributedAuditRecord,
} from "../audit/distributed.js";
import {
  agentExecutionReceiptSchema,
  assertExecuteRequestForDevice,
  parseAgentExecuteRequest,
  type AgentExecutionReceipt,
} from "../device/agent-protocol.js";
import type { DeviceDescriptor } from "../device/identity.js";
import { V3ExecutionPolicyGuard } from "../security/policy.js";

export type LocalExecutionAuditInput = {
  subject: string;
  profile: string;
  workflowExecutionId: string;
  nodeId: string;
  attempt: number;
  deviceId: string;
  capability: string;
  inputSha256: string;
  outputSha256: string | null;
  terminalState: "completed" | "failed" | "cancelled" | "interrupted";
  errorCode: string | null;
};

export interface LocalExecutionAuditPort {
  record(input: LocalExecutionAuditInput): Promise<string>;
}

export type CapabilityRuntimeContext = {
  auth: AuthInfo | undefined;
  subject: string;
  profile: string;
  device: DeviceDescriptor;
  agentInstanceId: string;
  isCancelled: () => boolean;
};

export type CapabilityRuntimeOutcome =
  | {
      ok: true;
      result: unknown;
      receipt: AgentExecutionReceipt;
      audit: SignedDistributedAuditRecord;
    }
  | {
      ok: false;
      error: { code: string; message: string };
      receipt: AgentExecutionReceipt;
      audit: SignedDistributedAuditRecord;
    };

export class CapabilityRuntimePolicyDenied extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CapabilityRuntimePolicyDenied";
  }
}

export class V3CapabilityRuntime {
  constructor(
    private readonly capabilities: CapabilityRegistry,
    private readonly policy: V3ExecutionPolicyGuard,
    private readonly localAudit: LocalExecutionAuditPort,
    private readonly distributedSigner: DistributedAuditSigner,
    private readonly now: () => string = () => new Date().toISOString(),
  ) {}

  async execute(
    rawRequest: unknown,
    context: CapabilityRuntimeContext,
  ): Promise<CapabilityRuntimeOutcome> {
    const request = parseAgentExecuteRequest(rawRequest);
    assertExecuteRequestForDevice(request, context.device);
    const provider = this.capabilities.resolve(request.capability);
    const decision = this.policy.authorize({
      auth: context.auth,
      profile: context.profile,
      tool: "capability.execute",
      requiredScope: provider.requiredScope,
      risk: provider.risk,
      capability: provider.id,
      target: { deviceId: request.targetDeviceId },
      device: context.device,
    });
    if (!decision.allowed) throw new CapabilityRuntimePolicyDenied(decision.reason);

    const startedAt = this.now();
    try {
      const result = await provider.execute(
        {
          subject: context.subject,
          profile: context.profile,
          auth: context.auth,
          isCancelled: context.isCancelled,
        },
        request.input,
      );
      const outputSha256 = sha256(canonicalJson(result));
      const endedAt = this.now();
      const localAuditReceiptHash = await this.localAudit.record({
        subject: context.subject,
        profile: context.profile,
        workflowExecutionId: request.workflowExecutionId,
        nodeId: request.nodeId,
        attempt: request.attempt,
        deviceId: context.device.deviceId,
        capability: request.capability,
        inputSha256: request.inputSha256,
        outputSha256,
        terminalState: "completed",
        errorCode: null,
      });
      const receipt = agentExecutionReceiptSchema.parse({
        workflowExecutionId: request.workflowExecutionId,
        nodeId: request.nodeId,
        attempt: request.attempt,
        resolvedDeviceId: context.device.deviceId,
        capability: request.capability,
        inputSha256: request.inputSha256,
        startedAt,
        terminalState: "completed",
        outputSha256,
        localAuditReceiptHash,
        globalCorrelationId: request.globalCorrelationId,
        traceId: request.traceId,
        agentInstanceId: context.agentInstanceId,
        endedAt,
        errorCode: null,
      });
      return {
        ok: true,
        result,
        receipt,
        audit: createDistributedAuditRecord(
          {
            globalCorrelationId: request.globalCorrelationId,
            traceId: request.traceId,
            subject: context.subject,
            profile: context.profile,
            workflowExecutionId: request.workflowExecutionId,
            nodeId: request.nodeId,
            attempt: request.attempt,
            resolvedDeviceId: context.device.deviceId,
            capability: request.capability,
            policyDecision: {
              allowed: true,
              reason: decision.reason,
              requiredScope: provider.requiredScope,
              risk: provider.risk,
            },
            inputSha256: request.inputSha256,
            outputSha256,
            localAuditReceiptHash,
            requestedAt: startedAt,
            endedAt,
            terminalState: "completed",
          },
          this.distributedSigner,
        ),
      };
    } catch (error) {
      const endedAt = this.now();
      const code =
        error instanceof Error && error.name
          ? error.name.slice(0, 128)
          : "CAPABILITY_EXECUTION_FAILED";
      const message =
        error instanceof Error ? error.message.slice(0, 1000) : "unknown capability failure";
      const localAuditReceiptHash = await this.localAudit.record({
        subject: context.subject,
        profile: context.profile,
        workflowExecutionId: request.workflowExecutionId,
        nodeId: request.nodeId,
        attempt: request.attempt,
        deviceId: context.device.deviceId,
        capability: request.capability,
        inputSha256: request.inputSha256,
        outputSha256: null,
        terminalState: context.isCancelled() ? "cancelled" : "failed",
        errorCode: code,
      });
      const terminalState = context.isCancelled() ? "cancelled" : "failed";
      const receipt = agentExecutionReceiptSchema.parse({
        workflowExecutionId: request.workflowExecutionId,
        nodeId: request.nodeId,
        attempt: request.attempt,
        resolvedDeviceId: context.device.deviceId,
        capability: request.capability,
        inputSha256: request.inputSha256,
        startedAt,
        terminalState,
        outputSha256: null,
        localAuditReceiptHash,
        globalCorrelationId: request.globalCorrelationId,
        traceId: request.traceId,
        agentInstanceId: context.agentInstanceId,
        endedAt,
        errorCode: code,
      });
      return {
        ok: false,
        error: { code, message },
        receipt,
        audit: createDistributedAuditRecord(
          {
            globalCorrelationId: request.globalCorrelationId,
            traceId: request.traceId,
            subject: context.subject,
            profile: context.profile,
            workflowExecutionId: request.workflowExecutionId,
            nodeId: request.nodeId,
            attempt: request.attempt,
            resolvedDeviceId: context.device.deviceId,
            capability: request.capability,
            policyDecision: {
              allowed: true,
              reason: decision.reason,
              requiredScope: provider.requiredScope,
              risk: provider.risk,
            },
            inputSha256: request.inputSha256,
            outputSha256: null,
            localAuditReceiptHash,
            requestedAt: startedAt,
            endedAt,
            terminalState,
          },
          this.distributedSigner,
        ),
      };
    }
  }
}
