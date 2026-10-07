import * as z from "zod/v4";

import { canonicalJson, sha256 } from "../../utils/json.js";
import { dispatchReceiptSchema } from "../workflow/contracts.js";
import {
  agentIdentityClaimSchema,
  assertTrustedAgentForDevice,
  assertTrustedDevice,
  deviceDescriptorSchema,
  type DeviceDescriptor,
} from "./identity.js";

export const DEVICE_AGENT_PROTOCOL_VERSION = "1.0.0" as const;

export const agentHelloSchema = z.object({
  protocolVersion: z.literal(DEVICE_AGENT_PROTOCOL_VERSION),
  descriptor: deviceDescriptorSchema,
  identity: agentIdentityClaimSchema,
});

export const agentExecuteRequestSchema = z.object({
  requestId: z.string().uuid(),
  workflowExecutionId: z.string().min(1).max(200),
  nodeId: z.string().min(1).max(128),
  attempt: z.number().int().positive(),
  targetDeviceId: z.string().min(1).max(64),
  capability: z.string().min(1).max(128),
  input: z.record(z.string(), z.unknown()),
  inputSha256: z.string().regex(/^[0-9a-f]{64}$/u),
  timeoutMs: z.number().int().min(100).max(86_400_000),
  globalCorrelationId: z.string().min(1).max(200),
  traceId: z.string().min(1).max(200),
});

export type AgentExecuteRequest = z.infer<typeof agentExecuteRequestSchema>;

export const agentCancelRequestSchema = z.object({
  requestId: z.string().uuid(),
  workflowExecutionId: z.string().min(1).max(200),
  nodeId: z.string().min(1).max(128),
  attempt: z.number().int().positive(),
  targetDeviceId: z.string().min(1).max(64),
});

export const agentExecutionReceiptSchema = dispatchReceiptSchema.extend({
  agentInstanceId: z.string().uuid(),
  endedAt: z.string().min(1).max(128),
  errorCode: z.string().min(1).max(128).nullable(),
});

export type AgentExecutionReceipt = z.infer<typeof agentExecutionReceiptSchema>;

export class DeviceAgentProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DeviceAgentProtocolError";
  }
}

export function parseAgentHello(input: unknown) {
  return agentHelloSchema.parse(input);
}

export function assertAgentHello(input: unknown) {
  const hello = parseAgentHello(input);
  assertTrustedAgentForDevice(hello.descriptor, hello.identity);
  return hello;
}

export function parseAgentExecuteRequest(input: unknown): AgentExecuteRequest {
  return agentExecuteRequestSchema.parse(input);
}

export function assertExecuteRequestForDevice(
  request: AgentExecuteRequest,
  descriptor: DeviceDescriptor,
): void {
  assertTrustedDevice(descriptor);
  if (request.targetDeviceId !== descriptor.deviceId) {
    throw new DeviceAgentProtocolError(
      `execution target mismatch: expected ${descriptor.deviceId}, got ${request.targetDeviceId}`,
    );
  }
  if (!descriptor.capabilities.includes(request.capability)) {
    throw new DeviceAgentProtocolError(
      `device ${descriptor.deviceId} does not advertise capability ${request.capability}`,
    );
  }
  const actualInputSha256 = sha256(canonicalJson(request.input));
  if (actualInputSha256 !== request.inputSha256) {
    throw new DeviceAgentProtocolError("execution input integrity check failed");
  }
}

export function parseAgentExecutionReceipt(input: unknown): AgentExecutionReceipt {
  return agentExecutionReceiptSchema.parse(input);
}
