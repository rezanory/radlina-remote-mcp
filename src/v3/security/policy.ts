import type { AuthInfo } from "@modelcontextprotocol/server";

import { type PolicyEngine, type Risk } from "../../policy/engine.js";
import type { DeviceDescriptor } from "../device/identity.js";
import type { DeviceTarget } from "../workflow/contracts.js";

export type V3ExecutionAuthorizationRequest = {
  auth: AuthInfo | undefined;
  profile: string;
  tool: string;
  requiredScope: string;
  risk: Risk;
  capability: string;
  target: DeviceTarget;
  device: DeviceDescriptor;
};

export type V3ExecutionPolicyDecision = {
  allowed: boolean;
  reason: string;
  resolvedDeviceId?: string;
};

const NON_DISPATCHABLE = new Set<DeviceDescriptor["status"]>(["offline", "draining", "unknown"]);

export class V3ExecutionPolicyGuard {
  constructor(private readonly basePolicy: PolicyEngine) {}

  authorize(request: V3ExecutionAuthorizationRequest): V3ExecutionPolicyDecision {
    const base = this.basePolicy.decide(
      request.auth,
      request.tool,
      request.requiredScope,
      request.profile,
      request.risk,
    );
    if (!base.allowed)
      return { allowed: false, reason: `user authorization denied: ${base.reason}` };

    if (request.device.trustState !== "trusted") {
      return {
        allowed: false,
        reason: `device trust denied: ${request.device.trustState}`,
      };
    }
    if (NON_DISPATCHABLE.has(request.device.status)) {
      return {
        allowed: false,
        reason: `device status is not dispatchable: ${request.device.status}`,
      };
    }
    if (request.device.health === "unhealthy" || request.device.health === "unknown") {
      return {
        allowed: false,
        reason: `device health is not dispatchable: ${request.device.health}`,
      };
    }
    if (!request.device.capabilities.includes(request.capability)) {
      return {
        allowed: false,
        reason: `device does not advertise capability ${request.capability}`,
      };
    }
    if (
      request.target.deviceId !== undefined &&
      request.target.deviceId !== request.device.deviceId
    ) {
      return { allowed: false, reason: "exact device selector mismatch" };
    }
    if (
      request.target.platform !== undefined &&
      request.target.platform !== request.device.platform
    ) {
      return { allowed: false, reason: "platform selector mismatch" };
    }
    if (
      request.target.capability !== undefined &&
      !request.device.capabilities.includes(request.target.capability)
    ) {
      return { allowed: false, reason: "capability selector mismatch" };
    }
    if (
      request.target.approvedTag !== undefined &&
      !request.device.tags.includes(request.target.approvedTag)
    ) {
      return { allowed: false, reason: "approved tag selector mismatch" };
    }
    if (
      request.target.architecture !== undefined &&
      request.target.architecture !== request.device.architecture
    ) {
      return { allowed: false, reason: "architecture constraint mismatch" };
    }
    return {
      allowed: true,
      reason: "user, target, trust, health and capability policy allow execution",
      resolvedDeviceId: request.device.deviceId,
    };
  }
}
