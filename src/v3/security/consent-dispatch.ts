import { randomUUID } from "node:crypto";

import { canonicalJson, sha256 } from "../../utils/json.js";
import type {
  ExecutionDispatchPort,
  WorkflowDispatchInput,
  WorkflowDispatchResult,
} from "../workflow/runtime.js";
import type { VerifiedDevicePrincipal, ConsentRequestInput } from "./consent-contracts.js";
import { SqliteCrossDeviceConsentAuthority } from "./device-consent.js";

export interface VerifiedWorkflowOriginPort {
  /**
   * Resolve the previously authenticated submitting device from immutable,
   * server-side workflow ownership. Never read a caller-provided source ID here.
   */
  resolve(input: {
    workflowExecutionId: string;
    subject: string;
  }): VerifiedDevicePrincipal | undefined;
}

export class ConsentDispatchDenied extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConsentDispatchDenied";
  }
}

/** Produces the SAME exact-operation scope at prompt time and dispatch time. */
export function consentRequestForDispatch(
  input: WorkflowDispatchInput,
  origin: VerifiedDevicePrincipal,
  purpose: string,
): ConsentRequestInput {
  const target = input.node.target.deviceId;
  if (!target) {
    throw new ConsentDispatchDenied(
      "dynamic device selectors require a separately approved verified target binding",
    );
  }
  const inputSha256 = sha256(canonicalJson(input.node.input));
  return {
    sourceDeviceId: origin.deviceId,
    targetDeviceId: target,
    subject: input.subject,
    capability: input.node.capability,
    resourceKey: `exact-input:${inputSha256}`,
    inputSha256,
    purpose,
  };
}

/**
 * Mandatory application-layer adapter for remote V3 workflow execution.
 * This does not enable raw TCP peer traffic or grant network-layer access.
 * The concrete V3 composition must enforce this AND target-agent revalidation.
 */
export class ConsentGatedExecutionDispatchPort implements ExecutionDispatchPort {
  constructor(
    private readonly underlying: ExecutionDispatchPort,
    private readonly consent: SqliteCrossDeviceConsentAuthority,
    private readonly origins: VerifiedWorkflowOriginPort,
    private readonly attemptId: () => string = () => randomUUID(),
  ) {}

  async execute(input: WorkflowDispatchInput): Promise<WorkflowDispatchResult> {
    const origin = this.origins.resolve({
      workflowExecutionId: input.workflowExecutionId,
      subject: input.subject,
    });
    if (!origin?.attested || origin.subject !== input.subject) {
      throw new ConsentDispatchDenied("verified workflow origin device is required");
    }
    const exact = consentRequestForDispatch(input, origin, "exact device operation");
    const scope = {
      sourceDeviceId: exact.sourceDeviceId,
      targetDeviceId: exact.targetDeviceId,
      subject: exact.subject,
      capability: exact.capability,
      resourceKey: exact.resourceKey,
      inputSha256: exact.inputSha256,
    };
    const decision = this.consent.consume(scope, origin, this.attemptId());
    if (!decision.allowed) {
      throw new ConsentDispatchDenied(decision.reason);
    }
    const result = await this.underlying.execute(input);
    if (result.receipt.resolvedDeviceId !== exact.targetDeviceId) {
      throw new ConsentDispatchDenied("executing device does not match consented target");
    }
    return result;
  }

  /** Cancellation must remain available after expiry/revocation to stop work. */
  async cancel(input: {
    workflowExecutionId: string;
    nodeId: string;
    attempt: number;
  }): Promise<void> {
    if (!this.underlying.cancel) {
      throw new ConsentDispatchDenied("device dispatch cancellation is unavailable");
    }
    await this.underlying.cancel(input);
  }
}
