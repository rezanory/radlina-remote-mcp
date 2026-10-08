import * as z from "zod/v4";

export const DEVICE_CONSENT_VERSION = "1.0.0" as const;

const deviceId = z
  .string()
  .regex(/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u)
  .max(64);
const digest = z.string().regex(/^[0-9a-f]{64}$/u);
const nonBlank = (max: number) => z.string().trim().min(1).max(max);
const noWildcard = nonBlank(300).refine((s) => s !== "*" && !s.includes("**"), {
  message: "unbounded resource scopes are forbidden",
});

const consentRequestBaseSchema = z.object({
  sourceDeviceId: deviceId,
  targetDeviceId: deviceId,
  subject: nonBlank(200),
  capability: z
    .string()
    .regex(/^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/u)
    .max(128),
  resourceKey: noWildcard,
  inputSha256: digest,
  purpose: nonBlank(300),
});

export const consentRequestInputSchema = consentRequestBaseSchema.refine(
  (x) => x.sourceDeviceId !== x.targetDeviceId,
  {
    message: "cross-device consent requires distinct source and target devices",
  },
);

export type ConsentRequestInput = z.infer<typeof consentRequestInputSchema>;
export type ConsentRequest = ConsentRequestInput & {
  requestId: string;
  requestHash: string;
  requestedAtMs: number;
  requestExpiresAtMs: number;
  state: "pending" | "approved" | "denied";
};

export const consentDurationSchema = z.enum([
  "once",
  "15m",
  "1h",
  "8h",
  "24h",
  "custom",
  "permanent",
]);
export type ConsentDuration = z.infer<typeof consentDurationSchema>;

export const consentDecisionSchema = z.object({
  requestId: z.string().uuid(),
  decision: z.enum(["approve", "deny"]),
  duration: consentDurationSchema,
  validUntilMs: z.number().int().positive().nullable(),
  signedAtMs: z.number().int().positive(),
  nonce: z.string().uuid(),
  signatureBase64: nonBlank(1024),
});
export type SignedConsentDecision = z.infer<typeof consentDecisionSchema>;

export type ConsentApprovalMessage = {
  schema: typeof DEVICE_CONSENT_VERSION;
  action: "consent.decision";
  requestId: string;
  requestHash: string;
  sourceDeviceId: string;
  targetDeviceId: string;
  decision: "approve" | "deny";
  duration: ConsentDuration;
  validUntilMs: number | null;
  signedAtMs: number;
  nonce: string;
};

export function buildApprovalMessage(
  request: ConsentRequest,
  decision: Omit<SignedConsentDecision, "signatureBase64">,
): ConsentApprovalMessage {
  return {
    schema: DEVICE_CONSENT_VERSION,
    action: "consent.decision",
    requestId: request.requestId,
    requestHash: request.requestHash,
    sourceDeviceId: request.sourceDeviceId,
    targetDeviceId: request.targetDeviceId,
    decision: decision.decision,
    duration: decision.duration,
    validUntilMs: decision.validUntilMs,
    signedAtMs: decision.signedAtMs,
    nonce: decision.nonce,
  };
}

export type ConsentGrant = ConsentRequestInput & {
  grantId: string;
  requestId: string;
  duration: ConsentDuration;
  approvedAtMs: number;
  validUntilMs: number | null;
  ownerKeyFingerprint: string;
  remainingUses: number | null;
  revokedAtMs: number | null;
};

export const consentDispatchScopeSchema = consentRequestBaseSchema.omit({ purpose: true });
export type ConsentDispatchScope = z.infer<typeof consentDispatchScopeSchema>;

export type VerifiedDevicePrincipal = {
  deviceId: string;
  subject: string;
  attested: boolean;
  /** Must be asserted only by an authenticated local target-device approval UI. */
  localUserApproved?: boolean;
};

export type PinnedConsentDevice = {
  deviceId: string;
  trustState: "pending" | "trusted" | "revoked" | "quarantined";
  approvalPublicKeyPem: string;
  approvalKeyFingerprint: string;
};

export interface ConsentDeviceTrustPort {
  get(deviceId: string): PinnedConsentDevice | undefined;
}

export type ConsentAccessDecision = {
  allowed: boolean;
  reason: string;
  grantId?: string;
};
