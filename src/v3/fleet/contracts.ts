import * as z from "zod/v4";

const sha256 = z.string().regex(/^[0-9a-f]{64}$/u);
const deviceId = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u);

export const FLEET_CONTRACT_VERSION = "1.0.0" as const;

export const fleetPlanSchema = z
  .object({
    planId: z.string().uuid(),
    idempotencyKey: z.string().uuid(),
    ownerSubject: z.string().trim().min(1).max(200),
    targetManifestSha256: sha256,
    rollbackManifestSha256: sha256,
    targetDeviceIds: z.array(deviceId).min(2).max(25),
    canaryDeviceId: deviceId,
    createdAtMs: z.number().int().nonnegative(),
  })
  .superRefine((plan, context) => {
    if (plan.targetManifestSha256 === plan.rollbackManifestSha256) {
      context.addIssue({ code: "custom", message: "target and rollback manifest must differ" });
    }
    if (new Set(plan.targetDeviceIds).size !== plan.targetDeviceIds.length) {
      context.addIssue({ code: "custom", message: "each fleet device must be unique" });
    }
    if (!plan.targetDeviceIds.includes(plan.canaryDeviceId)) {
      context.addIssue({
        code: "custom",
        message: "canary must be one of the explicitly selected devices",
      });
    }
  });
export type FleetPlan = z.infer<typeof fleetPlanSchema>;

export const fleetPlanStateSchema = z.enum([
  "planned",
  "preflighting",
  "ready",
  "canary",
  "rolling_out",
  "complete",
  "blocked",
  "rollback_pending",
  "rolled_back",
  "manual_intervention",
]);
export type FleetPlanState = z.infer<typeof fleetPlanStateSchema>;

export type FleetAttestation = {
  deviceId: string;
  previousManifestSha256: string;
  stagedTargetVerified: boolean;
  stagedRollbackVerified: boolean;
  identityVerified: boolean;
  consentSupported: boolean;
  health: "healthy" | "degraded" | "unhealthy" | "unknown";
  evidenceSha256: string;
};

export type FleetSwitchReceipt = {
  deviceId: string;
  previousManifestSha256: string;
  activeManifestSha256: string;
  deviceReceiptHash: string;
  identityVerified: boolean;
};

export type FleetVerifyReceipt = {
  deviceId: string;
  activeManifestSha256: string;
  health: "healthy" | "degraded" | "unhealthy" | "unknown";
  deviceReceiptHash: string;
  identityVerified: boolean;
};

export type FleetOperation =
  "fleet.preflight" | "fleet.activate" | "fleet.verify" | "fleet.rollback";

export interface FleetOwnershipAuthority {
  /** Must validate the authenticated owner; never trust an arbitrary caller-supplied boolean. */
  assertOwner(subject: string, operation: FleetOperation | "fleet.plan"): Promise<void>;
}

export interface FleetDeviceAgentPort {
  /** Must attest to a real P03 enrolled device and exact pinned release manifests. */
  preflight(deviceId: string, target: string, rollback: string): Promise<FleetAttestation>;
  activate(deviceId: string, target: string): Promise<FleetSwitchReceipt>;
  verify(deviceId: string, expected: string): Promise<FleetVerifyReceipt>;
  rollback(deviceId: string, previous: string): Promise<FleetSwitchReceipt>;
}

export interface FleetReceiptVerifierPort {
  /** Independently verify the attested P03 device identity and signed evidence. */
  verifyPreflight(report: FleetAttestation): Promise<boolean>;
  verifySwitch(receipt: FleetSwitchReceipt): Promise<boolean>;
  verifyHealth(receipt: FleetVerifyReceipt): Promise<boolean>;
}

export interface FleetRecipientConsentPort {
  /** Recipient-approved, short-lived, exact-device grant; fail closed if not available. */
  require(deviceId: string, operation: FleetOperation, planId: string): Promise<void>;
}

export interface FleetDeviceReader {
  get(
    deviceId: string,
  ): { deviceId: string; trustState: string; status: string; health: string } | undefined;
}

export type FleetEvent = {
  kind: string;
  planId: string;
  deviceId?: string;
  atMs: number;
  detailsHash?: string;
};

export function assertManifestHash(value: string): void {
  sha256.parse(value);
}
