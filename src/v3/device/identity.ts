import * as z from "zod/v4";

export const DEVICE_IDENTITY_CONTRACT_VERSION = "1.0.0" as const;

export const DEVICE_STATUSES = ["online", "offline", "degraded", "draining", "unknown"] as const;
export const DEVICE_TRUST_STATES = ["pending", "trusted", "revoked", "quarantined"] as const;
export const DEVICE_HEALTH_STATES = ["healthy", "degraded", "unhealthy", "unknown"] as const;
export const DEVICE_PLATFORMS = ["windows", "macos"] as const;
export const DEVICE_ARCHITECTURES = ["x64", "arm64", "unknown"] as const;

const deviceIdSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u);

const capabilityIdSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/u);

const uniqueStrings = (values: string[], context: z.RefinementCtx, label: string): void => {
  if (new Set(values).size !== values.length) {
    context.addIssue({
      code: "custom",
      message: `${label} must be unique`,
    });
  }
};

export const deviceDescriptorSchema = z
  .object({
    deviceId: deviceIdSchema,
    hostname: z.string().min(1).max(255),
    platform: z.enum(DEVICE_PLATFORMS),
    architecture: z.enum(DEVICE_ARCHITECTURES),
    agentVersion: z.string().min(1).max(128),
    status: z.enum(DEVICE_STATUSES),
    lastSeen: z.string().min(1).max(128),
    capabilities: z.array(capabilityIdSchema).max(512),
    tags: z.array(z.string().min(1).max(128)).max(128),
    trustState: z.enum(DEVICE_TRUST_STATES),
    health: z.enum(DEVICE_HEALTH_STATES),
  })
  .superRefine((descriptor, context) => {
    uniqueStrings(descriptor.capabilities, context, "capabilities");
    uniqueStrings(descriptor.tags, context, "tags");
  });

export type DeviceDescriptor = z.infer<typeof deviceDescriptorSchema>;

export const agentIdentityClaimSchema = z.object({
  deviceId: deviceIdSchema,
  agentInstanceId: z.string().uuid(),
  agentVersion: z.string().min(1).max(128),
  publicKeyFingerprint: z.string().regex(/^[0-9a-f]{64}$/u),
  enrolledAt: z.string().min(1).max(128),
});

export type AgentIdentityClaim = z.infer<typeof agentIdentityClaimSchema>;

export class DeviceIdentityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DeviceIdentityError";
  }
}

export function parseDeviceDescriptor(input: unknown): DeviceDescriptor {
  return deviceDescriptorSchema.parse(input);
}

export function parseAgentIdentityClaim(input: unknown): AgentIdentityClaim {
  return agentIdentityClaimSchema.parse(input);
}

export function assertTrustedDevice(descriptor: DeviceDescriptor): void {
  if (descriptor.trustState !== "trusted") {
    throw new DeviceIdentityError(
      `device ${descriptor.deviceId} is not trusted: ${descriptor.trustState}`,
    );
  }
}

export function assertAgentIdentityMatchesDevice(
  descriptor: DeviceDescriptor,
  claim: AgentIdentityClaim,
): void {
  if (descriptor.deviceId !== claim.deviceId) {
    throw new DeviceIdentityError(
      `agent identity device mismatch: expected ${descriptor.deviceId}, got ${claim.deviceId}`,
    );
  }
  if (descriptor.agentVersion !== claim.agentVersion) {
    throw new DeviceIdentityError(
      `agent version mismatch for ${descriptor.deviceId}: expected ${descriptor.agentVersion}, got ${claim.agentVersion}`,
    );
  }
}

export function assertTrustedAgentForDevice(
  descriptor: DeviceDescriptor,
  claim: AgentIdentityClaim,
): void {
  assertTrustedDevice(descriptor);
  assertAgentIdentityMatchesDevice(descriptor, claim);
}
