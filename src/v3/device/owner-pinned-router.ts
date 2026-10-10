import {
  ed25519PublicKeyFingerprint,
  SqliteOwnerPinnedEnrollmentAuthority,
} from "./owner-pinned-enrollment.js";
import { DeviceRouter, DeviceRoutingError, type DeviceRoute } from "./router.js";
import type { SqliteDeviceRegistry } from "./registry.js";

export const P03_SIGNED_ROUTE_BINDING_VERSION = "1.0.0" as const;

/**
 * Exact physical-device P06 guard.
 * It does NOT implement a transport or confer network authority; it only
 * permits selecting a real device when signed, fresh, exact identity exists.
 * The composition layer must STILL enforce S02E recipient approval and S03.
 */
export class OwnerPinnedMacRouteGuard {
  constructor(
    private readonly registry: SqliteDeviceRegistry,
    private readonly enrollment: SqliteOwnerPinnedEnrollmentAuthority,
    private readonly observeLiveMacPeerNodeHash: () => string | undefined,
    private readonly now: () => number = () => Date.now(),
    private readonly maxHeartbeatAgeMs = 120_000,
  ) {
    if (
      !Number.isInteger(maxHeartbeatAgeMs) ||
      maxHeartbeatAgeMs < 5_000 ||
      maxHeartbeatAgeMs > 120_000
    ) {
      throw new DeviceRoutingError("signed heartbeat maximum age must be 5s..120s");
    }
  }

  exact(deviceId: string, capability: string): DeviceRoute {
    const stored = this.enrollment.trustedIdentity(deviceId);
    if (!stored || stored.identity.deviceId !== deviceId) {
      throw new DeviceRoutingError("exact Mac P03 signed trust identity is missing");
    }
    if (ed25519PublicKeyFingerprint(stored.publicKeyPem) !== stored.identity.publicKeyFingerprint) {
      throw new DeviceRoutingError("pinned Mac signing key changed");
    }
    if (!stored.tailnetNodeHash || this.observeLiveMacPeerNodeHash() !== stored.tailnetNodeHash) {
      throw new DeviceRoutingError("exact Mac Tailscale peer identity is unavailable");
    }
    const descriptor = this.registry.get(deviceId);
    const signedAtMs = this.enrollment.latestSignedHeartbeatMs(deviceId);
    if (
      !descriptor ||
      signedAtMs === null ||
      descriptor.lastSeen !== new Date(signedAtMs).toISOString() ||
      descriptor.status !== "online" ||
      descriptor.health !== "healthy"
    ) {
      throw new DeviceRoutingError("exact Mac has no verified live signed heartbeat");
    }
    const age = this.now() - signedAtMs;
    if (!Number.isFinite(age) || age < 0 || age > this.maxHeartbeatAgeMs) {
      throw new DeviceRoutingError("exact Mac signed heartbeat is stale or from the future");
    }
    return new DeviceRouter(this.registry).route({ deviceId }, capability);
  }
}
