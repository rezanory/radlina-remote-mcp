import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { canonicalJson, sha256 } from "../../../src/utils/json.js";
import { parseDeviceDescriptor } from "../../../src/v3/device/identity.js";
import {
  ed25519PublicKeyFingerprint,
  SqliteOwnerPinnedEnrollmentAuthority,
} from "../../../src/v3/device/owner-pinned-enrollment.js";
import { SqliteDeviceRegistry } from "../../../src/v3/device/registry.js";

describe("P03 explicitly owner-pinned Windows platform", () => {
  it("requires two independent signatures, enforces platform and preserves heartbeat/replay/revocation checks", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "p03-windows-pin-"));
    const registry = new SqliteDeviceRegistry(path.join(root, "registry.sqlite3"));
    try {
      const owner = generateKeyPairSync("ed25519"),
        device = generateKeyPairSync("ed25519"),
        other = generateKeyPairSync("ed25519");
      const pem = device.publicKey.export({ type: "spki", format: "pem" }).toString();
      const ownerPem = owner.publicKey.export({ type: "spki", format: "pem" }).toString();
      let observed: string | undefined = sha256("independent-windows-node");
      const now = Date.now();
      const authority = new SqliteOwnerPinnedEnrollmentAuthority(registry, {
        approvedDeviceId: "windows-main",
        approvedHostname: "LAPTOP-13QINEIF",
        approvedPlatform: "windows",
        approvedOwnerPublicKeyPem: ownerPem,
        approvedTailnetNodeHash: observed,
        observeLivePeerNodeHash: () => observed,
        now: () => now,
      });
      const descriptor = parseDeviceDescriptor({
        deviceId: "windows-main",
        hostname: "LAPTOP-13QINEIF",
        platform: "windows",
        architecture: "x64",
        agentVersion: "3.0.0-alpha.1",
        trustState: "pending",
        status: "unknown",
        health: "unknown",
        lastSeen: new Date(now).toISOString(),
        capabilities: [],
        tags: [],
      });
      const identity = {
        deviceId: descriptor.deviceId,
        agentInstanceId: randomUUID(),
        agentVersion: descriptor.agentVersion,
        publicKeyFingerprint: ed25519PublicKeyFingerprint(pem),
        enrolledAt: new Date(now).toISOString(),
      };
      expect(() => authority.stage({ ...descriptor, platform: "macos" }, identity, pem)).toThrow(
        /identity/u,
      );
      const challenge = authority.stage(descriptor, identity, pem);
      const signWith = (key: typeof device.privateKey, payload: unknown) =>
        sign(null, Buffer.from(canonicalJson(payload)), key).toString("base64");
      expect(challenge.platform).toBe("windows");
      expect(() =>
        authority.admit(
          challenge.challengeId,
          signWith(device.privateKey, challenge),
          signWith(other.privateKey, challenge),
        ),
      ).toThrow(/owner approval/u);
      expect(registry.require("windows-main").trustState).toBe("pending");
      authority.admit(
        challenge.challengeId,
        signWith(device.privateKey, challenge),
        signWith(owner.privateKey, challenge),
      );
      expect(() =>
        authority.admit(
          challenge.challengeId,
          signWith(device.privateKey, challenge),
          signWith(owner.privateKey, challenge),
        ),
      ).toThrow(/pending challenge/u);
      const heartbeat = {
        schema: "radlina.v3.p03.signed-heartbeat/v1" as const,
        deviceId: "windows-main",
        agentInstanceId: identity.agentInstanceId,
        agentVersion: identity.agentVersion,
        signedAtMs: now,
        nonce: randomUUID(),
        status: "online" as const,
        health: "healthy" as const,
        capabilities: ["device.health"],
      };
      expect(() =>
        authority.applySignedHeartbeat(heartbeat, signWith(other.privateKey, heartbeat)),
      ).toThrow(/signature invalid/u);
      expect(() =>
        authority.applySignedHeartbeat(
          { ...heartbeat, signedAtMs: now - 120001 },
          signWith(device.privateKey, heartbeat),
        ),
      ).toThrow(/timestamp/u);
      const signature = signWith(device.privateKey, heartbeat);
      authority.applySignedHeartbeat(heartbeat, signature);
      expect(() => authority.applySignedHeartbeat(heartbeat, signature)).toThrow(/stale/u);
      observed = undefined;
      expect(() =>
        authority.applySignedHeartbeat(
          { ...heartbeat, signedAtMs: now + 1, nonce: randomUUID() },
          signature,
        ),
      ).toThrow(/matching Tailscale/u);
      const revocation = {
        schema: "radlina.v3.p03.owner-revocation/v1" as const,
        deviceId: "windows-main",
        deviceKeyFingerprint: identity.publicKeyFingerprint,
        signedAtMs: now,
        nonce: randomUUID(),
        reason: "test revocation",
      };
      expect(
        authority.revokeByOwner(revocation, signWith(owner.privateKey, revocation)).trustState,
      ).toBe("revoked");
      expect(authority.auditChain().valid).toBe(true);
    } finally {
      registry.close();
      await rm(root, { recursive: true, force: true });
    }
  });
});
