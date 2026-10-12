import { generateKeyPairSync, randomUUID, sign, createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";
import { canonicalJson } from "../../../src/utils/json.js";
import {
  ed25519PublicKeyFingerprint,
  SqliteOwnerPinnedEnrollmentAuthority,
} from "../../../src/v3/device/owner-pinned-enrollment.js";
import {
  V3MacSignedHeartbeatIngress,
  effectiveTrustedDeviceHeartbeat,
} from "../../../src/v3/device/mac-heartbeat-ingress.js";
import { SqliteDeviceRegistry } from "../../../src/v3/device/registry.js";

describe("P08 real-key-format signed heartbeat ingress", () => {
  it("accepts exact Ed25519 trusted Mac proof and rejects stale, replay, modified and offline messages", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-p08-hb-"));
    const db = new SqliteDeviceRegistry(path.join(root, "registry.sqlite3"));
    const owner = generateKeyPairSync("ed25519");
    const mac = generateKeyPairSync("ed25519");
    const ownerPem = owner.publicKey.export({ type: "spki", format: "pem" }).toString();
    const macPem = mac.publicKey.export({ type: "spki", format: "pem" }).toString();
    const ownerFingerprint = ed25519PublicKeyFingerprint(ownerPem);
    const macFingerprint = ed25519PublicKeyFingerprint(macPem);
    const networkHash = createHash("sha256").update("test-only-tailnet-peer").digest("hex");
    let liveNode: string | undefined = networkHash;
    let now = Date.now();
    const agentInstanceId = randomUUID();
    const descriptor = {
      deviceId: "macbook-main",
      hostname: "amirs-MacBook-Pro.local",
      platform: "macos" as const,
      architecture: "x64" as const,
      agentVersion: "3.0.0-alpha.1",
      status: "unknown" as const,
      health: "unknown" as const,
      trustState: "pending" as const,
      lastSeen: new Date(now).toISOString(),
      capabilities: [],
      tags: [],
    };
    try {
      db.register(descriptor);
      const auth = new SqliteOwnerPinnedEnrollmentAuthority(db, {
        approvedOwnerPublicKeyPem: ownerPem,
        approvedDeviceId: "macbook-main",
        approvedHostname: "amirs-MacBook-Pro.local",
        approvedPlatform: "macos",
        approvedTailnetNodeHash: networkHash,
        observeLivePeerNodeHash: () => liveNode,
        now: () => now,
      });
      const challenge = auth.stage(
        descriptor,
        {
          deviceId: descriptor.deviceId,
          agentInstanceId,
          agentVersion: descriptor.agentVersion,
          publicKeyFingerprint: macFingerprint,
          enrolledAt: new Date(now).toISOString(),
        },
        macPem,
      );
      const signPayload = (message: unknown) => Buffer.from(canonicalJson(message));
      const macSig = sign(null, signPayload(challenge), mac.privateKey).toString("base64");
      const ownerSig = sign(null, signPayload(challenge), owner.privateKey).toString("base64");
      expect(auth.admit(challenge.challengeId, macSig, ownerSig).trustState).toBe("trusted");

      const inbound = new V3MacSignedHeartbeatIngress(db, {
        ownerPublicKeyPem: ownerPem,
        ownerKeyFingerprint: ownerFingerprint,
        macDeviceKeyFingerprint: macFingerprint,
        macTailnetNodeHash: networkHash,
        observeLiveMacTailnetNodeHash: () => liveNode,
        clock: () => now,
      });
      const hb = {
        schema: "radlina.v3.p03.signed-heartbeat/v1",
        deviceId: "macbook-main",
        agentInstanceId,
        signedAtMs: now + 5,
        nonce: randomUUID(),
        agentVersion: "3.0.0-alpha.1",
        status: "online" as const,
        health: "degraded" as const,
        capabilities: ["device.health"],
      };
      const envelope = {
        schema: "radlina.v3.p03.heartbeat-evidence/v1",
        heartbeat: hb,
        deviceSignatureBase64: sign(null, signPayload(hb), mac.privateKey).toString("base64"),
      };
      now += 10;
      expect(inbound.receive(envelope)).toMatchObject({
        acceptance: "V3_P08_REAL_MAC_SIGNED_HEARTBEAT_ACCEPTED",
        trustState: "trusted",
        deviceId: "macbook-main",
        health: "degraded",
        crossDeviceExecutionEnabled: false,
      });
      expect(db.require("macbook-main").status).toBe("online");
      expect(() => inbound.receive(envelope)).toThrow();
      expect(() => inbound.receive({ ...envelope, deviceSignatureBase64: ownerSig })).toThrow();
      expect(() =>
        inbound.receive({
          ...envelope,
          heartbeat: { ...hb, capabilities: ["device.health", "filesystem.write"] },
        }),
      ).toThrow();
      liveNode = undefined;
      const newer = { ...hb, nonce: randomUUID(), signedAtMs: now + 1 };
      expect(() =>
        inbound.receive({
          ...envelope,
          heartbeat: newer,
          deviceSignatureBase64: sign(null, signPayload(newer), mac.privateKey).toString("base64"),
        }),
      ).toThrow(/absent/u);
      now += 150001;
      const stale = effectiveTrustedDeviceHeartbeat(db.require("macbook-main"), now);
      expect(stale.heartbeatFresh).toBe(false);
      expect(stale.status).toBe("unknown");
      expect(stale.health).toBe("unknown");
      expect(db.require("macbook-main").trustState).toBe("trusted");
      expect(auth.auditChain().valid).toBe(true);
    } finally {
      db.close();
      await rm(root, { recursive: true, force: true });
    }
  }, 30000);
});
