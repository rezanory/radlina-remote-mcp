import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { canonicalJson } from "../../../src/utils/json.js";
import { SqliteDeviceRegistry } from "../../../src/v3/device/registry.js";
import {
  SqliteOwnerPinnedEnrollmentAuthority,
  ed25519PublicKeyFingerprint,
} from "../../../src/v3/device/owner-pinned-enrollment.js";
import { startV3ReadOnlyOAuthGateway } from "../../../src/v3/gateway/oauth-readonly.js";
import { testConfig } from "../../helpers/config.js";

async function port(): Promise<number> {
  const s = createServer();
  s.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    s.once("listening", resolve);
    s.once("error", reject);
  });
  const a = s.address();
  if (!a || typeof a === "string") throw Error("expected local port");
  await new Promise<void>((resolve) => s.close(() => resolve()));
  return a.port;
}

describe("V3 signed Mac heartbeat MCP ingress", () => {
  it("accepts cryptographic P03 heartbeat and exposes staleness honestly", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-p08-http-"));
    const stateDirectory = path.join(root, "v3-state");
    const registry = new SqliteDeviceRegistry(path.join(stateDirectory, "v3-devices.sqlite3"));
    const owner = generateKeyPairSync("ed25519");
    const mac = generateKeyPairSync("ed25519");
    const ownerPem = owner.publicKey.export({ type: "spki", format: "pem" }).toString();
    const macPem = mac.publicKey.export({ type: "spki", format: "pem" }).toString();
    const macKey = ed25519PublicKeyFingerprint(macPem);
    const networkHash = createHash("sha256").update("fixture-tailnet-node").digest("hex");
    const encoded = (m: unknown) => Buffer.from(canonicalJson(m));
    const instanceId = randomUUID();
    const descriptor = {
      deviceId: "macbook-main",
      hostname: "amirs-MacBook-Pro.local",
      platform: "macos" as const,
      architecture: "x64" as const,
      agentVersion: "3.0.0-alpha.1",
      status: "unknown" as const,
      health: "unknown" as const,
      trustState: "pending" as const,
      lastSeen: new Date(Date.now() - 400000).toISOString(),
      tags: [],
      capabilities: [],
    };
    try {
      registry.register(descriptor);
      const authority = new SqliteOwnerPinnedEnrollmentAuthority(registry, {
        approvedOwnerPublicKeyPem: ownerPem,
        approvedDeviceId: "macbook-main",
        approvedHostname: "amirs-MacBook-Pro.local",
        approvedPlatform: "macos",
        approvedTailnetNodeHash: networkHash,
        observeLivePeerNodeHash: () => networkHash,
      });
      const ch = authority.stage(
        descriptor,
        {
          deviceId: "macbook-main",
          agentVersion: "3.0.0-alpha.1",
          agentInstanceId: instanceId,
          publicKeyFingerprint: macKey,
          enrolledAt: new Date().toISOString(),
        },
        macPem,
      );
      authority.admit(
        ch.challengeId,
        sign(null, encoded(ch), mac.privateKey).toString("base64"),
        sign(null, encoded(ch), owner.privateKey).toString("base64"),
      );
    } finally {
      registry.close();
    }
    const p = await port();
    const gateway = await startV3ReadOnlyOAuthGateway({
      baseConfig: testConfig(root),
      stateDirectory,
      publicUrl: "http://127.0.0.1:" + p,
      port: p,
      macHeartbeatPins: {
        ownerPublicKeyPem: ownerPem,
        ownerKeyFingerprint: ed25519PublicKeyFingerprint(ownerPem),
        macDeviceKeyFingerprint: macKey,
        macTailnetNodeHash: networkHash,
        observeLiveMacTailnetNodeHash: () => networkHash,
      },
    });
    try {
      const u = "http://127.0.0.1:" + p + "/v3/agent/heartbeat";
      const anonymous = await fetch(u, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ hello: "unauthorized" }),
      });
      expect(anonymous.status).toBe(403);
      const hb = {
        schema: "radlina.v3.p03.signed-heartbeat/v1",
        deviceId: "macbook-main",
        agentInstanceId: instanceId,
        agentVersion: "3.0.0-alpha.1",
        signedAtMs: Date.now(),
        nonce: randomUUID(),
        status: "online",
        health: "degraded",
        capabilities: ["device.health"],
      };
      const payload = {
        schema: "radlina.v3.p03.heartbeat-evidence/v1",
        heartbeat: hb,
        deviceSignatureBase64: sign(null, encoded(hb), mac.privateKey).toString("base64"),
      };
      await new Promise((resolve) => setTimeout(resolve, 1600)); // bypass bounded unauthenticated-rate throttle
      const ok = await fetch(u, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      expect(ok.status).toBe(200);
      expect(await ok.json()).toMatchObject({
        acceptance: "V3_P08_REAL_MAC_SIGNED_HEARTBEAT_ACCEPTED",
        deviceId: "macbook-main",
        trustState: "trusted",
        crossDeviceExecutionEnabled: false,
      });
      await new Promise((resolve) => setTimeout(resolve, 1600));
      const replay = await fetch(u, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      expect(replay.status).toBe(403);
    } finally {
      await gateway.shutdown();
      await rm(root, { recursive: true, force: true });
    }
  }, 45000);
});
