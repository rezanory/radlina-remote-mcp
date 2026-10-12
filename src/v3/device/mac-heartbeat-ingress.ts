import { execFileSync } from "node:child_process";
import { createHash, verify, createPublicKey } from "node:crypto";
import os from "node:os";

import * as z from "zod/v4";

import { canonicalJson } from "../../utils/json.js";
import {
  SqliteOwnerPinnedEnrollmentAuthority,
  ed25519PublicKeyFingerprint,
  signedAgentHeartbeatSchema,
} from "./owner-pinned-enrollment.js";
import type { SqliteDeviceRegistry } from "./registry.js";

const macHeartbeatEnvelope = z
  .object({
    schema: z.literal("radlina.v3.p03.heartbeat-evidence/v1"),
    heartbeat: signedAgentHeartbeatSchema.strict(),
    deviceSignatureBase64: z.string().min(1).max(200),
  })
  .strict();

export type P08HeartbeatPins = {
  ownerPublicKeyPem: string;
  ownerKeyFingerprint: string;
  macDeviceKeyFingerprint: string;
  macTailnetNodeHash: string;
  observeLiveMacTailnetNodeHash: () => string | undefined;
  clock?: () => number;
};

export function observeLiveMacTailnetPeer(): string | undefined {
  if (process.platform !== "win32" || os.hostname().toLowerCase() !== "laptop-13qineif") {
    return undefined;
  }
  try {
    const stdout = execFileSync(
      "C:\\Program Files\\Tailscale\\tailscale.exe",
      ["status", "--json"],
      { encoding: "utf8", timeout: 12000, maxBuffer: 4 * 1024 * 1024, windowsHide: true },
    );
    const inventory = JSON.parse(stdout) as {
      BackendState?: string;
      CurrentTailnet?: { Name?: string };
      Peer?: Record<string, { ID?: string; OS?: string; Online?: boolean; DNSName?: string }>;
    };
    if (
      inventory.BackendState !== "Running" ||
      inventory.CurrentTailnet?.Name !== "rezanory.github"
    ) {
      return undefined;
    }
    const matches = Object.values(inventory.Peer ?? {}).filter(
      (p) =>
        p.OS === "macOS" &&
        p.Online === true &&
        p.DNSName?.replace(/\.$/u, "").toLowerCase() === "amirs-macbook-pro.taile17c9e.ts.net",
    );
    if (matches.length !== 1 || !matches[0]?.ID) return undefined;
    return createHash("sha256").update(matches[0].ID).digest("hex");
  } catch {
    return undefined;
  }
}

export class V3MacHeartbeatDenied extends Error {
  constructor(message: string) {
    super(message);
    this.name = "V3MacHeartbeatDenied";
  }
}

export class V3MacSignedHeartbeatIngress {
  private readonly authority: SqliteOwnerPinnedEnrollmentAuthority;
  private readonly clock: () => number;
  constructor(
    private readonly registry: SqliteDeviceRegistry,
    private readonly pins: P08HeartbeatPins,
  ) {
    if (
      ed25519PublicKeyFingerprint(pins.ownerPublicKeyPem) !== pins.ownerKeyFingerprint ||
      !/^[0-9a-f]{64}$/u.test(pins.macDeviceKeyFingerprint) ||
      !/^[0-9a-f]{64}$/u.test(pins.macTailnetNodeHash)
    ) {
      throw new V3MacHeartbeatDenied("physical owner/device key pins invalid");
    }
    this.clock = pins.clock ?? (() => Date.now());
    this.authority = new SqliteOwnerPinnedEnrollmentAuthority(registry, {
      approvedOwnerPublicKeyPem: pins.ownerPublicKeyPem,
      approvedDeviceId: "macbook-main",
      approvedHostname: "amirs-MacBook-Pro.local",
      approvedPlatform: "macos",
      approvedTailnetNodeHash: pins.macTailnetNodeHash,
      observeLivePeerNodeHash: pins.observeLiveMacTailnetNodeHash,
      now: this.clock,
    });
  }

  receive(payload: unknown): {
    acceptance: string;
    deviceId: string;
    status: string;
    health: string;
    lastSeen: string;
    capabilities: string[];
    trustState: string;
    receiptHash: string;
    crossDeviceExecutionEnabled: false;
  } {
    const input = macHeartbeatEnvelope.safeParse(payload);
    if (!input.success) throw new V3MacHeartbeatDenied("bounded P03 signed envelope required");
    const { heartbeat, deviceSignatureBase64 } = input.data;
    if (
      heartbeat.deviceId !== "macbook-main" ||
      heartbeat.agentVersion !== "3.0.0-alpha.1" ||
      heartbeat.capabilities.length !== 1 ||
      heartbeat.capabilities[0] !== "device.health" ||
      heartbeat.status !== "online"
    ) {
      throw new V3MacHeartbeatDenied("only enrolled Mac health capability is allowed");
    }
    if (Math.abs(this.clock() - heartbeat.signedAtMs) > 120000) {
      throw new V3MacHeartbeatDenied("signed Mac heartbeat is stale");
    }
    const identity = this.authority.trustedIdentity("macbook-main");
    if (
      !identity ||
      identity.identity.publicKeyFingerprint !== this.pins.macDeviceKeyFingerprint ||
      identity.identity.agentInstanceId !== heartbeat.agentInstanceId ||
      identity.tailnetNodeHash !== this.pins.macTailnetNodeHash
    ) {
      throw new V3MacHeartbeatDenied("physical Mac is not admitted with pinned trusted identity");
    }
    const proof = Buffer.from(deviceSignatureBase64, "base64");
    if (
      proof.length !== 64 ||
      proof.toString("base64") !== deviceSignatureBase64 ||
      !verify(
        null,
        Buffer.from(canonicalJson(heartbeat)),
        createPublicKey(identity.publicKeyPem),
        proof,
      )
    ) {
      throw new V3MacHeartbeatDenied("physical Mac Ed25519 heartbeat signature mismatch");
    }
    // Network observation is independent of the signed payload; a caller cannot
    // claim a live peer identity by submitting its own Tailnet hash.
    if (this.pins.observeLiveMacTailnetNodeHash() !== this.pins.macTailnetNodeHash) {
      throw new V3MacHeartbeatDenied("real Mac peer is absent from Windows Tailscale");
    }
    const updated = this.authority.applySignedHeartbeat(heartbeat, deviceSignatureBase64);
    if (updated.trustState !== "trusted" || !this.authority.auditChain().valid) {
      throw new V3MacHeartbeatDenied("P03 signed registry write or audit validation failed");
    }
    return {
      acceptance: "V3_P08_REAL_MAC_SIGNED_HEARTBEAT_ACCEPTED",
      deviceId: updated.deviceId,
      status: updated.status,
      health: updated.health,
      lastSeen: updated.lastSeen,
      capabilities: updated.capabilities,
      trustState: updated.trustState,
      receiptHash: createHash("sha256")
        .update(
          canonicalJson({
            deviceId: updated.deviceId,
            signedAtMs: heartbeat.signedAtMs,
            nonce: heartbeat.nonce,
          }),
        )
        .digest("hex"),
      crossDeviceExecutionEnabled: false,
    };
  }
}

export function effectiveTrustedDeviceHeartbeat<
  T extends {
    deviceId: string;
    status: string;
    health: string;
    trustState: string;
    lastSeen: string;
  },
>(
  device: T,
  currentTime = Date.now(),
  maxAgeMs = 150_000,
): T & { heartbeatFresh: boolean; heartbeatAgeMs: number | null } {
  const stamp = Date.parse(device.lastSeen);
  const validAge =
    Number.isFinite(stamp) && stamp <= currentTime && currentTime - stamp <= maxAgeMs;
  return {
    ...device,
    // Never present a stale Mac as presently online and healthy.
    ...(device.deviceId === "macbook-main" && !validAge
      ? { status: "unknown", health: "unknown" }
      : {}),
    heartbeatFresh: Boolean(validAge),
    heartbeatAgeMs: Number.isFinite(stamp) ? Math.max(0, currentTime - stamp) : null,
  };
}
