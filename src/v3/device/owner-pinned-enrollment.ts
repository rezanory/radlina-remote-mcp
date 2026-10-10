import { createPublicKey, randomUUID, verify, type KeyObject } from "node:crypto";

import * as z from "zod/v4";

import { canonicalJson, sha256 } from "../../utils/json.js";
import {
  agentIdentityClaimSchema,
  deviceDescriptorSchema,
  type AgentIdentityClaim,
  type DeviceDescriptor,
} from "./identity.js";
import { DeviceRegistryConflict, SqliteDeviceRegistry } from "./registry.js";

const HASH = z.string().regex(/^[0-9a-f]{64}$/u);
const UUID = z.string().uuid();
const MAX_AGE_MS = 10 * 60_000;
const MAX_HEARTBEAT_SKEW_MS = 120_000;
export const P03_OWNER_PINNED_ENROLLMENT_VERSION = "1.0.0" as const;

export type P03EnrollmentChallenge = {
  schema: typeof P03_OWNER_PINNED_ENROLLMENT_VERSION;
  purpose: "p03.owner-approved-enrollment";
  challengeId: string;
  deviceId: string;
  hostname: string;
  platform: "macos";
  architecture: DeviceDescriptor["architecture"];
  agentVersion: string;
  agentInstanceId: string;
  deviceKeyFingerprint: string;
  expectedTailnetNodeHash: string;
  issuedAtMs: number;
  expiresAtMs: number;
};

export const signedAgentHeartbeatSchema = z.object({
  schema: z.literal("radlina.v3.p03.signed-heartbeat/v1"),
  deviceId: z.string().min(1).max(64),
  agentInstanceId: UUID,
  signedAtMs: z.number().int().positive(),
  nonce: UUID,
  agentVersion: z.string().min(1).max(128),
  status: z.enum(["online", "offline", "degraded"]),
  health: z.enum(["healthy", "degraded", "unhealthy", "unknown"]),
  capabilities: z.array(z.string().regex(/^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/u)).max(512),
});
export type SignedAgentHeartbeat = z.infer<typeof signedAgentHeartbeatSchema>;

export const ownerRevocationSchema = z.object({
  schema: z.literal("radlina.v3.p03.owner-revocation/v1"),
  deviceId: z.string().min(1).max(64),
  deviceKeyFingerprint: HASH,
  signedAtMs: z.number().int().positive(),
  nonce: UUID,
  reason: z.string().trim().min(1).max(300),
});
export type OwnerRevocation = z.infer<typeof ownerRevocationSchema>;

export interface PinnedEnrollmentAuthorityConfig {
  /** Pinned independently of any user-controlled request or Mac-supplied data. */
  approvedOwnerPublicKeyPem: string;
  approvedDeviceId: string;
  approvedHostname: string;
  approvedTailnetNodeHash: string;
  /** Must independently read Windows' live Tailscale peer inventory. */
  observeLivePeerNodeHash(): string | undefined;
  now?: () => number;
  uuid?: () => string;
}

export class P03EnrollmentDenied extends Error {
  constructor(message: string) {
    super(message);
    this.name = "P03EnrollmentDenied";
  }
}

function ed25519Key(publicKeyPem: string): KeyObject {
  if (publicKeyPem.length > 4_096 || !publicKeyPem.includes("BEGIN PUBLIC KEY")) {
    throw new P03EnrollmentDenied("valid public key PEM is required");
  }
  try {
    const key = createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== "ed25519") throw new Error("key type mismatch");
    return key;
  } catch {
    throw new P03EnrollmentDenied("Ed25519 public key is required");
  }
}

export function ed25519PublicKeyFingerprint(publicKeyPem: string): string {
  return sha256(ed25519Key(publicKeyPem).export({ type: "spki", format: "der" }));
}

function verifyProof(key: KeyObject, message: string, signatureBase64: string): boolean {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(signatureBase64)) {
    return false;
  }
  const signature = Buffer.from(signatureBase64, "base64");
  if (signature.length !== 64 || signature.toString("base64") !== signatureBase64) return false;
  try {
    return verify(null, Buffer.from(message, "utf8"), key, signature);
  } catch {
    return false;
  }
}

type ChallengeRow = {
  payload_json: string;
  device_public_key_pem: string;
  state: string;
};
type StoredIdentity = {
  identity_json: string;
  device_public_key_pem: string;
  tailscale_node_hash: string;
};

export class SqliteOwnerPinnedEnrollmentAuthority {
  private readonly approvedOwnerKey: KeyObject;
  private readonly now: () => number;
  private readonly uuid: () => string;
  private readonly approvedTailnetNodeHash: string;

  constructor(
    private readonly registry: SqliteDeviceRegistry,
    private readonly config: PinnedEnrollmentAuthorityConfig,
  ) {
    this.approvedOwnerKey = ed25519Key(config.approvedOwnerPublicKeyPem);
    this.approvedTailnetNodeHash = HASH.parse(config.approvedTailnetNodeHash);
    if (!config.approvedDeviceId || !config.approvedHostname.trim()) {
      throw new P03EnrollmentDenied("owner-pinned device identity is required");
    }
    this.now = config.now ?? (() => Date.now());
    this.uuid = config.uuid ?? (() => randomUUID());
    this.registry.db.exec(`
      CREATE TABLE IF NOT EXISTS v3_p03_enrollment_challenges (
        challenge_id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL REFERENCES v3_devices(device_id),
        payload_json TEXT NOT NULL,
        device_public_key_pem TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('pending','admitted','expired'))
      );
      CREATE TABLE IF NOT EXISTS v3_p03_trusted_identities (
        device_id TEXT PRIMARY KEY REFERENCES v3_devices(device_id),
        identity_json TEXT NOT NULL,
        device_public_key_pem TEXT NOT NULL,
        tailscale_node_hash TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS v3_p03_heartbeat_nonces (
        nonce TEXT PRIMARY KEY,
        device_id TEXT NOT NULL REFERENCES v3_devices(device_id),
        signed_at_ms INTEGER NOT NULL,
        accepted_at_ms INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS v3_p03_revocation_nonces (
        nonce TEXT PRIMARY KEY,
        device_id TEXT NOT NULL REFERENCES v3_devices(device_id),
        accepted_at_ms INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS v3_p03_enrollment_audit (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        event_json TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL
      );
    `);
  }

  /**
   * Pending registration only. The candidate never supplies the pinned owner key,
   * owner approval, observed network identity or registry trust transition.
   */
  stage(
    rawDescriptor: DeviceDescriptor,
    rawIdentity: AgentIdentityClaim,
    publicKeyPem: string,
  ): P03EnrollmentChallenge {
    const candidate = deviceDescriptorSchema.parse(rawDescriptor);
    const identity = agentIdentityClaimSchema.parse(rawIdentity);
    if (
      candidate.deviceId !== this.config.approvedDeviceId ||
      candidate.hostname !== this.config.approvedHostname ||
      candidate.platform !== "macos" ||
      identity.deviceId !== candidate.deviceId ||
      identity.agentVersion !== candidate.agentVersion ||
      candidate.trustState !== "pending"
    ) {
      throw new P03EnrollmentDenied("Mac identity does not match owner-pinned enrollment");
    }
    if (
      identity.publicKeyFingerprint ===
      sha256(this.approvedOwnerKey.export({ type: "spki", format: "der" }))
    ) {
      throw new P03EnrollmentDenied("owner and device signing keys must be independent");
    }
    if (identity.publicKeyFingerprint !== ed25519PublicKeyFingerprint(publicKeyPem)) {
      throw new P03EnrollmentDenied("agent public key fingerprint mismatch");
    }
    if (
      this.registry.get(candidate.deviceId)?.trustState !== undefined &&
      this.registry.get(candidate.deviceId)?.trustState !== "pending"
    ) {
      throw new P03EnrollmentDenied("trusted or revoked device cannot be silently re-enrolled");
    }

    const issuedAtMs = this.now();
    const challenge = {
      schema: P03_OWNER_PINNED_ENROLLMENT_VERSION,
      purpose: "p03.owner-approved-enrollment",
      challengeId: UUID.parse(this.uuid()),
      deviceId: candidate.deviceId,
      hostname: candidate.hostname,
      platform: candidate.platform,
      architecture: candidate.architecture,
      agentVersion: identity.agentVersion,
      agentInstanceId: identity.agentInstanceId,
      deviceKeyFingerprint: identity.publicKeyFingerprint,
      expectedTailnetNodeHash: this.approvedTailnetNodeHash,
      issuedAtMs,
      expiresAtMs: issuedAtMs + MAX_AGE_MS,
    } satisfies P03EnrollmentChallenge;

    // The enrolled descriptor is intentionally non-routable until an
    // independently authenticated heartbeat is implemented.
    this.registry.db.exec("BEGIN IMMEDIATE");
    try {
      const existing = this.registry.get(candidate.deviceId);
      if (!existing) {
        this.registry.register({
          ...candidate,
          capabilities: [],
          tags: [],
          status: "unknown",
          health: "unknown",
        });
      } else if (
        existing.hostname !== candidate.hostname ||
        existing.platform !== candidate.platform ||
        existing.architecture !== candidate.architecture
      ) {
        throw new P03EnrollmentDenied("existing pending device has conflicting identity");
      }
      const active = this.registry.db
        .prepare(
          "SELECT challenge_id,payload_json FROM v3_p03_enrollment_challenges WHERE device_id=? AND state='pending'",
        )
        .get(candidate.deviceId) as { challenge_id: string; payload_json: string } | undefined;
      if (active) {
        const previous = JSON.parse(active.payload_json) as P03EnrollmentChallenge;
        if (issuedAtMs < previous.expiresAtMs) {
          throw new P03EnrollmentDenied("pending enrollment already exists");
        }
        const expired = this.registry.db
          .prepare(
            "UPDATE v3_p03_enrollment_challenges SET state='expired' WHERE challenge_id=? AND state='pending'",
          )
          .run(active.challenge_id);
        if (Number(expired.changes) !== 1) {
          throw new P03EnrollmentDenied("expired challenge CAS failed");
        }
        this.appendAudit({
          event: "enrollment.challenge-expired",
          deviceId: candidate.deviceId,
          challengeHash: sha256(active.payload_json),
          atMs: issuedAtMs,
        });
      }
      if (
        this.registry.db
          .prepare("SELECT device_id FROM v3_p03_trusted_identities WHERE device_id=?")
          .get(candidate.deviceId)
      ) {
        throw new P03EnrollmentDenied("device already has a pinned identity");
      }
      this.registry.db
        .prepare(
          "INSERT INTO v3_p03_enrollment_challenges(challenge_id,device_id,payload_json,device_public_key_pem,state) VALUES(?,?,?,?,'pending')",
        )
        .run(challenge.challengeId, candidate.deviceId, canonicalJson(challenge), publicKeyPem);
      this.appendAudit({
        event: "enrollment.staged",
        deviceId: candidate.deviceId,
        challengeHash: sha256(canonicalJson(challenge)),
        atMs: issuedAtMs,
      });
      this.registry.db.exec("COMMIT");
    } catch (error) {
      this.registry.db.exec("ROLLBACK");
      throw error;
    }
    return challenge;
  }

  /**
   * Requires BOTH Ed25519 signatures over the exact challenge plus live
   * independently observed Tailscale identity. No "ownerVerified: true" shortcuts.
   * Does not grant execution consent or authorize remote operations.
   */
  admit(
    challengeId: string,
    deviceSignatureBase64: string,
    ownerSignatureBase64: string,
  ): DeviceDescriptor {
    UUID.parse(challengeId);
    const row = this.registry.db
      .prepare(
        "SELECT payload_json,device_public_key_pem,state FROM v3_p03_enrollment_challenges WHERE challenge_id=?",
      )
      .get(challengeId) as ChallengeRow | undefined;
    if (!row || row.state !== "pending")
      throw new P03EnrollmentDenied("pending challenge not found");
    const challenge = JSON.parse(row.payload_json) as P03EnrollmentChallenge;
    const now = this.now();
    if (now < challenge.issuedAtMs || now >= challenge.expiresAtMs) {
      throw new P03EnrollmentDenied("expired or future-dated challenge");
    }
    const observed = this.config.observeLivePeerNodeHash();
    if (
      !observed ||
      observed !== challenge.expectedTailnetNodeHash ||
      observed !== this.approvedTailnetNodeHash
    ) {
      throw new P03EnrollmentDenied("independent live Mac Tailscale peer identity is missing");
    }
    const message = canonicalJson(challenge);
    if (!verifyProof(ed25519Key(row.device_public_key_pem), message, deviceSignatureBase64)) {
      throw new P03EnrollmentDenied("physical device signature invalid");
    }
    if (!verifyProof(this.approvedOwnerKey, message, ownerSignatureBase64)) {
      throw new P03EnrollmentDenied("owner approval signature invalid");
    }
    this.registry.db.exec("BEGIN IMMEDIATE");
    try {
      const pending = this.registry.db
        .prepare(
          "UPDATE v3_p03_enrollment_challenges SET state='admitted' WHERE challenge_id=? AND state='pending'",
        )
        .run(challengeId);
      if (Number(pending.changes) !== 1) throw new P03EnrollmentDenied("enrollment replay denied");
      const current = this.registry.require(challenge.deviceId);
      if (
        current.trustState !== "pending" ||
        current.hostname !== challenge.hostname ||
        current.platform !== "macos" ||
        current.agentVersion !== challenge.agentVersion
      ) {
        throw new P03EnrollmentDenied("pending descriptor changed during enrollment");
      }
      const trusted = deviceDescriptorSchema.parse({ ...current, trustState: "trusted" });
      const updated = this.registry.db
        .prepare(
          "UPDATE v3_devices SET descriptor_json=?,updated_at=? WHERE device_id=? AND descriptor_json=?",
        )
        .run(canonicalJson(trusted), now, challenge.deviceId, canonicalJson(current));
      if (Number(updated.changes) !== 1)
        throw new DeviceRegistryConflict("device trust CAS failed");
      const claim: AgentIdentityClaim = agentIdentityClaimSchema.parse({
        deviceId: challenge.deviceId,
        agentInstanceId: challenge.agentInstanceId,
        agentVersion: challenge.agentVersion,
        publicKeyFingerprint: challenge.deviceKeyFingerprint,
        enrolledAt: new Date(now).toISOString(),
      });
      this.registry.db
        .prepare(
          "INSERT INTO v3_p03_trusted_identities(device_id,identity_json,device_public_key_pem,tailscale_node_hash) VALUES(?,?,?,?)",
        )
        .run(
          challenge.deviceId,
          canonicalJson(claim),
          row.device_public_key_pem,
          challenge.expectedTailnetNodeHash,
        );
      this.appendAudit({
        event: "enrollment.trusted",
        deviceId: challenge.deviceId,
        challengeHash: sha256(message),
        atMs: now,
      });
      this.registry.db.exec("COMMIT");
      return trusted;
    } catch (error) {
      this.registry.db.exec("ROLLBACK");
      throw error;
    }
  }

  trustedIdentity(deviceId: string):
    | {
        identity: AgentIdentityClaim;
        publicKeyPem: string;
        tailnetNodeHash: string;
      }
    | undefined {
    if (this.registry.get(deviceId)?.trustState !== "trusted") return undefined;
    const row = this.registry.db
      .prepare(
        "SELECT identity_json,device_public_key_pem,tailscale_node_hash FROM v3_p03_trusted_identities WHERE device_id=?",
      )
      .get(deviceId) as StoredIdentity | undefined;
    if (!row) return undefined;
    return {
      identity: agentIdentityClaimSchema.parse(JSON.parse(row.identity_json)),
      publicKeyPem: row.device_public_key_pem,
      tailnetNodeHash: row.tailscale_node_hash,
    };
  }

  /**
   * Only a LIVE signed heartbeat from the enrolled key and pinned Tailnet
   * peer may update the trusted device's health or advertised capabilities.
   * The legacy registry heartbeat intentionally rejects trusted devices.
   */
  applySignedHeartbeat(
    rawHeartbeat: SignedAgentHeartbeat,
    signatureBase64: string,
  ): DeviceDescriptor {
    const heartbeat = signedAgentHeartbeatSchema.parse(rawHeartbeat);
    const stored = this.trustedIdentity(heartbeat.deviceId);
    if (
      !stored ||
      heartbeat.deviceId !== this.config.approvedDeviceId ||
      heartbeat.agentInstanceId !== stored.identity.agentInstanceId ||
      heartbeat.agentVersion !== stored.identity.agentVersion
    ) {
      throw new P03EnrollmentDenied("trusted enrolled agent identity required for heartbeat");
    }
    const now = this.now();
    if (Math.abs(now - heartbeat.signedAtMs) > MAX_HEARTBEAT_SKEW_MS) {
      throw new P03EnrollmentDenied("heartbeat timestamp outside allowed window");
    }
    if (
      this.config.observeLivePeerNodeHash() !== stored.tailnetNodeHash ||
      stored.tailnetNodeHash !== this.approvedTailnetNodeHash
    ) {
      throw new P03EnrollmentDenied("signed heartbeat requires live matching Tailscale peer");
    }
    if (new Set(heartbeat.capabilities).size !== heartbeat.capabilities.length) {
      throw new P03EnrollmentDenied("heartbeat capabilities must be unique");
    }
    const message = canonicalJson(heartbeat);
    if (!verifyProof(ed25519Key(stored.publicKeyPem), message, signatureBase64)) {
      throw new P03EnrollmentDenied("heartbeat signature invalid");
    }
    this.registry.db.exec("BEGIN IMMEDIATE");
    try {
      const previous = this.registry.db
        .prepare(
          "SELECT MAX(signed_at_ms) AS latest FROM v3_p03_heartbeat_nonces WHERE device_id=?",
        )
        .get(heartbeat.deviceId) as { latest: number | null };
      if (previous.latest !== null && heartbeat.signedAtMs <= previous.latest) {
        throw new P03EnrollmentDenied("stale or out-of-order signed heartbeat");
      }
      const current = this.registry.require(heartbeat.deviceId);
      if (current.trustState !== "trusted") {
        throw new P03EnrollmentDenied("device trust was revoked during heartbeat");
      }
      const updated = deviceDescriptorSchema.parse({
        ...current,
        status: heartbeat.status,
        health: heartbeat.health,
        capabilities: heartbeat.capabilities,
        agentVersion: heartbeat.agentVersion,
        lastSeen: new Date(heartbeat.signedAtMs).toISOString(),
      });
      this.registry.db
        .prepare(
          "INSERT INTO v3_p03_heartbeat_nonces(nonce,device_id,signed_at_ms,accepted_at_ms) VALUES(?,?,?,?)",
        )
        .run(heartbeat.nonce, heartbeat.deviceId, heartbeat.signedAtMs, now);
      const outcome = this.registry.db
        .prepare(
          "UPDATE v3_devices SET descriptor_json=?,updated_at=? WHERE device_id=? AND descriptor_json=?",
        )
        .run(canonicalJson(updated), now, heartbeat.deviceId, canonicalJson(current));
      if (Number(outcome.changes) !== 1) {
        throw new P03EnrollmentDenied("signed heartbeat registry update lost CAS");
      }
      this.appendAudit({
        event: "device.signed-heartbeat",
        deviceId: heartbeat.deviceId,
        payloadHash: sha256(message),
        atMs: now,
      });
      this.registry.db.exec("COMMIT");
      return updated;
    } catch (error) {
      this.registry.db.exec("ROLLBACK");
      throw error;
    }
  }

  /**
   * Signed revocation must work even when the Mac is offline or compromised.
   * It changes the authoritative P03 trust state and immediately removes
   * routing eligibility; no network connectivity or agent cooperation needed.
   */
  revokeByOwner(rawRevocation: OwnerRevocation, signatureBase64: string): DeviceDescriptor {
    const input = ownerRevocationSchema.parse(rawRevocation);
    const stored = this.trustedIdentity(input.deviceId);
    if (
      !stored ||
      input.deviceId !== this.config.approvedDeviceId ||
      input.deviceKeyFingerprint !== stored.identity.publicKeyFingerprint
    ) {
      throw new P03EnrollmentDenied("owner revocation requires exact trusted device identity");
    }
    const now = this.now();
    if (Math.abs(now - input.signedAtMs) > MAX_HEARTBEAT_SKEW_MS) {
      throw new P03EnrollmentDenied("owner revocation signature timestamp invalid");
    }
    if (!verifyProof(this.approvedOwnerKey, canonicalJson(input), signatureBase64)) {
      throw new P03EnrollmentDenied("owner revocation signature invalid");
    }

    this.registry.db.exec("BEGIN IMMEDIATE");
    try {
      const current = this.registry.require(input.deviceId);
      if (current.trustState !== "trusted") {
        throw new P03EnrollmentDenied("device already not trusted");
      }
      const revoked = deviceDescriptorSchema.parse({
        ...current,
        trustState: "revoked",
        status: "offline",
        health: "unknown",
        capabilities: [],
      });
      this.registry.db
        .prepare(
          "INSERT INTO v3_p03_revocation_nonces(nonce,device_id,accepted_at_ms) VALUES(?,?,?)",
        )
        .run(input.nonce, input.deviceId, now);
      const outcome = this.registry.db
        .prepare(
          "UPDATE v3_devices SET descriptor_json=?,updated_at=? WHERE device_id=? AND descriptor_json=?",
        )
        .run(canonicalJson(revoked), now, input.deviceId, canonicalJson(current));
      if (Number(outcome.changes) !== 1) {
        throw new P03EnrollmentDenied("owner revocation CAS failed");
      }
      this.appendAudit({
        event: "enrollment.owner-revoked",
        deviceId: input.deviceId,
        reasonHash: sha256(input.reason),
        evidenceHash: sha256(canonicalJson(input)),
        atMs: now,
      });
      this.registry.db.exec("COMMIT");
      return revoked;
    } catch (error) {
      this.registry.db.exec("ROLLBACK");
      throw error;
    }
  }

  auditChain(): { valid: boolean; events: number; head: string } {
    const rows = this.registry.db
      .prepare(
        "SELECT event_json,previous_hash,event_hash FROM v3_p03_enrollment_audit ORDER BY sequence",
      )
      .all() as Array<{ event_json: string; previous_hash: string; event_hash: string }>;
    let previous = "0".repeat(64);
    for (const r of rows) {
      if (r.previous_hash !== previous || r.event_hash !== sha256(previous + "|" + r.event_json)) {
        return { valid: false, events: rows.length, head: previous };
      }
      previous = r.event_hash;
    }
    return { valid: true, events: rows.length, head: previous };
  }

  private appendAudit(event: Record<string, unknown>): void {
    const last = this.registry.db
      .prepare("SELECT event_hash FROM v3_p03_enrollment_audit ORDER BY sequence DESC LIMIT 1")
      .get() as { event_hash: string } | undefined;
    const previous = last?.event_hash ?? "0".repeat(64);
    const json = canonicalJson(event);
    this.registry.db
      .prepare(
        "INSERT INTO v3_p03_enrollment_audit(event_json,previous_hash,event_hash) VALUES(?,?,?)",
      )
      .run(json, previous, sha256(previous + "|" + json));
  }
}
