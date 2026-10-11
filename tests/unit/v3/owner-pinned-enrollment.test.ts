import { generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { canonicalJson, sha256 } from "../../../src/utils/json.js";
import { parseDeviceDescriptor } from "../../../src/v3/device/identity.js";
import {
  ed25519PublicKeyFingerprint,
  SqliteOwnerPinnedEnrollmentAuthority,
  type P03EnrollmentChallenge,
  type OwnerRevocation,
  type SignedAgentHeartbeat,
} from "../../../src/v3/device/owner-pinned-enrollment.js";
import { SqliteDeviceRegistry } from "../../../src/v3/device/registry.js";
import { OwnerPinnedMacRouteGuard } from "../../../src/v3/device/owner-pinned-router.js";
import { DeviceRouter } from "../../../src/v3/device/router.js";

const NODE_HASH = sha256("REAL_TAILSCALE_NODE_ID_IS_NEVER_IN_TEST_EVIDENCE");
const OTHER_HASH = sha256("UNAPPROVED_TAILSCALE_ID");
const MAC = "macbook-main";
const HOST = "amirs-MacBook-Pro.local";
const roots: string[] = [];
const dbs: SqliteDeviceRegistry[] = [];

function signPayload(privateKey: KeyObject, payload: unknown): string {
  return sign(null, Buffer.from(canonicalJson(payload), "utf8"), privateKey).toString("base64");
}

async function fixture() {
  const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-p03-pinned-"));
  roots.push(root);
  const dbFile = path.join(root, "devices.sqlite3");
  const registry = new SqliteDeviceRegistry(dbFile);
  dbs.push(registry);
  const owner = generateKeyPairSync("ed25519");
  const mac = generateKeyPairSync("ed25519");
  const alternate = generateKeyPairSync("ed25519");
  const ownerPublicPem = owner.publicKey.export({ type: "spki", format: "pem" }).toString();
  const devicePublicPem = mac.publicKey.export({ type: "spki", format: "pem" }).toString();
  let clock = Date.UTC(2026, 9, 11, 1, 0, 0);
  let observedHash: string | undefined = NODE_HASH;
  const config = {
    approvedDeviceId: MAC,
    approvedHostname: HOST,
    approvedTailnetNodeHash: NODE_HASH,
    approvedOwnerPublicKeyPem: ownerPublicPem,
    observeLivePeerNodeHash: () => observedHash,
    now: () => clock,
    uuid: () => randomUUID(),
  };
  const authority = new SqliteOwnerPinnedEnrollmentAuthority(registry, config);
  const descriptor = () =>
    parseDeviceDescriptor({
      deviceId: MAC,
      hostname: HOST,
      platform: "macos",
      architecture: "x64",
      agentVersion: "3.0.0-alpha.1",
      trustState: "pending",
      status: "online", // will be forced nonroutable at stage
      health: "healthy",
      lastSeen: new Date(clock).toISOString(),
      capabilities: ["device.health"], // NOT admitted until signed heartbeat
      tags: ["primary"],
    });
  const claim = () => ({
    deviceId: MAC,
    agentVersion: "3.0.0-alpha.1",
    agentInstanceId: "4c7208a8-f6a3-475d-84f9-f0bf9ddc0f9e",
    publicKeyFingerprint: ed25519PublicKeyFingerprint(devicePublicPem),
    enrolledAt: new Date(clock).toISOString(),
  });
  const staged = () => authority.stage(descriptor(), claim(), devicePublicPem);
  const signed = (challenge: P03EnrollmentChallenge) => ({
    deviceSignature: signPayload(mac.privateKey, challenge),
    ownerSignature: signPayload(owner.privateKey, challenge),
  });
  const admitted = () => {
    const challenge = staged();
    const { deviceSignature, ownerSignature } = signed(challenge);
    authority.admit(challenge.challengeId, deviceSignature, ownerSignature);
    return challenge;
  };
  const heartbeat = (extra: Partial<SignedAgentHeartbeat> = {}): SignedAgentHeartbeat => ({
    schema: "radlina.v3.p03.signed-heartbeat/v1",
    deviceId: MAC,
    agentInstanceId: claim().agentInstanceId,
    signedAtMs: clock,
    nonce: randomUUID(),
    agentVersion: "3.0.0-alpha.1",
    status: "online",
    health: "healthy",
    capabilities: ["device.health"],
    ...extra,
  });
  return {
    root,
    dbFile,
    registry,
    authority,
    descriptor,
    claim,
    staged,
    signed,
    admitted,
    heartbeat,
    owner,
    mac,
    alternate,
    config,
    ownerPublicPem,
    devicePublicPem,
    currentTime: () => clock,
    currentObserved: () => observedHash,
    advanceClock: (milliseconds: number) => {
      clock += milliseconds;
    },
    setObservedHash: (next?: string) => {
      observedHash = next;
    },
  };
}

afterEach(async () => {
  for (const db of dbs.splice(0)) db.close();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("P03 owner-pinned signed macOS enrollment (dormant candidate)", () => {
  it("stages only a pending, unknown-health, capability-free descriptor that P06 cannot route", async () => {
    const f = await fixture();
    const challenge = f.staged();
    expect(challenge).toMatchObject({
      deviceId: MAC,
      expectedTailnetNodeHash: NODE_HASH,
      purpose: "p03.owner-approved-enrollment",
    });
    expect(f.registry.require(MAC)).toMatchObject({
      trustState: "pending",
      health: "unknown",
      status: "unknown",
      capabilities: [],
    });
    expect(() => new DeviceRouter(f.registry).route({ deviceId: MAC }, "device.health")).toThrow(
      /will not fail over/u,
    );
    expect(f.authority.auditChain()).toMatchObject({ valid: true, events: 1 });
  });

  it("requires BOTH independent Ed25519 signatures plus live Windows-observed Tailscale pin", async () => {
    const f = await fixture();
    const challenge = f.staged();
    const proofs = f.signed(challenge);
    expect(
      f.authority.admit(challenge.challengeId, proofs.deviceSignature, proofs.ownerSignature),
    ).toMatchObject({ deviceId: MAC, trustState: "trusted", capabilities: [], status: "unknown" });
    expect(f.authority.trustedIdentity(MAC)).toMatchObject({
      identity: { deviceId: MAC, publicKeyFingerprint: f.claim().publicKeyFingerprint },
      tailnetNodeHash: NODE_HASH,
    });
    expect(f.authority.auditChain()).toMatchObject({ valid: true, events: 2 });
    expect(() => new DeviceRouter(f.registry).route({ deviceId: MAC }, "device.health")).toThrow(
      /will not fail over/u,
    );
  });

  it("denies forged owner or device signatures, and prevents mixing unrelated signing keys", async () => {
    const f = await fixture();
    const challenge = f.staged();
    const proofs = f.signed(challenge);
    const wrong = signPayload(f.alternate.privateKey, challenge);
    expect(() => f.authority.admit(challenge.challengeId, wrong, proofs.ownerSignature)).toThrow(
      /device signature invalid/u,
    );
    expect(() => f.authority.admit(challenge.challengeId, proofs.deviceSignature, wrong)).toThrow(
      /owner approval signature invalid/u,
    );
    expect(f.registry.require(MAC).trustState).toBe("pending");
  });

  it("rejects replayed admissions, duplicate pending enrollment and silent key rotation", async () => {
    const f = await fixture();
    const challenge = f.staged();
    expect(() => f.staged()).toThrow(/pending enrollment already exists/u);
    const proofs = f.signed(challenge);
    f.authority.admit(challenge.challengeId, proofs.deviceSignature, proofs.ownerSignature);
    expect(() =>
      f.authority.admit(challenge.challengeId, proofs.deviceSignature, proofs.ownerSignature),
    ).toThrow(/pending challenge not found/u);
    expect(() => f.staged()).toThrow(/silently re-enrolled/u);
  });

  it("fails closed for expired challenge and a stale or changed independent Tailnet peer", async () => {
    const first = await fixture();
    const ch1 = first.staged();
    const proofs = first.signed(ch1);
    first.setObservedHash(undefined);
    expect(() =>
      first.authority.admit(ch1.challengeId, proofs.deviceSignature, proofs.ownerSignature),
    ).toThrow(/live Mac Tailscale peer identity/u);
    first.setObservedHash(OTHER_HASH);
    expect(() =>
      first.authority.admit(ch1.challengeId, proofs.deviceSignature, proofs.ownerSignature),
    ).toThrow(/live Mac Tailscale peer identity/u);
    first.setObservedHash(NODE_HASH);
    first.advanceClock(10 * 60_000 + 1);
    expect(() =>
      first.authority.admit(ch1.challengeId, proofs.deviceSignature, proofs.ownerSignature),
    ).toThrow(/expired/u);
    expect(first.registry.require(MAC).trustState).toBe("pending");
  });

  it("replaces an expired pending challenge atomically without trusting the Mac", async () => {
    const f = await fixture();
    const expired = f.staged();
    f.advanceClock(10 * 60_000 + 1);
    const renewed = f.staged();
    expect(renewed.challengeId).not.toBe(expired.challengeId);
    expect(f.registry.require(MAC)).toMatchObject({
      trustState: "pending",
      status: "unknown",
      health: "unknown",
    });
    const oldSignatures = f.signed(expired);
    expect(() =>
      f.authority.admit(
        expired.challengeId,
        oldSignatures.deviceSignature,
        oldSignatures.ownerSignature,
      ),
    ).toThrow(/pending challenge not found/u);
    expect(f.authority.auditChain()).toMatchObject({ valid: true, events: 3 });
  });

  it("rejects spoofed platform, hostname, logical identity and public-key fingerprint", async () => {
    const f = await fixture();
    const raw = f.descriptor();
    expect(() =>
      f.authority.stage({ ...raw, deviceId: "windows-main" }, f.claim(), f.devicePublicPem),
    ).toThrow(/identity/u);
    expect(() =>
      f.authority.stage({ ...raw, hostname: "other-host" }, f.claim(), f.devicePublicPem),
    ).toThrow(/identity/u);
    expect(() =>
      f.authority.stage({ ...raw, platform: "windows" }, f.claim(), f.devicePublicPem),
    ).toThrow(/identity/u);
    expect(() =>
      f.authority.stage(raw, { ...f.claim(), publicKeyFingerprint: OTHER_HASH }, f.devicePublicPem),
    ).toThrow(/fingerprint mismatch/u);
    expect(() =>
      f.authority.stage(
        raw,
        { ...f.claim(), publicKeyFingerprint: ed25519PublicKeyFingerprint(f.ownerPublicPem) },
        f.ownerPublicPem,
      ),
    ).toThrow(/owner and device signing keys must be independent/u);
    expect(f.registry.list()).toEqual([]);
  });

  it("never routes based on unsiged trusted heartbeat; only a signed fresh exact-device health report", async () => {
    const f = await fixture();
    f.admitted();
    expect(() =>
      f.registry.heartbeat(MAC, {
        status: "online",
        health: "healthy",
        lastSeen: new Date().toISOString(),
        agentVersion: "3.0.0-alpha.1",
        capabilities: ["device.health"],
      }),
    ).toThrow(/requires a verified signed/u);
    const hb = f.heartbeat();
    expect(f.authority.applySignedHeartbeat(hb, signPayload(f.mac.privateKey, hb))).toMatchObject({
      deviceId: MAC,
      status: "online",
      health: "healthy",
      capabilities: ["device.health"],
      trustState: "trusted",
    });
    expect(
      new DeviceRouter(f.registry).route({ deviceId: MAC }, "device.health").device.deviceId,
    ).toBe(MAC);
    expect(() =>
      new DeviceRouter(f.registry).route({ deviceId: "windows-main" }, "device.health"),
    ).toThrow(/exact device not found/u);
    expect(f.authority.auditChain()).toMatchObject({ valid: true, events: 3 });
  });

  it("rejects heartbeat replay and tampering, including signer, nonce, input and agent instance", async () => {
    const f = await fixture();
    f.admitted();
    const hb = f.heartbeat();
    const sig = signPayload(f.mac.privateKey, hb);
    expect(() =>
      f.authority.applySignedHeartbeat(hb, signPayload(f.alternate.privateKey, hb)),
    ).toThrow(/signature invalid/u);
    expect(() => f.authority.applySignedHeartbeat({ ...hb, status: "offline" }, sig)).toThrow(
      /signature invalid/u,
    );
    expect(() =>
      f.authority.applySignedHeartbeat({ ...hb, agentInstanceId: randomUUID() }, sig),
    ).toThrow(/identity required/u);
    f.authority.applySignedHeartbeat(hb, sig);
    expect(() => f.authority.applySignedHeartbeat(hb, sig)).toThrow(/stale or out-of-order/u);
    expect(f.registry.require(MAC).status).toBe("online");
  });

  it("rejects wrong Tailnet node, stale timestamp, future-dated and duplicated heartbeat capabilities", async () => {
    const f = await fixture();
    f.admitted();
    const hb = f.heartbeat();
    const sig = signPayload(f.mac.privateKey, hb);
    f.setObservedHash(OTHER_HASH);
    expect(() => f.authority.applySignedHeartbeat(hb, sig)).toThrow(/matching Tailscale peer/u);
    f.setObservedHash(NODE_HASH);
    f.advanceClock(120_001);
    expect(() => f.authority.applySignedHeartbeat(hb, sig)).toThrow(/timestamp outside/u);
    const dup = f.heartbeat({ capabilities: ["device.health", "device.health"] });
    expect(() => f.authority.applySignedHeartbeat(dup, signPayload(f.mac.privateKey, dup))).toThrow(
      /capabilities must be unique/u,
    );
  });

  it("accepts owner-signed revocation even with the Mac offline; P06 immediately rejects the device", async () => {
    const f = await fixture();
    f.admitted();
    const signed = f.heartbeat();
    f.authority.applySignedHeartbeat(signed, signPayload(f.mac.privateKey, signed));
    f.setObservedHash(undefined);
    const ownerRevocation: OwnerRevocation = {
      schema: "radlina.v3.p03.owner-revocation/v1",
      deviceId: MAC,
      deviceKeyFingerprint: f.claim().publicKeyFingerprint,
      signedAtMs: signed.signedAtMs,
      nonce: randomUUID(),
      reason: "physical device access revoked by owner",
    };
    const signature = signPayload(f.owner.privateKey, ownerRevocation);
    expect(f.authority.revokeByOwner(ownerRevocation, signature)).toMatchObject({
      trustState: "revoked",
      status: "offline",
      capabilities: [],
    });
    expect(f.authority.trustedIdentity(MAC)).toBeUndefined();
    expect(() => new DeviceRouter(f.registry).route({ deviceId: MAC }, "device.health")).toThrow(
      /will not fail over/u,
    );
    expect(f.authority.auditChain()).toMatchObject({ valid: true, events: 4 });
    expect(() => f.authority.revokeByOwner(ownerRevocation, signature)).toThrow(
      /exact trusted device identity/u,
    );
  });

  it("rejects forged owner revocation, wrong key pin and out-of-window owner signatures", async () => {
    const f = await fixture();
    f.admitted();
    const ownerRevocation: OwnerRevocation = {
      schema: "radlina.v3.p03.owner-revocation/v1",
      deviceId: MAC,
      deviceKeyFingerprint: f.claim().publicKeyFingerprint,
      signedAtMs: Date.UTC(2026, 9, 11, 1, 0, 0),
      nonce: randomUUID(),
      reason: "owner approval withdrawn",
    };
    expect(() =>
      f.authority.revokeByOwner(
        ownerRevocation,
        signPayload(f.alternate.privateKey, ownerRevocation),
      ),
    ).toThrow(/revocation signature invalid/u);
    expect(() =>
      f.authority.revokeByOwner(
        { ...ownerRevocation, deviceKeyFingerprint: OTHER_HASH },
        signPayload(f.owner.privateKey, ownerRevocation),
      ),
    ).toThrow(/exact trusted device identity/u);
    f.advanceClock(120_001);
    expect(() =>
      f.authority.revokeByOwner(ownerRevocation, signPayload(f.owner.privateKey, ownerRevocation)),
    ).toThrow(/timestamp invalid/u);
    expect(f.registry.require(MAC).trustState).toBe("trusted");
  });

  it("P06 refuses pending or trusted-but-no-signed-heartbeat Mac, then routes exact signed healthy Mac only", async () => {
    const f = await fixture();
    const guard = new OwnerPinnedMacRouteGuard(
      f.registry,
      f.authority,
      f.currentObserved,
      f.currentTime,
    );
    f.staged();
    expect(() => guard.exact(MAC, "device.health")).toThrow(/trust identity is missing/u);

    const db2 = await fixture();
    const guard2 = new OwnerPinnedMacRouteGuard(
      db2.registry,
      db2.authority,
      db2.currentObserved,
      db2.currentTime,
    );
    db2.admitted();
    expect(() => guard2.exact(MAC, "device.health")).toThrow(/no verified live signed heartbeat/u);
    const heartbeat = db2.heartbeat();
    db2.authority.applySignedHeartbeat(heartbeat, signPayload(db2.mac.privateKey, heartbeat));
    expect(guard2.exact(MAC, "device.health")).toMatchObject({
      exact: true,
      device: { deviceId: MAC, platform: "macos", trustState: "trusted" },
    });
    expect(() => guard2.exact("windows-main", "device.health")).toThrow(
      /trust identity is missing/u,
    );
  });

  it("P06 fails closed for changed Tailscale peer, stale signed heartbeat or corrupted descriptor", async () => {
    const f = await fixture();
    f.admitted();
    const heartbeat = f.heartbeat();
    f.authority.applySignedHeartbeat(heartbeat, signPayload(f.mac.privateKey, heartbeat));
    const guard = new OwnerPinnedMacRouteGuard(
      f.registry,
      f.authority,
      f.currentObserved,
      f.currentTime,
    );
    f.setObservedHash(OTHER_HASH);
    expect(() => guard.exact(MAC, "device.health")).toThrow(/Tailscale peer identity/u);
    f.setObservedHash(NODE_HASH);
    f.advanceClock(120_001);
    expect(() => guard.exact(MAC, "device.health")).toThrow(/stale/u);
    f.advanceClock(-120_001);
    const current = f.registry.require(MAC);
    f.registry.db
      .prepare("UPDATE v3_devices SET descriptor_json=? WHERE device_id=?")
      .run(canonicalJson({ ...current, lastSeen: "2030-01-01T00:00:00.000Z" }), MAC);
    expect(() => guard.exact(MAC, "device.health")).toThrow(/no verified live signed heartbeat/u);
  });

  it("P06 rejects identity-table key replacement independently of device trust flags", async () => {
    const f = await fixture();
    f.admitted();
    const heartbeat = f.heartbeat();
    f.authority.applySignedHeartbeat(heartbeat, signPayload(f.mac.privateKey, heartbeat));
    const guard = new OwnerPinnedMacRouteGuard(
      f.registry,
      f.authority,
      f.currentObserved,
      f.currentTime,
    );
    const wrongPem = f.alternate.publicKey.export({ type: "spki", format: "pem" }).toString();
    f.registry.db
      .prepare("UPDATE v3_p03_trusted_identities SET device_public_key_pem=? WHERE device_id=?")
      .run(wrongPem, MAC);
    expect(() => guard.exact(MAC, "device.health")).toThrow(/signing key changed/u);
  });

  it("persists independently verified public key and detects tampering in the local audit journal", async () => {
    const f = await fixture();
    f.admitted();
    const other = new SqliteDeviceRegistry(f.dbFile);
    dbs.push(other);
    const authority2 = new SqliteOwnerPinnedEnrollmentAuthority(other, f.config);
    expect(authority2.trustedIdentity(MAC)?.identity.publicKeyFingerprint).toBe(
      f.claim().publicKeyFingerprint,
    );
    expect(authority2.auditChain().valid).toBe(true);
    f.registry.db
      .prepare("UPDATE v3_p03_enrollment_audit SET event_json='tampered' WHERE sequence=1")
      .run();
    expect(authority2.auditChain().valid).toBe(false);
  });
});
