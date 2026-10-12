import { execFileSync } from "node:child_process";
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import * as z from "zod/v4";
import { canonicalJson, sha256 } from "../../src/utils/json.js";
import {
  SqliteOwnerPinnedEnrollmentAuthority,
  ed25519PublicKeyFingerprint,
} from "../../src/v3/device/owner-pinned-enrollment.js";
import { SqliteDeviceRegistry } from "../../src/v3/device/registry.js";

const id = "1307f5bc-b1ee-47a4-bd06-251b3d128e5e";
const root = "E:\\radlina-v3-oauth-standalone\\p03-inbound";
const tailPin = "c7886ac103d4c05907ff8953ae60687d31303146a9b122cb55bff0dc1860bc9c";
const macPin = "f2c2e93ff120fbc5122cbb6b5a0b461a072f54bd8d226368c858fd0bd17037ea";
const ownerPin = "6259d21211f73fc9d2d7cc0174d9bfdc36424cd456878671ab5683468ca0fe93";
if (process.platform !== "win32" || os.hostname().toLowerCase() !== "laptop-13qineif")
  throw Error("physical owner Windows required");
const challengeSchema = z
  .object({
    schema: z.literal("1.0.0"),
    purpose: z.literal("p03.owner-approved-enrollment"),
    challengeId: z.string().uuid(),
    deviceId: z.literal("macbook-main"),
    hostname: z.literal("amirs-MacBook-Pro.local"),
    platform: z.literal("macos"),
    architecture: z.literal("x64"),
    agentVersion: z.literal("3.0.0-alpha.1"),
    agentInstanceId: z.string().uuid(),
    deviceKeyFingerprint: z.string().regex(/^[0-9a-f]{64}$/u),
    expectedTailnetNodeHash: z.string().regex(/^[0-9a-f]{64}$/u),
    issuedAtMs: z.number().int(),
    expiresAtMs: z.number().int(),
  })
  .strict();
const ownerSchema = z
  .object({
    challenge: challengeSchema,
    publicPin: z
      .object({
        fingerprint: z.string().regex(/^[0-9a-f]{64}$/u),
        publicKeyPem: z.string().min(1).max(4096),
      })
      .passthrough(),
    ownerSignatureBase64: z.string().min(1).max(200),
  })
  .passthrough();
const macSchema = z
  .object({
    challengeId: z.string().uuid(),
    challengeSha256: z.string().regex(/^[0-9a-f]{64}$/u),
    deviceId: z.literal("macbook-main"),
    schema: z.literal("radlina.v3.p03.device-proof/v1"),
    deviceSignatureBase64: z.string().min(1).max(200),
  })
  .strict();
const challenge = challengeSchema.parse(
  JSON.parse(await readFile(path.win32.join(root, "mac-challenge-" + id + ".json"), "utf8")),
);
const owner = ownerSchema.parse(
  JSON.parse(await readFile(path.win32.join(root, "mac-owner-signature-" + id + ".json"), "utf8")),
);
const mac = macSchema.parse(
  JSON.parse(await readFile(path.win32.join(root, "mac-signed-challenge-" + id + ".json"), "utf8")),
);
if (
  challenge.challengeId !== id ||
  owner.challenge?.challengeId !== id ||
  mac.challengeId !== id ||
  canonicalJson(challenge) !== canonicalJson(owner.challenge) ||
  mac.deviceId !== "macbook-main" ||
  mac.schema !== "radlina.v3.p03.device-proof/v1" ||
  mac.challengeSha256 !== sha256(canonicalJson(challenge)) ||
  challenge.deviceKeyFingerprint !== macPin ||
  owner.publicPin?.fingerprint !== ownerPin ||
  ed25519PublicKeyFingerprint(owner.publicPin.publicKeyPem) !== ownerPin ||
  !verify(
    null,
    Buffer.from(canonicalJson(challenge)),
    createPublicKey(owner.publicPin.publicKeyPem),
    Buffer.from(owner.ownerSignatureBase64, "base64"),
  )
)
  throw Error("owner signature or exact public challenge mismatched");
function onlineMac(): string | undefined {
  const s = JSON.parse(
    execFileSync("C:\\Program Files\\Tailscale\\tailscale.exe", ["status", "--json"], {
      encoding: "utf8",
      timeout: 13000,
      maxBuffer: 4194304,
      windowsHide: true,
    }),
  ) as {
    BackendState?: string;
    CurrentTailnet?: { Name?: string };
    Peer?: Record<string, { ID?: string; OS?: string; Online?: boolean; DNSName?: string }>;
  };
  const peers = Object.values(s.Peer ?? {}).filter(
    (p) =>
      p.OS === "macOS" &&
      p.Online === true &&
      p.DNSName?.replace(/\.$/u, "").toLowerCase() === "amirs-macbook-pro.taile17c9e.ts.net",
  );
  if (
    s.BackendState !== "Running" ||
    s.CurrentTailnet?.Name !== "rezanory.github" ||
    peers.length !== 1 ||
    !peers[0]?.ID
  )
    return undefined;
  return createHash("sha256").update(peers[0].ID).digest("hex");
}
if (onlineMac() !== tailPin) throw Error("Mac Tailnet node not independently online or changed");
const registry = new SqliteDeviceRegistry("E:\\radlina-v3-oauth-standalone\\v3-devices.sqlite3");
try {
  const current = registry.require("macbook-main");
  if (current.trustState !== "pending" || current.capabilities.length !== 0)
    throw Error("Mac not pending/fail-closed");
  const auth = new SqliteOwnerPinnedEnrollmentAuthority(registry, {
    approvedOwnerPublicKeyPem: owner.publicPin.publicKeyPem,
    approvedDeviceId: "macbook-main",
    approvedHostname: "amirs-MacBook-Pro.local",
    approvedPlatform: "macos",
    approvedTailnetNodeHash: tailPin,
    observeLivePeerNodeHash: onlineMac,
  });
  const trusted = auth.admit(id, mac.deviceSignatureBase64, owner.ownerSignatureBase64);
  const saved = auth.trustedIdentity("macbook-main");
  const audit = auth.auditChain();
  if (
    trusted.trustState !== "trusted" ||
    !saved ||
    saved.identity.publicKeyFingerprint !== macPin ||
    !audit.valid ||
    registry.require("macbook-main").trustState !== "trusted"
  )
    throw Error("P03 trust was not durably admitted");
  const result = {
    acceptance: "REAL_MAC_P03_DUAL_ED25519_TRUSTED_ADMISSION_PASS",
    id,
    deviceId: "macbook-main",
    ownerSignatureVerified: true,
    macSignatureVerified: true,
    windowsObservedTailnetPin: tailPin,
    macPublicKeyFingerprint: macPin,
    registryTrust: "trusted",
    registryStatus: trusted.status,
    registryHealth: trusted.health,
    registryCapabilities: trusted.capabilities,
    auditValid: audit.valid,
    auditEvents: audit.events,
    signedHeartbeatFresh: false,
    remoteExecutionEnabledByAdmission: false,
    v2Modified: false,
  };
  await writeFile(
    path.win32.join(root, "mac-trusted-receipt-" + id + ".json"),
    canonicalJson(result) + "\n",
    { flag: "wx" },
  );
  process.stdout.write(JSON.stringify(result) + "\n");
} finally {
  registry.close();
}
