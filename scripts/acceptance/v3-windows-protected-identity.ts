import { randomUUID, verify } from "node:crypto";
import { writeFile } from "node:fs/promises";
import os from "node:os";

import { canonicalJson, sha256 } from "../../src/utils/json.js";
import { type P03EnrollmentChallenge } from "../../src/v3/device/owner-pinned-enrollment.js";
import { WindowsProtectedDeviceIdentity } from "../../src/v3/device/windows-protected-identity.js";

if (process.platform !== "win32" || os.hostname().toLowerCase() !== "laptop-13qineif")
  throw new Error("physical Windows control-plane host required");
const directory = process.argv[2],
  output = process.argv[3];
if (!directory || !output)
  throw new Error("private identity directory and public evidence output required");
const identity = await WindowsProtectedDeviceIdentity.open(directory, true);
const first = identity.publicIdentity();
const reopened = await WindowsProtectedDeviceIdentity.open(directory);
const second = reopened.publicIdentity();
if (canonicalJson(first) !== canonicalJson(second)) throw new Error("identity did not persist");
const now = Date.now();
const challenge: P03EnrollmentChallenge = {
  schema: "1.0.0",
  purpose: "p03.owner-approved-enrollment",
  challengeId: randomUUID(),
  deviceId: first.deviceId,
  hostname: first.hostname,
  platform: "windows",
  architecture: "x64",
  agentVersion: first.agentVersion,
  agentInstanceId: first.agentInstanceId,
  deviceKeyFingerprint: first.fingerprint,
  expectedTailnetNodeHash: sha256("isolated-device-signing-check-not-enrollment"),
  issuedAtMs: now,
  expiresAtMs: now + 60000,
};
const signature = reopened.signChallenge(challenge);
const valid = verify(
  null,
  Buffer.from(canonicalJson(challenge)),
  first.publicKeyPem,
  Buffer.from(signature, "base64"),
);
if (!valid) throw new Error("Windows Ed25519 proof invalid");
const rejects: Record<string, boolean> = {};
const candidates: Record<string, P03EnrollmentChallenge> = {
  expired: { ...challenge, issuedAtMs: now - 120000, expiresAtMs: now - 1 },
  future: { ...challenge, issuedAtMs: now + 60000 },
  wrongDevice: { ...challenge, deviceId: "macbook-main" },
  wrongKey: { ...challenge, deviceKeyFingerprint: "0".repeat(64) },
  wrongInstance: { ...challenge, agentInstanceId: randomUUID() },
  wrongPlatform: { ...challenge, platform: "macos" },
  overlong: { ...challenge, expiresAtMs: now + 600001 },
};
for (const [name, payload] of Object.entries(candidates)) {
  try {
    reopened.signChallenge(payload);
    rejects[name] = false;
  } catch {
    rejects[name] = true;
  }
}
if (Object.values(rejects).some((x) => !x)) throw new Error("negative challenge check failed");
const heartbeat = reopened.heartbeat("degraded", "unknown");
if (
  !verify(
    null,
    Buffer.from(canonicalJson(heartbeat.heartbeat)),
    first.publicKeyPem,
    Buffer.from(heartbeat.deviceSignatureBase64, "base64"),
  )
)
  throw new Error("heartbeat proof invalid");
const receipt = {
  schema: "radlina.v3.windows-protected-device-real-proof/v1",
  input: { host: os.hostname(), privateDirectory: directory, V2CredentialsUsed: false },
  runtime: {
    node: process.version,
    platform: process.platform,
    protection: "DPAPI-LocalMachine plus SYSTEM/Administrators ACL",
  },
  execution: {
    timestamp: new Date().toISOString(),
    identityPersisted: true,
    challengeSignatureVerified: valid,
    negativeChecks: rejects,
    signedHeartbeatVerified: true,
  },
  output: { publicIdentity: first, challenge, deviceSignatureBase64: signature, heartbeat },
  acceptance: "REAL_WINDOWS_DEVICE_PROOF_ONLY_NOT_TRUSTED_ENROLLMENT",
  remaining: [
    "independent owner identity pin and owner signature",
    "live independent Tailnet observation",
    "P03 dual-signature admission",
    "accepted fresh heartbeat",
    "target consent and distributed audit",
  ],
  official: { accepted: 24, total: 28, percent: 85.71 },
};
await writeFile(output, JSON.stringify(receipt, null, 2) + "\n", { flag: "wx" });
process.stdout.write(
  JSON.stringify({
    acceptance: receipt.acceptance,
    publicIdentity: first,
    checksPassed: 10,
    checksFailed: 0,
    evidence: output,
  }) + "\n",
);
