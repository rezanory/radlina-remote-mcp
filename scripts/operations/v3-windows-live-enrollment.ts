import { execFileSync } from "node:child_process";
import { verify } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import os from "node:os";

import { canonicalJson, sha256 } from "../../src/utils/json.js";
import {
  ed25519PublicKeyFingerprint,
  SqliteOwnerPinnedEnrollmentAuthority,
} from "../../src/v3/device/owner-pinned-enrollment.js";
import { SqliteDeviceRegistry } from "../../src/v3/device/registry.js";
import { WindowsProtectedDeviceIdentity } from "../../src/v3/device/windows-protected-identity.js";

if (process.platform !== "win32" || os.hostname().toLowerCase() !== "laptop-13qineif")
  throw new Error("physical Windows required");
const mode = process.argv[2];
if (mode !== "stage" && mode !== "admit") throw new Error("stage or admit required");
const ownerPin = JSON.parse(
  await readFile(
    "C:\\Users\\Radlina\\AppData\\Local\\Radlina\\V3\\owner-signing\\owner-public-pin.json",
    "utf8",
  ),
) as { ownerPrincipal: string; ownerSid: string; publicKeyPem: string; fingerprint: string };
const ownerFingerprint = "6259d21211f73fc9d2d7cc0174d9bfdc36424cd456878671ab5683468ca0fe93";
if (
  ownerPin.ownerPrincipal.toLowerCase() !== "laptop-13qineif\\radlina" ||
  ownerPin.ownerSid !== "S-1-5-21-827254616-2815314212-688626134-1001" ||
  ownerPin.fingerprint !== ownerFingerprint ||
  ed25519PublicKeyFingerprint(ownerPin.publicKeyPem) !== ownerFingerprint
)
  throw new Error("independent authenticated owner pin mismatch");
function observeWindowsNode() {
  const s = JSON.parse(
    execFileSync("C:\\Program Files\\Tailscale\\tailscale.exe", ["status", "--json"], {
      encoding: "utf8",
      timeout: 15000,
    }),
  ) as {
    BackendState: string;
    CurrentTailnet: { Name: string };
    Self: { ID: string; OS: string; DNSName: string; Online: boolean };
  };
  if (
    s.BackendState !== "Running" ||
    s.CurrentTailnet.Name !== "rezanory.github" ||
    !s.Self.ID ||
    s.Self.OS !== "windows" ||
    !s.Self.Online ||
    s.Self.DNSName.replace(/\.$/u, "").toLowerCase() !== "laptop-13qineif.taile17c9e.ts.net"
  )
    throw new Error("Windows network identity not independently available");
  return sha256(s.Self.ID);
}
const networkPin = observeWindowsNode();
const device = await WindowsProtectedDeviceIdentity.open(
  "E:\\radlina-v3-runtime\\windows-device-identity",
);
const pub = device.publicIdentity();
if (
  pub.fingerprint !== "fafcea842b3d0142b9cb24ff05455a09da409d44e7d08a483b39bb0596a7f5a0" ||
  String(pub.fingerprint) === ownerFingerprint
)
  throw new Error("dedicated Windows device pin mismatch");
const registry = new SqliteDeviceRegistry("E:\\radlina-v3-oauth-standalone\\v3-devices.sqlite3");
const authority = new SqliteOwnerPinnedEnrollmentAuthority(registry, {
  approvedOwnerPublicKeyPem: ownerPin.publicKeyPem,
  approvedDeviceId: "windows-main",
  approvedHostname: "LAPTOP-13QINEIF",
  approvedPlatform: "windows",
  approvedTailnetNodeHash: networkPin,
  observeLivePeerNodeHash: () => observeWindowsNode(),
});
const challengeFile = "E:\\radlina-v3-runtime\\windows-device-identity\\enrollment-challenge.json";
const deviceSignatureFile =
  "E:\\radlina-v3-runtime\\windows-device-identity\\device-challenge-signature.json";
const ownerSignatureFile =
  "E:\\radlina-v3-runtime\\windows-device-identity\\owner-challenge-signature.json";
try {
  if (mode === "stage") {
    const descriptor = registry.require("windows-main");
    const challenge = authority.stage(
      descriptor,
      {
        deviceId: pub.deviceId,
        agentInstanceId: pub.agentInstanceId,
        agentVersion: pub.agentVersion,
        publicKeyFingerprint: pub.fingerprint,
        enrolledAt: new Date().toISOString(),
      },
      pub.publicKeyPem,
    );
    const signature = device.signChallenge(challenge);
    if (
      !verify(
        null,
        Buffer.from(canonicalJson(challenge)),
        pub.publicKeyPem,
        Buffer.from(signature, "base64"),
      )
    )
      throw new Error("device proof failed");
    await writeFile(challengeFile, JSON.stringify(challenge, null, 2) + "\n", { flag: "wx" });
    await writeFile(
      deviceSignatureFile,
      JSON.stringify({ challenge, deviceSignatureBase64: signature }),
      { flag: "wx" },
    );
    process.stdout.write(
      JSON.stringify({
        status: "P03_WINDOWS_REAL_CHALLENGE_STAGED",
        challengeId: challenge.challengeId,
        expiresAt: challenge.expiresAtMs,
        trust: registry.require("windows-main").trustState,
      }) + "\n",
    );
  } else {
    const owner = JSON.parse(await readFile(ownerSignatureFile, "utf8")) as {
      challenge: unknown;
      publicPin: { fingerprint: string };
      ownerSignatureBase64: string;
    };
    const signed = JSON.parse(await readFile(deviceSignatureFile, "utf8")) as {
      challenge: { challengeId: string };
      deviceSignatureBase64: string;
    };
    if (
      canonicalJson(owner.challenge) !== canonicalJson(signed.challenge) ||
      owner.publicPin.fingerprint !== ownerFingerprint
    )
      throw new Error("challenge or owner pin changed");
    const admitted = authority.admit(
      signed.challenge.challengeId,
      signed.deviceSignatureBase64,
      owner.ownerSignatureBase64,
    );
    // Agent transport is not yet active, so health remains unknown and routing stays denied.
    const heartbeat = device.heartbeat("degraded", "unknown");
    const updated = authority.applySignedHeartbeat(
      heartbeat.heartbeat,
      heartbeat.deviceSignatureBase64,
    );
    let replayDenied = false;
    try {
      authority.applySignedHeartbeat(heartbeat.heartbeat, heartbeat.deviceSignatureBase64);
    } catch {
      replayDenied = true;
    }
    if (!replayDenied || !authority.auditChain().valid)
      throw new Error("heartbeat replay/audit failed");
    const receipt = {
      schema: "radlina.v3.windows-real-dual-signature-admission/v1",
      input: {
        deviceId: "windows-main",
        ownerFingerprint,
        ownerSidHash: sha256(ownerPin.ownerSid),
        deviceFingerprint: pub.fingerprint,
        networkPin,
      },
      runtime: {
        ownerSigner: "actual owner interactive token / DPAPI CurrentUser",
        deviceSigner: "SYSTEM service / DPAPI LocalMachine with private ACL",
        registry: "actual V3 OAuth SQLite",
      },
      execution: {
        timestamp: new Date().toISOString(),
        challenge: signed.challenge,
        deviceSignatureBase64: signed.deviceSignatureBase64,
        ownerSignatureBase64: owner.ownerSignatureBase64,
        independentKeys: true,
        admittedTrust: admitted.trustState,
        heartbeatApplied: true,
        heartbeatReplayDenied: replayDenied,
        audit: authority.auditChain(),
      },
      output: { device: updated, heartbeat },
      acceptance: "WINDOWS_P03_TRUSTED_WITH_SIGNED_DEGRADED_HEARTBEAT_ONLY",
      remaining: [
        "Mac trusted enrollment and fresh heartbeat",
        "healthy persistent agent transport",
        "target-local consent",
        "distributed audit anchor",
        "real two-host fleet canary/rollback",
        "executable OAuth runtime",
      ],
      official: { accepted: 24, total: 28, percent: 85.71 },
    };
    await writeFile(
      "governance/v3/validation/V3_WINDOWS_REAL_OWNER_DEVICE_DUAL_SIGNATURE_20261011.json",
      JSON.stringify(receipt, null, 2) + "\n",
      { flag: "wx" },
    );
    process.stdout.write(
      JSON.stringify({
        acceptance: receipt.acceptance,
        trust: updated.trustState,
        health: updated.health,
        status: updated.status,
        replayDenied,
        audit: authority.auditChain(),
        productionReady: false,
      }) + "\n",
    );
  }
} finally {
  registry.close();
}
