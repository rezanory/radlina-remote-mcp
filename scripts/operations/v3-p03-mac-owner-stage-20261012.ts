import { execFileSync } from "node:child_process";
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { canonicalJson } from "../../src/utils/json.js";
import {
  ed25519PublicKeyFingerprint,
  SqliteOwnerPinnedEnrollmentAuthority,
} from "../../src/v3/device/owner-pinned-enrollment.js";
import { SqliteDeviceRegistry } from "../../src/v3/device/registry.js";

const macPin = "f2c2e93ff120fbc5122cbb6b5a0b461a072f54bd8d226368c858fd0bd17037ea";
const peerPin = "c7886ac103d4c05907ff8953ae60687d31303146a9b122cb55bff0dc1860bc9c";
const ownerPin = "6259d21211f73fc9d2d7cc0174d9bfdc36424cd456878671ab5683468ca0fe93";
const root = "E:\\radlina-v3-oauth-standalone\\p03-inbound";
if (process.platform !== "win32" || os.hostname().toLowerCase() !== "laptop-13qineif") {
  throw Error("Windows live owner enrollment host required");
}
const signed = JSON.parse(
  await readFile(path.win32.join(root, "mac-ensure-38189747769.json"), "utf8"),
) as {
  request: {
    schema: string;
    deviceId: string;
    hostname: string;
    platform: string;
    architecture: string;
    agentVersion: string;
    agentInstanceId: string;
    deviceKeyFingerprint: string;
    devicePublicKeyPem: string;
    selfClaimedTailnetNodeHash: string;
    requestedTrustState: string;
    tailnet: string;
  };
  deviceSignatureBase64: string;
};
const r = signed.request;
if (
  r.schema !== "radlina.v3.p03.macos-enrollment-request/v1" ||
  r.deviceId !== "macbook-main" ||
  r.hostname !== "amirs-MacBook-Pro.local" ||
  r.platform !== "macos" ||
  r.architecture !== "x64" ||
  r.agentVersion !== "3.0.0-alpha.1" ||
  r.requestedTrustState !== "pending" ||
  r.tailnet !== "rezanory.github" ||
  r.deviceKeyFingerprint !== macPin ||
  r.selfClaimedTailnetNodeHash !== peerPin ||
  ed25519PublicKeyFingerprint(r.devicePublicKeyPem) !== macPin ||
  !verify(
    null,
    Buffer.from(canonicalJson(r)),
    createPublicKey(r.devicePublicKeyPem),
    Buffer.from(signed.deviceSignatureBase64, "base64"),
  )
) {
  throw Error("Mac Ed25519 signed enrollment identity is not pinned or verified");
}
const owner = JSON.parse(
  await readFile(
    "C:\\Users\\Radlina\\AppData\\Local\\Radlina\\V3\\owner-signing\\owner-public-pin.json",
    "utf8",
  ),
) as {
  ownerPrincipal: string;
  ownerSid: string;
  publicKeyPem: string;
  fingerprint: string;
};
if (
  owner.fingerprint !== ownerPin ||
  owner.ownerPrincipal.toLowerCase() !== "laptop-13qineif\\radlina" ||
  owner.ownerSid !== "S-1-5-21-827254616-2815314212-688626134-1001" ||
  ed25519PublicKeyFingerprint(owner.publicKeyPem) !== ownerPin
) {
  throw Error("independent owner key is not pinned");
}
function livePeerHash(): string | undefined {
  const s = JSON.parse(
    execFileSync("C:\\Program Files\\Tailscale\\tailscale.exe", ["status", "--json"], {
      encoding: "utf8",
      timeout: 12000,
      maxBuffer: 4194304,
      windowsHide: true,
    }),
  ) as {
    BackendState?: string;
    CurrentTailnet?: { Name?: string };
    Peer?: Record<string, { ID?: string; OS?: string; Online?: boolean; DNSName?: string }>;
  };
  const p = Object.values(s.Peer ?? {}).filter(
    (x) =>
      x.OS === "macOS" &&
      x.Online === true &&
      x.DNSName?.replace(/\.$/u, "").toLowerCase() === "amirs-macbook-pro.taile17c9e.ts.net",
  );
  if (
    s.BackendState !== "Running" ||
    s.CurrentTailnet?.Name !== "rezanory.github" ||
    p.length !== 1 ||
    !p[0]?.ID
  )
    return undefined;
  return createHash("sha256").update(p[0].ID).digest("hex");
}
if (livePeerHash() !== peerPin)
  throw Error("live Windows-observed Mac Tailnet identity mismatched");
const db = new SqliteDeviceRegistry("E:\\radlina-v3-oauth-standalone\\v3-devices.sqlite3");
try {
  const current = db.require("macbook-main");
  if (
    current.trustState !== "pending" ||
    current.capabilities.length !== 0 ||
    current.hostname !== r.hostname ||
    current.platform !== "macos"
  ) {
    throw Error("Mac registry must be existing non-routable pending device");
  }
  const auth = new SqliteOwnerPinnedEnrollmentAuthority(db, {
    approvedOwnerPublicKeyPem: owner.publicKeyPem,
    approvedDeviceId: "macbook-main",
    approvedHostname: "amirs-MacBook-Pro.local",
    approvedPlatform: "macos",
    approvedTailnetNodeHash: peerPin,
    observeLivePeerNodeHash: livePeerHash,
  });
  const challenge = auth.stage(
    current,
    {
      deviceId: r.deviceId,
      agentInstanceId: r.agentInstanceId,
      agentVersion: r.agentVersion,
      publicKeyFingerprint: r.deviceKeyFingerprint,
      enrolledAt: new Date().toISOString(),
    },
    r.devicePublicKeyPem,
  );
  const file = path.win32.join(root, "mac-challenge-" + challenge.challengeId + ".json");
  await writeFile(file, canonicalJson(challenge) + "\n", { flag: "wx" });
  process.stdout.write(
    JSON.stringify({
      stage: "REAL_P03_MAC_CHALLENGE_PENDING_DUAL_SIGNATURES",
      challengeId: challenge.challengeId,
      path: file,
      expiresAtMs: challenge.expiresAtMs,
      challengeBase64: Buffer.from(canonicalJson(challenge), "utf8").toString("base64"),
      actualTrust: db.require("macbook-main").trustState,
      ownerKeyTouched: false,
      v2Touched: false,
    }) + "\n",
  );
} finally {
  db.close();
}
