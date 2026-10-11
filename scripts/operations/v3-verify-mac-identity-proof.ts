import { execFileSync } from "node:child_process";
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { canonicalJson } from "../../src/utils/json.js";
import { ed25519PublicKeyFingerprint } from "../../src/v3/device/owner-pinned-enrollment.js";
import { SqliteDeviceRegistry } from "../../src/v3/device/registry.js";

const reqFile = process.argv[2];
const heartbeatFile = process.argv[3];
if (process.platform !== "win32" || os.hostname().toLowerCase() !== "laptop-13qineif") {
  throw new Error("physical Windows control-plane host required");
}
if (!reqFile || !path.isAbsolute(reqFile)) throw new Error("Mac evidence file must be absolute");
const original = JSON.parse(readFileSync(reqFile, "utf8")) as {
  request: {
    deviceId: string;
    hostname: string;
    platform: string;
    architecture: string;
    agentVersion: string;
    agentInstanceId: string;
    devicePublicKeyPem: string;
    deviceKeyFingerprint: string;
    selfClaimedTailnetNodeHash: string;
    tailnet: string;
    requestedAt: string;
    requestedTrustState: string;
  };
  deviceSignatureBase64: string;
};
const request = original.request;
const pub = createPublicKey(request.devicePublicKeyPem);
const requestSig = Buffer.from(original.deviceSignatureBase64, "base64");
const requestOk =
  requestSig.length === 64 && verify(null, Buffer.from(canonicalJson(request)), pub, requestSig);
const fingerprint = ed25519PublicKeyFingerprint(request.devicePublicKeyPem);
const pinnedTailnet = "c7886ac103d4c05907ff8953ae60687d31303146a9b122cb55bff0dc1860bc9c";
const status = JSON.parse(
  execFileSync("C:\\Program Files\\Tailscale\\tailscale.exe", ["status", "--json"], {
    encoding: "utf8",
    timeout: 15_000,
    maxBuffer: 4 * 1024 * 1024,
  }),
) as {
  BackendState?: string;
  CurrentTailnet?: { Name?: string };
  Peer?: Record<string, { ID?: string; Online?: boolean; OS?: string; DNSName?: string }>;
};
const macCandidates = Object.values(status.Peer ?? {}).filter(
  (peer) =>
    peer.Online &&
    peer.OS === "macOS" &&
    peer.DNSName?.replace(/\.$/u, "").toLowerCase() === "amirs-macbook-pro.taile17c9e.ts.net",
);
const actualTailnet =
  macCandidates.length === 1 && macCandidates[0]?.ID
    ? createHash("sha256").update(macCandidates[0].ID).digest("hex")
    : "";
if (
  !requestOk ||
  fingerprint !== request.deviceKeyFingerprint ||
  request.deviceId !== "macbook-main" ||
  request.hostname !== "amirs-MacBook-Pro.local" ||
  request.platform !== "macos" ||
  request.architecture !== "x64" ||
  request.agentVersion !== "3.0.0-alpha.1" ||
  request.requestedTrustState !== "pending" ||
  request.selfClaimedTailnetNodeHash !== pinnedTailnet ||
  status.BackendState !== "Running" ||
  status.CurrentTailnet?.Name !== "rezanory.github" ||
  actualTailnet !== pinnedTailnet
)
  throw new Error("real Mac signed enrollment request failed independent Windows verification");

const registry = new SqliteDeviceRegistry("E:\\radlina-v3-oauth-standalone\\v3-devices.sqlite3");
try {
  const mac = registry.require("macbook-main");
  const windows = registry.require("windows-main");
  if (
    mac.trustState !== "pending" ||
    windows.trustState !== "pending" ||
    mac.capabilities.length > 0 ||
    windows.capabilities.length > 0
  ) {
    throw new Error("the live V3 registry has unexpected trusted/executable state");
  }
  let signatureHeartbeatValid: boolean | null = null;
  let heartbeatFresh: boolean | null = null;
  let heartbeatNonce: string | null = null;
  if (heartbeatFile) {
    if (!path.isAbsolute(heartbeatFile))
      throw new Error("heartbeat evidence path must be absolute");
    const envelope = JSON.parse(readFileSync(heartbeatFile, "utf8")) as {
      schema: string;
      heartbeat: {
        schema: string;
        deviceId: string;
        agentInstanceId: string;
        agentVersion: string;
        signedAtMs: number;
        status: string;
        health: string;
        capabilities: string[];
        nonce: string;
      };
      deviceSignatureBase64: string;
    };
    const hb = envelope.heartbeat;
    const sig = Buffer.from(envelope.deviceSignatureBase64, "base64");
    signatureHeartbeatValid =
      envelope.schema === "radlina.v3.p03.heartbeat-evidence/v1" &&
      hb.schema === "radlina.v3.p03.signed-heartbeat/v1" &&
      hb.deviceId === "macbook-main" &&
      hb.agentInstanceId === request.agentInstanceId &&
      hb.agentVersion === request.agentVersion &&
      hb.status === "online" &&
      hb.health === "healthy" &&
      hb.capabilities.length === 1 &&
      hb.capabilities[0] === "device.health" &&
      sig.length === 64 &&
      verify(null, Buffer.from(canonicalJson(hb)), pub, sig);
    heartbeatFresh = Math.abs(Date.now() - hb.signedAtMs) <= 120_000;
    heartbeatNonce = hb.nonce;
    if (!signatureHeartbeatValid)
      throw new Error("real Mac heartbeat was not signed by enrolled device identity");
  }
  process.stdout.write(
    JSON.stringify({
      verification: "REAL_MAC_DEVICE_SIGNATURE_VERIFIED_ON_PHYSICAL_WINDOWS",
      realMacRequestEd25519Verified: requestOk,
      publicKeyFingerprint: fingerprint,
      independentlyObservedTailnetHash: actualTailnet,
      signedHeartbeatVerified: signatureHeartbeatValid,
      signedHeartbeatFresh: heartbeatFresh,
      heartbeatNoncePresent: !!heartbeatNonce,
      authoritativeV3RegistryDeviceCount: registry.list().length,
      actualRegistryMacTrust: mac.trustState,
      actualRegistryWindowsTrust: windows.trustState,
      p03TrustedAdmission: "NOT_COMPLETED_REQUIRES_INDEPENDENT_OWNER_SIGNATURE",
      p06RouteEnabled: false,
      f01RealCanaryRollbackEnabled: false,
      v2Modified: false,
    }) + "\n",
  );
} finally {
  registry.close();
}
