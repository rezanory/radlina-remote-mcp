/**
 * Real Windows verification of the physical Mac Keychain-signed P03 request.
 * Read-only: never auto-trusts a device or grants P06 execution.
 */
import { execFileSync } from "node:child_process";
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import os from "node:os";

import { canonicalJson } from "../../src/utils/json.js";
import { SqliteDeviceRegistry } from "../../src/v3/device/registry.js";
import { ed25519PublicKeyFingerprint } from "../../src/v3/device/owner-pinned-enrollment.js";

const proofPath = "E:\\radlina-v3-oauth-standalone\\p03-inbound\\mac-ensure-38189747769.json";
const macKeyPin = "f2c2e93ff120fbc5122cbb6b5a0b461a072f54bd8d226368c858fd0bd17037ea";
const macNetworkPin = "c7886ac103d4c05907ff8953ae60687d31303146a9b122cb55bff0dc1860bc9c";
if (process.platform !== "win32" || os.hostname().toLowerCase() !== "laptop-13qineif") {
  throw new Error("independent physical Windows verifier required");
}
const envelope = JSON.parse(await readFile(proofPath, "utf8")) as {
  deviceSignatureBase64: string;
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
    requestedAt: string;
    requestedTrustState: string;
    tailnet: string;
    tailscaleDnsName: string;
  };
};
const request = envelope.request;
const pub = createPublicKey(request.devicePublicKeyPem);
const proof = Buffer.from(envelope.deviceSignatureBase64, "base64");
const signed = proof.length === 64 && verify(null, Buffer.from(canonicalJson(request)), pub, proof);
const tailnet = JSON.parse(
  execFileSync("C:\\Program Files\\Tailscale\\tailscale.exe", ["status", "--json"], {
    encoding: "utf8",
    timeout: 15000,
    maxBuffer: 4 * 1024 * 1024,
    windowsHide: true,
  }),
) as {
  BackendState?: string;
  CurrentTailnet?: { Name?: string };
  Peer?: Record<string, { ID?: string; OS?: string; Online?: boolean; DNSName?: string }>;
};
const peers = Object.values(tailnet.Peer ?? {}).filter(
  (p) =>
    p.OS === "macOS" &&
    p.Online === true &&
    p.DNSName?.replace(/\.$/u, "").toLowerCase() === "amirs-macbook-pro.taile17c9e.ts.net",
);
const observed =
  peers.length === 1 && peers[0]?.ID ? createHash("sha256").update(peers[0].ID).digest("hex") : "";
if (
  !signed ||
  ed25519PublicKeyFingerprint(request.devicePublicKeyPem) !== macKeyPin ||
  request.deviceKeyFingerprint !== macKeyPin ||
  request.selfClaimedTailnetNodeHash !== macNetworkPin ||
  request.deviceId !== "macbook-main" ||
  request.hostname !== "amirs-MacBook-Pro.local" ||
  request.platform !== "macos" ||
  request.architecture !== "x64" ||
  request.agentVersion !== "3.0.0-alpha.1" ||
  request.requestedTrustState !== "pending" ||
  request.tailnet !== "rezanory.github" ||
  tailnet.BackendState !== "Running" ||
  tailnet.CurrentTailnet?.Name !== "rezanory.github" ||
  observed !== macNetworkPin
) {
  throw new Error(
    "P03 real Mac public signature or independently observed live Tailnet pin mismatch",
  );
}
const registry = new SqliteDeviceRegistry("E:\\radlina-v3-oauth-standalone\\v3-devices.sqlite3");
try {
  const mac = registry.require("macbook-main");
  const windows = registry.require("windows-main");
  if (
    mac.trustState !== "pending" ||
    mac.capabilities.length !== 0 ||
    windows.trustState !== "trusted"
  ) {
    throw new Error("unexpected actual device-trust state; no trust transition attempted");
  }
  process.stdout.write(
    JSON.stringify({
      proof: "REAL_MAC_KEYCHAIN_SIGNATURE_AND_WINDOWS_TAILNET_PASS",
      checkedFrom: os.hostname(),
      deviceId: request.deviceId,
      agentInstanceId: request.agentInstanceId,
      fingerprint: macKeyPin,
      deviceSignatureValid: true,
      independentlyObservedMacOnline: true,
      tailnetMatch: true,
      actualRegistryMacTrust: mac.trustState,
      actualRegistryWindowsTrust: windows.trustState,
      privateKeysAccessed: false,
      trustedAdmission: false,
      executionEnabled: false,
    }) + "\n",
  );
} finally {
  registry.close();
}
