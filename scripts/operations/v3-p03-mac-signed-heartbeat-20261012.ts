import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import { canonicalJson } from "../../src/utils/json.js";
import {
  SqliteOwnerPinnedEnrollmentAuthority,
  ed25519PublicKeyFingerprint,
  signedAgentHeartbeatSchema,
} from "../../src/v3/device/owner-pinned-enrollment.js";
import { SqliteDeviceRegistry } from "../../src/v3/device/registry.js";

const file = process.argv[2];
if (
  process.platform !== "win32" ||
  os.hostname().toLowerCase() !== "laptop-13qineif" ||
  !file ||
  !file.startsWith("E:\\radlina-v3-oauth-standalone\\p03-inbound\\mac-heartbeat-")
) {
  throw Error("Physical Windows and pinned receipt path are required");
}
const macPin = "f2c2e93ff120fbc5122cbb6b5a0b461a072f54bd8d226368c858fd0bd17037ea";
const tailPin = "c7886ac103d4c05907ff8953ae60687d31303146a9b122cb55bff0dc1860bc9c";
const ownerPin = "6259d21211f73fc9d2d7cc0174d9bfdc36424cd456878671ab5683468ca0fe93";
const owner = JSON.parse(
  await readFile(
    "C:\\Users\\Radlina\\AppData\\Local\\Radlina\\V3\\owner-signing\\owner-public-pin.json",
    "utf8",
  ),
) as { publicKeyPem: string; fingerprint: string; ownerPrincipal: string };
if (
  owner.fingerprint !== ownerPin ||
  ed25519PublicKeyFingerprint(owner.publicKeyPem) !== ownerPin ||
  owner.ownerPrincipal.toLowerCase() !== "laptop-13qineif\\radlina"
)
  throw Error("owner pin mismatch");
function liveMacPeer(): string | undefined {
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
if (liveMacPeer() !== tailPin) throw Error("real Mac is not independently visible on Tailnet");
const envelope = JSON.parse(await readFile(file, "utf8")) as {
  schema: string;
  heartbeat: {
    schema: string;
    deviceId: string;
    agentInstanceId: string;
    agentVersion: string;
    signedAtMs: number;
    nonce: string;
    status: string;
    health: string;
    capabilities: string[];
  };
  deviceSignatureBase64: string;
};
if (
  envelope.schema !== "radlina.v3.p03.heartbeat-evidence/v1" ||
  envelope.heartbeat.deviceId !== "macbook-main" ||
  envelope.heartbeat.schema !== "radlina.v3.p03.signed-heartbeat/v1" ||
  envelope.heartbeat.status !== "online" ||
  envelope.heartbeat.health !== "healthy" ||
  envelope.heartbeat.capabilities.length !== 1 ||
  envelope.heartbeat.capabilities[0] !== "device.health" ||
  Math.abs(Date.now() - envelope.heartbeat.signedAtMs) > 120000
) {
  throw Error("Mac heartbeat is stale, not a live device, or has unauthorized capability claims");
}
const registry = new SqliteDeviceRegistry("E:\\radlina-v3-oauth-standalone\\v3-devices.sqlite3");
try {
  const authority = new SqliteOwnerPinnedEnrollmentAuthority(registry, {
    approvedOwnerPublicKeyPem: owner.publicKeyPem,
    approvedDeviceId: "macbook-main",
    approvedHostname: "amirs-MacBook-Pro.local",
    approvedPlatform: "macos",
    approvedTailnetNodeHash: tailPin,
    observeLivePeerNodeHash: liveMacPeer,
  });
  const pinned = authority.trustedIdentity("macbook-main");
  if (
    !pinned ||
    pinned.identity.publicKeyFingerprint !== macPin ||
    pinned.identity.agentInstanceId !== envelope.heartbeat.agentInstanceId
  ) {
    throw Error("Mac trusted Ed25519 identity is not the heartbeat signer");
  }
  const accepted = authority.applySignedHeartbeat(
    signedAgentHeartbeatSchema.parse(envelope.heartbeat),
    envelope.deviceSignatureBase64,
  );
  const chain = authority.auditChain();
  if (
    !chain.valid ||
    accepted.trustState !== "trusted" ||
    accepted.lastSeen !== new Date(envelope.heartbeat.signedAtMs).toISOString()
  ) {
    throw Error("Signed Mac heartbeat failed registry CAS or audit acceptance");
  }
  const result = {
    acceptance: "REAL_MAC_P03_TRUSTED_LIVE_SIGNED_HEARTBEAT_PASS",
    deviceId: "macbook-main",
    trustState: accepted.trustState,
    status: accepted.status,
    health: accepted.health,
    capabilities: accepted.capabilities,
    lastSeen: accepted.lastSeen,
    signatureVerified: true,
    liveTailnetMatched: true,
    auditValid: true,
    persistentRemoteAgentTransportVerified: false,
    executableRoutingEnabledByThisScript: false,
    fullProductionAcceptance: false,
  };
  const target = file.replace(".json", ".receipt.json");
  await writeFile(target, canonicalJson(result) + "\n", { flag: "wx" });
  process.stdout.write(JSON.stringify(result) + "\n");
} finally {
  registry.close();
}
