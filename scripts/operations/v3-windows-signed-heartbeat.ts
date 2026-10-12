/**
 * V3 Windows physical signed heartbeat, fail-closed and service-safe.
 * This asserts Windows is alive; health remains DEGRADED until P06/S02E/S03
 * and true two-device execution pass. Nothing here grants file/remote execution.
 */
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import os from "node:os";

import { sha256 } from "../../src/utils/json.js";
import {
  ed25519PublicKeyFingerprint,
  SqliteOwnerPinnedEnrollmentAuthority,
} from "../../src/v3/device/owner-pinned-enrollment.js";
import { SqliteDeviceRegistry } from "../../src/v3/device/registry.js";
import { WindowsProtectedDeviceIdentity } from "../../src/v3/device/windows-protected-identity.js";

const ROOT = "E:\\radlina-v3-runtime";
const DATABASE = "E:\\radlina-v3-oauth-standalone\\v3-devices.sqlite3";
const PIN_PATH =
  "C:\\Users\\Radlina\\AppData\\Local\\Radlina\\V3\\owner-signing\\owner-public-pin.json";
const PINNED_OWNER = "6259d21211f73fc9d2d7cc0174d9bfdc36424cd456878671ab5683468ca0fe93";
const PINNED_DEVICE = "fafcea842b3d0142b9cb24ff05455a09da409d44e7d08a483b39bb0596a7f5a0";
const MODE = process.argv[2] ?? "--once";

if (!["--once", "--daemon"].includes(MODE) || process.argv.length > 3) {
  throw new Error("V3 signed Windows heartbeat accepts only --once or --daemon");
}
if (process.platform !== "win32" || os.hostname().toLowerCase() !== "laptop-13qineif") {
  throw new Error("exact enrolled Windows host required");
}
const ownerPin = JSON.parse(await readFile(PIN_PATH, "utf8")) as {
  ownerPrincipal: string;
  ownerSid: string;
  publicKeyPem: string;
  fingerprint: string;
};
if (
  ownerPin.ownerPrincipal.toLowerCase() !== "laptop-13qineif\\radlina" ||
  ownerPin.ownerSid !== "S-1-5-21-827254616-2815314212-688626134-1001" ||
  ownerPin.fingerprint !== PINNED_OWNER ||
  ed25519PublicKeyFingerprint(ownerPin.publicKeyPem) !== PINNED_OWNER
) {
  throw new Error("independent owner Ed25519 pin mismatch");
}

function observeLiveWindowsNodeHash(): string {
  const status = JSON.parse(
    execFileSync("C:\\Program Files\\Tailscale\\tailscale.exe", ["status", "--json"], {
      encoding: "utf8",
      timeout: 12_000,
      windowsHide: true,
    }),
  ) as {
    BackendState?: string;
    CurrentTailnet?: { Name?: string };
    Self?: { ID?: string; OS?: string; DNSName?: string; Online?: boolean };
  };
  if (
    status.BackendState !== "Running" ||
    status.CurrentTailnet?.Name !== "rezanory.github" ||
    status.Self?.OS !== "windows" ||
    !status.Self.ID ||
    status.Self.Online !== true ||
    status.Self.DNSName?.replace(/\.$/u, "").toLowerCase() !== "laptop-13qineif.taile17c9e.ts.net"
  ) {
    throw new Error("independently verified live Windows tailnet identity missing");
  }
  return sha256(status.Self.ID);
}

const device = await WindowsProtectedDeviceIdentity.open(ROOT + "\\windows-device-identity");
const identity = device.publicIdentity();
if (identity.fingerprint !== PINNED_DEVICE || identity.deviceId !== "windows-main") {
  throw new Error("protected Windows signing key is not enrolled device");
}
const registry = new SqliteDeviceRegistry(DATABASE);
const networkPin = observeLiveWindowsNodeHash();
const authority = new SqliteOwnerPinnedEnrollmentAuthority(registry, {
  approvedOwnerPublicKeyPem: ownerPin.publicKeyPem,
  approvedDeviceId: "windows-main",
  approvedHostname: "LAPTOP-13QINEIF",
  approvedPlatform: "windows",
  approvedTailnetNodeHash: networkPin,
  observeLivePeerNodeHash: observeLiveWindowsNodeHash,
});
const trusted = authority.trustedIdentity("windows-main");
if (
  !trusted ||
  trusted.identity.agentInstanceId !== identity.agentInstanceId ||
  trusted.identity.publicKeyFingerprint !== PINNED_DEVICE ||
  trusted.tailnetNodeHash !== networkPin
) {
  registry.close();
  throw new Error("persisted signed P03 device enrollment does not match protected key");
}

let closing = false;
process.once("SIGTERM", () => {
  closing = true;
});
process.once("SIGINT", () => {
  closing = true;
});

async function localServiceHealthy(): Promise<boolean> {
  try {
    const [auth, mcp, metadata] = await Promise.all([
      fetch("http://127.0.0.1:7344/auth-health", {
        signal: AbortSignal.timeout(4_000),
      }),
      fetch("http://127.0.0.1:7344/mcp", {
        method: "POST",
        signal: AbortSignal.timeout(4_000),
      }),
      fetch("http://127.0.0.1:7344/.well-known/oauth-authorization-server", {
        signal: AbortSignal.timeout(4_000),
      }),
    ]);
    if (!auth.ok || mcp.status !== 401 || !metadata.ok) return false;
    const health = (await auth.json()) as { status?: string };
    const discovery = (await metadata.json()) as { scopes_supported?: string[] };
    return (
      health.status === "healthy" &&
      discovery.scopes_supported?.includes("filesystem:write") === true
    );
  } catch {
    return false;
  }
}

async function tick(): Promise<void> {
  // The signed status can be online if the actual pinned agent is running.
  // Health deliberately remains degraded: no authenticated P06 cross-device transport,
  // target-local S02E consent or S03 external audit has been admitted.
  const localReady = await localServiceHealthy();
  const signed = device.heartbeat(localReady ? "online" : "degraded", "degraded");
  const before = authority.latestSignedHeartbeatMs("windows-main");
  const accepted = authority.applySignedHeartbeat(signed.heartbeat, signed.deviceSignatureBase64);
  if (
    accepted.trustState !== "trusted" ||
    accepted.health !== "degraded" ||
    accepted.lastSeen !== new Date(signed.heartbeat.signedAtMs).toISOString() ||
    (before !== null && signed.heartbeat.signedAtMs <= before) ||
    !authority.auditChain().valid
  ) {
    throw new Error("signed P03 Windows heartbeat acceptance or audit chain invalid");
  }
  process.stdout.write(
    JSON.stringify({
      result: "REAL_P03_WINDOWS_SIGNED_LIVE_HEARTBEAT",
      mode: MODE,
      deviceId: accepted.deviceId,
      localServiceHealthy: localReady,
      status: accepted.status,
      health: accepted.health,
      trust: accepted.trustState,
      signedAt: accepted.lastSeen,
      auditValid: true,
      heartbeatNonce: signed.heartbeat.nonce,
      ownerKeyExported: false,
      remoteExecutionEnabledByThisJob: false,
      productionAcceptance: "PENDING_CROSS_DEVICE",
    }) + "\n",
  );
}

try {
  while (!closing) {
    try {
      await tick();
    } catch (error) {
      process.stderr.write(
        JSON.stringify({
          heartbeat: "FAILED_CLOSED",
          error: error instanceof Error ? error.message : "unknown",
          diagnosticId: randomUUID(),
        }) + "\n",
      );
      if (MODE === "--once") throw error;
    }
    if (MODE === "--once") break;
    const until = Date.now() + 45_000;
    while (!closing && Date.now() < until) {
      await new Promise<void>((resolve) => setTimeout(resolve, 1_000));
    }
  }
} finally {
  registry.close();
}
