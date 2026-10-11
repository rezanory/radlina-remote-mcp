import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import * as z from "zod/v4";

import { SqliteDeviceRegistry } from "../../src/v3/device/registry.js";
import { parseDeviceDescriptor } from "../../src/v3/device/identity.js";
import { DeviceRouter, DeviceRoutingError } from "../../src/v3/device/router.js";

const physicalMacEvidence = z.object({
  status: z.literal("REAL_PHYSICAL_MACBOOK_READINESS_PASS_NOT_PRODUCTION_ACCEPTANCE"),
  actualMacBook: z.object({
    logicalDeviceId: z.literal("macbook-main"),
    hostname: z.literal("amirs-MacBook-Pro.local"),
    architecture: z.literal("x64"),
    tailnet: z.literal("rezanory.github"),
    nodeIdFingerprintSha256: z.string().regex(/^[0-9a-f]{64}$/u),
  }),
  actualGitHubRunnerJobs: z.object({
    relay_aware_readiness: z.object({ status: z.literal("PASS_ALL_TEN_GUARDS") }),
  }),
  operational: z.object({
    identityGuard: z.object({ passed: z.literal(10), total: z.literal(10) }),
    nativeDeviceHealthExecution: z.literal("PASS"),
  }),
  officialAcceptance: z.object({
    liveP03ApprovedTrustedEnrollment: z.literal("NOT_PROVEN"),
  }),
});

type TailscaleStatus = {
  BackendState?: string;
  CurrentTailnet?: { Name?: string };
  Self?: { ID?: string; Online?: boolean; OS?: string; HostName?: string };
  Peer?: Record<string, { ID?: string; OS?: string; Online?: boolean; DNSName?: string }>;
};

if (process.platform !== "win32" || os.hostname().toLowerCase() !== "laptop-13qineif") {
  throw new Error("the actual approved Windows control host is required");
}
const stateRoot = path.resolve("E:\\radlina-v3-oauth-standalone");
const registryFile = path.join(stateRoot, "v3-devices.sqlite3");
if (!statSync(registryFile).isFile() || stateRoot.toLowerCase().includes("v2")) {
  throw new Error("the existing live isolated V3 OAuth registry is required");
}
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const evidence = physicalMacEvidence.parse(
  JSON.parse(
    readFileSync(
      path.join(root, "governance/v3/validation/V3_P08_PHYSICAL_MAC_READINESS_PASS_20261011.json"),
      "utf8",
    ),
  ),
);

const tailscale = JSON.parse(
  execFileSync("C:\\Program Files\\Tailscale\\tailscale.exe", ["status", "--json"], {
    encoding: "utf8",
    timeout: 15_000,
    maxBuffer: 4 * 1024 * 1024,
  }),
) as TailscaleStatus;
const peerCandidates = Object.values(tailscale.Peer ?? {}).filter(
  (peer) =>
    peer.OS === "macOS" &&
    peer.DNSName?.replace(/\.$/u, "").toLowerCase() === "amirs-macbook-pro.taile17c9e.ts.net",
);
if (
  tailscale.BackendState !== "Running" ||
  tailscale.CurrentTailnet?.Name !== "rezanory.github" ||
  !tailscale.Self?.Online ||
  !tailscale.Self.ID ||
  peerCandidates.length !== 1 ||
  !peerCandidates[0]?.Online ||
  !peerCandidates[0].ID
) {
  throw new Error("live Windows/Mac Tailnet peer validation failed");
}
const observedMacFingerprint = createHash("sha256").update(peerCandidates[0].ID).digest("hex");
if (observedMacFingerprint !== evidence.actualMacBook.nodeIdFingerprintSha256) {
  throw new Error("the physical Mac peer identity differs from pinned P08 evidence");
}

const now = new Date().toISOString();
const pending = [
  parseDeviceDescriptor({
    deviceId: "macbook-main",
    hostname: evidence.actualMacBook.hostname,
    platform: "macos",
    architecture: evidence.actualMacBook.architecture,
    agentVersion: "3.0.0-alpha.1",
    status: "unknown",
    lastSeen: now,
    capabilities: [],
    tags: [],
    trustState: "pending",
    health: "unknown",
  }),
  parseDeviceDescriptor({
    deviceId: "windows-main",
    hostname: os.hostname(),
    platform: "windows",
    architecture: process.arch === "x64" ? "x64" : "unknown",
    agentVersion: "3.0.0-alpha.1",
    status: "unknown",
    lastSeen: now,
    capabilities: [],
    tags: [],
    trustState: "pending",
    health: "unknown",
  }),
];
const registry = new SqliteDeviceRegistry(registryFile);
try {
  // Check every existing record and all required inputs BEFORE modifying either row.
  const existingRows = registry.list();
  if (existingRows.some((row) => !pending.some((p) => p.deviceId === row.deviceId))) {
    throw new Error("unrecognized live registry entries; operator review required");
  }
  for (const device of pending) {
    const existing = registry.get(device.deviceId);
    if (
      existing &&
      (existing.trustState !== "pending" ||
        existing.hostname !== device.hostname ||
        existing.platform !== device.platform ||
        existing.architecture !== device.architecture ||
        existing.capabilities.length !== 0 ||
        existing.status !== "unknown" ||
        existing.health !== "unknown")
    ) {
      throw new Error("existing device is non-pending or changed: refuse to alter trust");
    }
  }

  registry.db.exec("BEGIN IMMEDIATE");
  let registration;
  try {
    registration = pending.map((device) => ({
      id: device.deviceId,
      replayed: registry.register(device).replayed,
    }));
    registry.db.exec("COMMIT");
  } catch (error) {
    registry.db.exec("ROLLBACK");
    throw error;
  }

  // No trust-state shortcut: both devices remain non-routable until the
  // independently pinned device and owner signatures plus signed live heartbeats exist.
  const router = new DeviceRouter(registry);
  const results = pending.map(({ deviceId }) => {
    const device = registry.require(deviceId);
    let exactDenied = false;
    try {
      router.route({ deviceId }, "device.health");
    } catch (error) {
      exactDenied =
        error instanceof DeviceRoutingError &&
        /not eligible and will not fail over/u.test(error.message);
    }
    if (
      device.trustState !== "pending" ||
      device.status !== "unknown" ||
      device.health !== "unknown" ||
      device.capabilities.length !== 0 ||
      !exactDenied
    ) {
      throw new Error("registration or P06 deny-by-default failed for " + deviceId);
    }
    return {
      deviceId,
      trustState: device.trustState,
      health: device.health,
      capabilities: device.capabilities.length,
      exactRouteDenied: exactDenied,
    };
  });

  let dynamicDenied = false;
  try {
    router.route({}, "device.health");
  } catch (error) {
    dynamicDenied =
      error instanceof DeviceRoutingError && /no eligible device/u.test(error.message);
  }
  if (!dynamicDenied) throw new Error("selector routing was not denied for pending devices");

  process.stdout.write(
    JSON.stringify({
      schema: "radlina.v3.p03.physical-pending-discovery/v1",
      input: {
        macPhysicalEvidence: "P08-10/10",
        windowsHost: os.hostname(),
        tailnet: tailscale.CurrentTailnet.Name,
        liveMacPeerMatchesPinnedEvidence: true,
      },
      runtime: {
        state: "independent live V3 OAuth registry",
        connectedDevicesDiscovered: 2,
      },
      execution: { registrations: registration, exactRoutes: results, dynamicRouteDenied: true },
      output: { actualV3RegistryRecords: registry.list().length, changesToV2: false },
      acceptance: "REAL_TWO_DEVICE_P03_PENDING_REGISTRATION_ONLY",
      missing: [
        "physical Mac public key and challenge signature verified by P03",
        "independent owner signature over P03 enrollment challenge",
        "trusted Windows agent key attestation",
        "fresh signed heartbeats",
        "target-local S02E consent and external S03 audit",
        "two-host F01 live canary and rollback",
      ],
      officialPercent: 85.71,
    }) + "\n",
  );
} finally {
  registry.close();
}
