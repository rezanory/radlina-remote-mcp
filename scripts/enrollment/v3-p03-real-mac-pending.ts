import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import * as z from "zod/v4";

import { DeviceRouter } from "../../src/v3/device/router.js";
import { parseDeviceDescriptor } from "../../src/v3/device/identity.js";
import { SqliteDeviceRegistry } from "../../src/v3/device/registry.js";

const pinnedEvidenceSchema = z.object({
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
    physicalMacTypecheck: z.literal("PASS"),
    nativeDeviceHealthExecution: z.literal("PASS"),
  }),
  officialAcceptance: z.object({
    liveP03ApprovedTrustedEnrollment: z.literal("NOT_PROVEN"),
  }),
});

if (process.platform !== "win32") throw new Error("real Windows peer inventory is required");
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const evidence = pinnedEvidenceSchema.parse(
  JSON.parse(
    readFileSync(
      path.join(root, "governance/v3/validation/V3_P08_PHYSICAL_MAC_READINESS_PASS_20261011.json"),
      "utf8",
    ),
  ),
);

const approvedDirectory = process.env["RADLINA_V3_BETA_STATE_DIRECTORY"];
if (
  !approvedDirectory ||
  !path.isAbsolute(approvedDirectory) ||
  path.basename(path.normalize(approvedDirectory)).toLowerCase() !== "v3betastandalone"
) {
  throw new Error("explicit isolated V3BetaStandalone state directory required");
}
if (path.normalize(approvedDirectory).toLowerCase().includes("v2")) {
  throw new Error("V2 runtime storage must not be touched");
}

const status = JSON.parse(
  execFileSync("C:\\Program Files\\Tailscale\\tailscale.exe", ["status", "--json"], {
    encoding: "utf8",
    timeout: 20_000,
    maxBuffer: 4 * 1024 * 1024,
  }),
) as {
  BackendState?: string;
  CurrentTailnet?: { Name?: string };
  Peer?: Record<
    string,
    {
      ID?: string;
      OS?: string;
      Online?: boolean;
      DNSName?: string;
    }
  >;
};
const observed = Object.values(status.Peer ?? {}).find(
  (peer) =>
    peer.OS === "macOS" &&
    peer.DNSName?.replace(/\.$/u, "").toLowerCase() === "amirs-macbook-pro.taile17c9e.ts.net",
);
const fingerprint = observed?.ID ? createHash("sha256").update(observed.ID).digest("hex") : "";

if (
  status.BackendState !== "Running" ||
  status.CurrentTailnet?.Name !== evidence.actualMacBook.tailnet ||
  !observed?.Online ||
  fingerprint !== evidence.actualMacBook.nodeIdFingerprintSha256
) {
  throw new Error("MacBook live Tailscale identity does not match pinned owner evidence");
}

const dbFile = path.join(approvedDirectory, "v3-beta-devices.sqlite3");
const registry = new SqliteDeviceRegistry(dbFile);
try {
  const description = parseDeviceDescriptor({
    deviceId: "macbook-main",
    hostname: evidence.actualMacBook.hostname,
    platform: "macos",
    architecture: evidence.actualMacBook.architecture,
    agentVersion: "3.0.0-alpha.1",
    status: "unknown",
    lastSeen: new Date().toISOString(),
    capabilities: [],
    tags: [],
    trustState: "pending",
    health: "unknown",
  });
  const outcome = registry.register(description);
  const current = registry.require("macbook-main");
  if (
    current.trustState !== "pending" ||
    current.capabilities.length !== 0 ||
    current.health !== "unknown"
  ) {
    throw new Error("P03 MacBook Pending registration became executable or trusted");
  }
  let routeDenied = false;
  try {
    new DeviceRouter(registry).route({ deviceId: "macbook-main" }, "device.health");
  } catch (error) {
    routeDenied = error instanceof Error && /will not fail over/u.test(error.message);
  }
  if (!routeDenied) throw new Error("P06 must fail closed for pending MacBook");
  process.stdout.write(
    JSON.stringify({
      input: {
        deviceId: "macbook-main",
        evidenceCommit: "765072304d49108858f9ec7cfea87d9c8f4c1f3d",
        evidenceJob: 38091109343,
      },
      runtime: {
        physicalWindowsHost: "LAPTOP-13QINEIF",
        liveTailnet: status.CurrentTailnet.Name,
        liveMacNodeFingerprint: fingerprint,
        registry: "independent V3 SQLite WAL",
      },
      execution: {
        alreadyRegistered: outcome.replayed,
        finalTrustState: current.trustState,
        finalHealth: current.health,
        agentCapabilitiesEnabled: current.capabilities.length,
        exactDeviceRouteDenied: routeDenied,
      },
      output: {
        physicalMacPendingRecord: true,
        registryDeviceCount: registry.list().length,
        v2RuntimeTouched: false,
      },
      acceptance: "REAL_MAC_P03_PENDING_ONLY_PASS",
      productionAcceptance: "PENDING_SIGNED_DEVICE_AND_OWNER_APPROVAL_PLUS_LIVE_CONSENT",
    }) + "\n",
  );
} finally {
  registry.close();
}
