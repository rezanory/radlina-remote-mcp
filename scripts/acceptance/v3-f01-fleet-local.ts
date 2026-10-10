import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  type FleetAttestation,
  type FleetDeviceAgentPort,
  type FleetReceiptVerifierPort,
} from "../../src/v3/fleet/contracts.js";
import { V3FleetController } from "../../src/v3/fleet/controller.js";
import { SqliteFleetStore } from "../../src/v3/fleet/store.js";

const previous = "b".repeat(64);
const target = "a".repeat(64);
const signedHashFixture = "c".repeat(64);
const devices = ["macbook-main", "windows-main"] as const;
const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-f01-port-acceptance-"));
const store = new SqliteFleetStore(path.join(root, "fleet.sqlite3"));
const state = new Map<string, string>(devices.map((id) => [id, previous]));
const stages: string[] = [];
const consentChecks: string[] = [];

const devicePorts: FleetDeviceAgentPort = {
  preflight: async (deviceId, targetManifest, rollbackManifest): Promise<FleetAttestation> => {
    stages.push(`preflight:${deviceId}`);
    return {
      deviceId,
      previousManifestSha256: state.get(deviceId)!,
      stagedTargetVerified: targetManifest === target,
      stagedRollbackVerified: rollbackManifest === previous,
      identityVerified: true,
      consentSupported: true,
      health: "healthy",
      evidenceSha256: signedHashFixture,
    };
  },
  activate: async (deviceId, manifest) => {
    stages.push(`activate:${deviceId}`);
    const current = state.get(deviceId)!;
    state.set(deviceId, manifest);
    return {
      deviceId,
      previousManifestSha256: current,
      activeManifestSha256: manifest,
      deviceReceiptHash: signedHashFixture,
      identityVerified: true,
    };
  },
  verify: async (deviceId) => {
    stages.push(`verify:${deviceId}`);
    return {
      deviceId,
      activeManifestSha256: state.get(deviceId)!,
      health: "healthy",
      deviceReceiptHash: signedHashFixture,
      identityVerified: true,
    };
  },
  rollback: async (deviceId, manifest) => {
    stages.push(`rollback:${deviceId}`);
    const current = state.get(deviceId)!;
    state.set(deviceId, manifest);
    return {
      deviceId,
      previousManifestSha256: current,
      activeManifestSha256: manifest,
      deviceReceiptHash: signedHashFixture,
      identityVerified: true,
    };
  },
};

const evidence: FleetReceiptVerifierPort = {
  verifyPreflight: async () => true, // Only synthetic acceptance. Do not use in production.
  verifySwitch: async () => true,
  verifyHealth: async () => true,
};

const controller = new V3FleetController(
  store,
  {
    get: (id) =>
      devices.includes(id as (typeof devices)[number])
        ? { deviceId: id, trustState: "trusted", status: "online", health: "healthy" }
        : undefined,
  },
  devicePorts,
  {
    assertOwner: async (subject) => {
      if (subject !== "synthetic-test-owner") throw Error("owner proof mismatch");
    },
  },
  {
    require: async (id, operation) => {
      consentChecks.push(`${operation}:${id}`);
      if (!devices.includes(id as (typeof devices)[number])) throw Error("recipient mismatch");
    },
  },
  evidence,
);

try {
  const planId = randomUUID();
  await controller.plan({
    planId,
    idempotencyKey: randomUUID(),
    ownerSubject: "synthetic-test-owner",
    canaryDeviceId: "macbook-main",
    targetDeviceIds: [...devices],
    rollbackManifestSha256: previous,
    targetManifestSha256: target,
    createdAtMs: Date.now(),
  });
  const outcome = await controller.run(planId, "synthetic-test-owner");
  let replayRejected = false;
  try {
    await controller.run(planId, "synthetic-test-owner");
  } catch {
    replayRejected = true;
  }
  const audit = store.verifyAuditChain();
  const preflightBeforeActivation =
    stages.indexOf("preflight:windows-main") < stages.indexOf("activate:macbook-main");
  const canaryBeforeOthers =
    stages.indexOf("activate:macbook-main") < stages.indexOf("activate:windows-main");
  const consentChecked = consentChecks.length >= 6;
  const acceptance =
    outcome.state === "complete" &&
    replayRejected &&
    audit.valid &&
    preflightBeforeActivation &&
    canaryBeforeOthers &&
    consentChecked &&
    [...devices].every((id) => state.get(id) === target);
  process.stdout.write(
    JSON.stringify({
      input: { targetDevices: [...devices], canary: "macbook-main", targetRelease: target },
      runtime: {
        journal: "real SQLite WAL",
        algorithm: "F01 state machine",
        devicePorts: "synthetic/isolated",
      },
      execution: {
        steps: stages,
        consentChecks,
        replayRejected,
        preflightBeforeActivation,
        canaryBeforeOthers,
      },
      output: { state: outcome.state, eventCount: audit.events, auditChainValid: audit.valid },
      acceptance: acceptance ? "LOCAL_SIMULATED_F01_PASS" : "FAIL",
      productionAcceptance: "NOT_GRANTED_P08_REAL_MACBOOK_AND_SIGNED_PORTS_REQUIRED",
    }) + "\n",
  );
  if (!acceptance) process.exitCode = 1;
} finally {
  store.close();
  await rm(root, { recursive: true, force: true });
}
