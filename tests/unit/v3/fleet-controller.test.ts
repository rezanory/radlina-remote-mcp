import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  fleetPlanSchema,
  type FleetDeviceAgentPort,
  type FleetDeviceReader,
  type FleetOwnershipAuthority,
  type FleetPlan,
  type FleetReceiptVerifierPort,
  type FleetRecipientConsentPort,
  type FleetOperation,
} from "../../../src/v3/fleet/contracts.js";
import { V3FleetController } from "../../../src/v3/fleet/controller.js";
import { FleetStoreConflict, SqliteFleetStore } from "../../../src/v3/fleet/store.js";

const TARGET = "a".repeat(64);
const PREVIOUS = "b".repeat(64);
const RECEIPT = "c".repeat(64);
const roots: string[] = [];
const stores: SqliteFleetStore[] = [];

const plan = (overrides: Partial<FleetPlan> = {}): FleetPlan =>
  fleetPlanSchema.parse({
    planId: randomUUID(),
    idempotencyKey: randomUUID(),
    ownerSubject: "approved-operator",
    targetManifestSha256: TARGET,
    rollbackManifestSha256: PREVIOUS,
    targetDeviceIds: ["windows-main", "macbook-main"],
    canaryDeviceId: "macbook-main",
    createdAtMs: Date.now(),
    ...overrides,
  });

async function harness() {
  const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-f01-"));
  roots.push(root);
  const store = new SqliteFleetStore(path.join(root, "fleet.sqlite3"));
  stores.push(store);

  const state = new Map<string, string>([
    ["windows-main", PREVIOUS],
    ["macbook-main", PREVIOUS],
  ]);
  const trust = new Map([
    [
      "windows-main",
      { deviceId: "windows-main", trustState: "trusted", status: "online", health: "healthy" },
    ],
    [
      "macbook-main",
      { deviceId: "macbook-main", trustState: "trusted", status: "online", health: "healthy" },
    ],
  ]);
  const events: string[] = [];
  let noOwner = false;
  let deniedConsent: string | undefined;
  let preflightBadDevice: string | undefined;
  let badSwitchDevice: string | undefined;
  let badHealthDevice: string | undefined;
  let failActivateDevice: string | undefined;
  let failRollbackDevice: string | undefined;
  let badSignature = false;

  const devices: FleetDeviceReader = { get: (id) => trust.get(id) };
  const owner: FleetOwnershipAuthority = {
    assertOwner: async (subject, operation) => {
      events.push(`owner:${operation}`);
      if (subject !== "approved-operator" || noOwner) throw Error("owner authorization denied");
    },
  };
  const consent: FleetRecipientConsentPort = {
    require: async (id, operation: FleetOperation) => {
      events.push(`consent:${operation}:${id}`);
      if (deniedConsent === `${operation}:${id}`) throw Error("recipient consent missing");
    },
  };
  const agent: FleetDeviceAgentPort = {
    preflight: async (id) => {
      events.push(`preflight:${id}`);
      return {
        deviceId: id,
        previousManifestSha256: state.get(id)!,
        stagedTargetVerified: true,
        stagedRollbackVerified: true,
        identityVerified: preflightBadDevice !== id,
        consentSupported: true,
        health: "healthy",
        evidenceSha256: RECEIPT,
      };
    },
    activate: async (id, hash) => {
      events.push(`activate:${id}`);
      if (failActivateDevice === id) throw Error("unknown outcome after activation request");
      const prior = state.get(id)!;
      state.set(id, hash);
      return {
        deviceId: id,
        previousManifestSha256: prior,
        activeManifestSha256: hash,
        deviceReceiptHash: RECEIPT,
        identityVerified: badSwitchDevice !== id || hash === PREVIOUS,
      };
    },
    verify: async (id) => {
      events.push(`verify:${id}`);
      return {
        deviceId: id,
        activeManifestSha256: state.get(id)!,
        health: badHealthDevice === id ? "unhealthy" : "healthy",
        deviceReceiptHash: RECEIPT,
        identityVerified: true,
      };
    },
    rollback: async (id, to) => {
      events.push(`rollback:${id}`);
      if (failRollbackDevice === id) throw Error("recipient not able to rollback");
      const before = state.get(id)!;
      state.set(id, to);
      return {
        deviceId: id,
        previousManifestSha256: before,
        activeManifestSha256: to,
        deviceReceiptHash: RECEIPT,
        identityVerified: true,
      };
    },
  };
  const evidence: FleetReceiptVerifierPort = {
    verifyPreflight: async () => !badSignature,
    verifySwitch: async () => !badSignature,
    verifyHealth: async () => !badSignature,
  };
  const control = new V3FleetController(store, devices, agent, owner, consent, evidence);
  return {
    root,
    store,
    control,
    events,
    state,
    trust,
    denyOwner: () => {
      noOwner = true;
    },
    denyConsent: (value: string) => {
      deniedConsent = value;
    },
    invalidatePreflight: (id: string) => {
      preflightBadDevice = id;
    },
    invalidateSwitch: (id: string) => {
      badSwitchDevice = id;
    },
    invalidateHealth: (id: string) => {
      badHealthDevice = id;
    },
    failActivation: (id: string) => {
      failActivateDevice = id;
    },
    failRollback: (id: string) => {
      failRollbackDevice = id;
    },
    invalidateSignature: () => {
      badSignature = true;
    },
  };
}

afterEach(async () => {
  for (const store of stores.splice(0)) store.close();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("F01 fleet plan / preflight / canary / rollout / rollback (dormant candidate)", () => {
  it("rejects duplicate devices, missing canary and same release/rollback identities", () => {
    expect(() => plan({ targetDeviceIds: ["windows-main", "windows-main"] })).toThrow();
    expect(() => plan({ canaryDeviceId: "unknown-device" })).toThrow();
    expect(() => plan({ targetManifestSha256: PREVIOUS })).toThrow();
  });

  it("requires verified owner and trusted online healthy devices at planning", async () => {
    const h = await harness();
    h.denyOwner();
    await expect(h.control.plan(plan())).rejects.toThrow(/authorization denied/u);
    const j = await harness();
    j.trust.get("macbook-main")!.trustState = "pending";
    await expect(j.control.plan(plan())).rejects.toThrow(/not healthy and trusted/u);
    expect(j.store.db.prepare("SELECT COUNT(*) AS n FROM v3_fleet_plans").get()).toMatchObject({
      n: 0,
    });
  });

  it("persists exact plan once and rejects same idempotency key with changed scope", async () => {
    const h = await harness();
    const request = plan();
    const first = await h.control.plan(request);
    expect(first.replayed).toBe(false);
    expect((await h.control.plan(request)).replayed).toBe(true);
    await expect(
      h.control.plan({
        ...request,
        targetManifestSha256: "d".repeat(64),
      }),
    ).rejects.toThrow(FleetStoreConflict);
    expect(h.store.verifyAuditChain()).toMatchObject({ valid: true, events: 1 });
  });

  it("prevents two unresolved fleet plans from concurrently upgrading a shared device", async () => {
    const h = await harness();
    const first = plan();
    await h.control.plan(first);
    const competing = plan();
    await expect(h.control.plan(competing)).rejects.toThrow(/another unresolved fleet plan/u);
    expect(h.store.require(first.planId).state).toBe("planned");
  });

  it("performs all recipient-approved preflights before any activation; mac is exact canary", async () => {
    const h = await harness();
    const p = plan();
    await h.control.plan(p);
    const result = await h.control.run(p.planId, p.ownerSubject);
    expect(result.state).toBe("complete");
    const preflightWindows = h.events.indexOf("preflight:windows-main");
    const activateMac = h.events.indexOf("activate:macbook-main");
    const activateWindows = h.events.indexOf("activate:windows-main");
    expect(preflightWindows).toBeLessThan(activateMac);
    expect(activateMac).toBeLessThan(activateWindows);
    expect(h.state.get("macbook-main")).toBe(TARGET);
    expect(h.state.get("windows-main")).toBe(TARGET);
    expect(h.store.verifyAuditChain().valid).toBe(true);
    await expect(h.control.run(p.planId, p.ownerSubject)).rejects.toThrow(FleetStoreConflict);
  });

  it("stops before activation when recipient denies preflight", async () => {
    const h = await harness();
    const p = plan();
    await h.control.plan(p);
    h.denyConsent("fleet.preflight:windows-main");
    const outcome = await h.control.run(p.planId, p.ownerSubject);
    expect(outcome.state).toBe("blocked");
    expect(h.events.some((event) => event.startsWith("activate:"))).toBe(false);
    expect(h.state.get("macbook-main")).toBe(PREVIOUS);
  });

  it("blocks preflight when target device attestation is invalid", async () => {
    const h = await harness();
    const p = plan();
    await h.control.plan(p);
    h.invalidatePreflight("macbook-main");
    expect((await h.control.run(p.planId, p.ownerSubject)).state).toBe("blocked");
    expect(h.events.some((event) => event.startsWith("activate:"))).toBe(false);
  });

  it("fails closed when a signed preflight evidence verifier rejects the report", async () => {
    const h = await harness();
    const p = plan();
    await h.control.plan(p);
    h.invalidateSignature();
    expect((await h.control.run(p.planId, p.ownerSubject)).state).toBe("blocked");
  });

  it("automatically attempts a consented canary rollback when verify health fails", async () => {
    const h = await harness();
    const p = plan();
    await h.control.plan(p);
    h.invalidateHealth("macbook-main");
    const outcome = await h.control.run(p.planId, p.ownerSubject);
    expect(["rolled_back", "manual_intervention"]).toContain(outcome.state);
    expect(h.events).toContain("rollback:macbook-main");
    expect(h.events).not.toContain("activate:windows-main");
  });

  it("quarantines an unverified second switch while safely reverting the proven canary", async () => {
    const h = await harness();
    const p = plan();
    await h.control.plan(p);
    h.invalidateSwitch("windows-main");
    const outcome = await h.control.run(p.planId, p.ownerSubject);
    expect(outcome.state).toBe("manual_intervention");
    expect(h.events.filter((v) => v.startsWith("rollback:"))).toEqual(["rollback:macbook-main"]);
    expect(h.state.get("windows-main")).toBe(TARGET);
    expect(h.state.get("macbook-main")).toBe(PREVIOUS);
    expect(h.store.verifyAuditChain().valid).toBe(true);
  });

  it("records manual intervention when recipient denies consent to critical rollback", async () => {
    const h = await harness();
    const p = plan();
    await h.control.plan(p);
    h.invalidateHealth("macbook-main");
    h.denyConsent("fleet.rollback:macbook-main");
    expect((await h.control.run(p.planId, p.ownerSubject)).state).toBe("manual_intervention");
    expect(h.state.get("macbook-main")).toBe(TARGET);
  });

  it("does not retry ambiguous agent activation outcomes automatically", async () => {
    const h = await harness();
    const p = plan();
    await h.control.plan(p);
    h.failActivation("macbook-main");
    const outcome = await h.control.run(p.planId, p.ownerSubject);
    expect(outcome.state).toBe("manual_intervention");
    expect(h.events.filter((v) => v === "activate:macbook-main")).toHaveLength(1);
    expect(h.events).not.toContain("rollback:macbook-main");
    expect(h.state.get("macbook-main")).toBe(PREVIOUS);
    expect(h.store.verifyAuditChain().valid).toBe(true);
    await expect(h.control.run(p.planId, p.ownerSubject)).rejects.toThrow(FleetStoreConflict);
  });

  it("refuses to roll back a canary after an invalid activation receipt", async () => {
    const h = await harness();
    const p = plan();
    await h.control.plan(p);
    h.invalidateSwitch("macbook-main");
    const outcome = await h.control.run(p.planId, p.ownerSubject);
    expect(outcome.state).toBe("manual_intervention");
    expect(h.state.get("macbook-main")).toBe(TARGET);
    expect(h.events).not.toContain("rollback:macbook-main");
    expect(h.events).not.toContain("activate:windows-main");
    expect(h.store.verifyAuditChain().valid).toBe(true);
  });

  it("isolates an unknown second activation while reverting only a verified canary", async () => {
    const h = await harness();
    const p = plan();
    await h.control.plan(p);
    h.failActivation("windows-main");
    const outcome = await h.control.run(p.planId, p.ownerSubject);
    expect(outcome.state).toBe("manual_intervention");
    expect(h.events.filter((v) => v.startsWith("rollback:"))).toEqual(["rollback:macbook-main"]);
    expect(h.events.filter((v) => v === "activate:windows-main")).toHaveLength(1);
    expect(h.state.get("macbook-main")).toBe(PREVIOUS);
    expect(h.store.verifyAuditChain().valid).toBe(true);
  });
  it("keeps startup-interrupted canary in durable non-replay state", async () => {
    const h = await harness();
    const p = plan();
    await h.control.plan(p);
    h.store.transition(p.planId, "planned", "preflighting", Date.now());
    h.store.transition(p.planId, "preflighting", "ready", Date.now());
    h.store.transition(p.planId, "ready", "canary", Date.now());
    await expect(h.control.run(p.planId, p.ownerSubject)).rejects.toThrow(FleetStoreConflict);
    expect(h.events.filter((v) => v.startsWith("activate:"))).toHaveLength(0);
  });

  it("detects an edited durable audit journal", async () => {
    const h = await harness();
    const p = plan();
    await h.control.plan(p);
    expect(h.store.verifyAuditChain().valid).toBe(true);
    h.store.db.prepare("UPDATE v3_fleet_events SET event_json='tampered' WHERE sequence=1").run();
    expect(h.store.verifyAuditChain().valid).toBe(false);
  });
});
