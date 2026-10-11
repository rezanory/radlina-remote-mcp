import { canonicalJson, sha256 } from "../../utils/json.js";
import {
  assertManifestHash,
  fleetPlanSchema,
  type FleetAttestation,
  type FleetDeviceAgentPort,
  type FleetDeviceReader,
  type FleetOwnershipAuthority,
  type FleetPlan,
  type FleetReceiptVerifierPort,
  type FleetRecipientConsentPort,
  type FleetSwitchReceipt,
  type FleetVerifyReceipt,
} from "./contracts.js";
import { SqliteFleetStore, type FleetPlanSnapshot } from "./store.js";

export class FleetPreflightError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FleetPreflightError";
  }
}

/**
 * Port-bound F01 fleet lifecycle. A real activation is NOT wired by default:
 * live identity, recipient consent and signed device evidence are mandatory.
 * Unknown activation outcomes are never automatically retried.
 */
export class V3FleetController {
  constructor(
    private readonly store: SqliteFleetStore,
    private readonly devices: FleetDeviceReader,
    private readonly agent: FleetDeviceAgentPort,
    private readonly owner: FleetOwnershipAuthority,
    private readonly consent: FleetRecipientConsentPort,
    private readonly evidence: FleetReceiptVerifierPort,
    private readonly now: () => number = () => Date.now(),
  ) {}

  private requireEnrolled(deviceId: string): void {
    const item = this.devices.get(deviceId);
    if (
      !item ||
      item.deviceId !== deviceId ||
      item.trustState !== "trusted" ||
      item.status !== "online" ||
      item.health !== "healthy"
    ) {
      throw new FleetPreflightError(
        `device ${deviceId} is not healthy and trusted for fleet operations`,
      );
    }
  }

  async plan(raw: FleetPlan): Promise<{ snapshot: FleetPlanSnapshot; replayed: boolean }> {
    const plan = fleetPlanSchema.parse(raw);
    await this.owner.assertOwner(plan.ownerSubject, "fleet.plan");
    for (const deviceId of plan.targetDeviceIds) this.requireEnrolled(deviceId);
    return this.store.create(plan, this.now());
  }

  async run(planId: string, ownerSubject: string): Promise<FleetPlanSnapshot> {
    const snapshot = this.store.require(planId);
    const plan = snapshot.plan;
    if (ownerSubject !== plan.ownerSubject) {
      throw new FleetPreflightError("fleet plan subject mismatch");
    }
    await this.owner.assertOwner(ownerSubject, "fleet.preflight");
    const ordered = [
      plan.canaryDeviceId,
      ...plan.targetDeviceIds.filter((id) => id !== plan.canaryDeviceId),
    ];

    // Durable CAS admits precisely one attempt. After a process crash,
    // preflighting/canary/rolling_out require independent human reconciliation.
    this.store.transition(planId, "planned", "preflighting", this.now());
    try {
      for (const deviceId of ordered) {
        this.requireEnrolled(deviceId);
        await this.consent.require(deviceId, "fleet.preflight", planId);
        const report = await this.agent.preflight(
          deviceId,
          plan.targetManifestSha256,
          plan.rollbackManifestSha256,
        );
        await this.assertPreflight(report, deviceId, plan);
        this.store.record({
          kind: "device.preflight.verified",
          planId,
          deviceId,
          atMs: this.now(),
          detailsHash: report.evidenceSha256,
        });
      }
    } catch (error) {
      const detailsHash = sha256(
        error instanceof Error ? error.message : "unknown-preflight-failure",
      );
      return this.store.transition(planId, "preflighting", "blocked", this.now(), detailsHash);
    }

    this.store.transition(planId, "preflighting", "ready", this.now());
    this.store.transition(planId, "ready", "canary", this.now());

    // Every switch attempt is recorded before invoking an external agent.
    // The recipient's grant is rechecked for each operation.
    // Only a verified switch receipt permits automatic rollback; otherwise
    // the device state is unknown and must be reconciled by an operator.
    const verifiedSwitches: string[] = [];
    let unresolvedActivationDevice: string | undefined;
    let currentPhase: "canary" | "rolling_out" = "canary";
    try {
      for (const [index, deviceId] of ordered.entries()) {
        this.requireEnrolled(deviceId);
        await this.owner.assertOwner(ownerSubject, "fleet.activate");
        await this.consent.require(deviceId, "fleet.activate", planId);
        this.store.record({
          kind: "device.activate.intent",
          planId,
          deviceId,
          atMs: this.now(),
          detailsHash: sha256(canonicalJson({ target: plan.targetManifestSha256, deviceId })),
        });
        // The activation may have reached the device even if the transport
        // times out. Never automatically roll back an unverified switch.
        unresolvedActivationDevice = deviceId;
        const switched = await this.agent.activate(deviceId, plan.targetManifestSha256);
        await this.assertSwitch(
          switched,
          deviceId,
          plan.rollbackManifestSha256,
          plan.targetManifestSha256,
        );
        verifiedSwitches.push(deviceId);
        unresolvedActivationDevice = undefined;
        await this.owner.assertOwner(ownerSubject, "fleet.verify");
        await this.consent.require(deviceId, "fleet.verify", planId);
        const observed = await this.agent.verify(deviceId, plan.targetManifestSha256);
        await this.assertHealthy(observed, deviceId, plan.targetManifestSha256);
        this.store.record({
          kind: "device.activate.verified",
          planId,
          deviceId,
          atMs: this.now(),
          detailsHash: observed.deviceReceiptHash,
        });
        if (index === 0 && ordered.length > 1) {
          this.store.transition(planId, "canary", "rolling_out", this.now());
          currentPhase = "rolling_out";
        }
      }
      return this.store.transition(planId, currentPhase, "complete", this.now());
    } catch (error) {
      this.store.transition(
        planId,
        currentPhase,
        "rollback_pending",
        this.now(),
        sha256(error instanceof Error ? error.message : "unknown-fleet-error"),
      );
      let unresolved = unresolvedActivationDevice !== undefined;
      if (unresolvedActivationDevice !== undefined) {
        // Preserve the uncertain target in the tamper-evident journal. Its
        // actual release may be either previous or target: fail closed.
        this.store.record({
          kind: "device.activate.unresolved",
          planId,
          deviceId: unresolvedActivationDevice,
          atMs: this.now(),
          detailsHash: sha256(
            error instanceof Error ? error.message : "unknown-activation-outcome",
          ),
        });
      }
      // Only independently verified switches have a known rollback base.
      // Uncertain targets require manual reconciliation, not an automatic call.
      for (const deviceId of [...verifiedSwitches].reverse()) {
        try {
          this.requireEnrolled(deviceId);
          await this.owner.assertOwner(ownerSubject, "fleet.rollback");
          await this.consent.require(deviceId, "fleet.rollback", planId);
          this.store.record({
            kind: "device.rollback.intent",
            planId,
            deviceId,
            atMs: this.now(),
            detailsHash: sha256(canonicalJson({ rollback: plan.rollbackManifestSha256, deviceId })),
          });
          const reverted = await this.agent.rollback(deviceId, plan.rollbackManifestSha256);
          await this.assertSwitch(
            reverted,
            deviceId,
            plan.targetManifestSha256,
            plan.rollbackManifestSha256,
          );
          await this.consent.require(deviceId, "fleet.verify", planId);
          const verified = await this.agent.verify(deviceId, plan.rollbackManifestSha256);
          await this.assertHealthy(verified, deviceId, plan.rollbackManifestSha256);
          this.store.record({
            kind: "device.rollback.verified",
            planId,
            deviceId,
            atMs: this.now(),
            detailsHash: verified.deviceReceiptHash,
          });
        } catch (rollbackError) {
          unresolved = true;
          this.store.record({
            kind: "device.rollback.unresolved",
            planId,
            deviceId,
            atMs: this.now(),
            detailsHash: sha256(
              rollbackError instanceof Error ? rollbackError.message : "unknown-rollback-error",
            ),
          });
        }
      }
      return this.store.transition(
        planId,
        "rollback_pending",
        unresolved ? "manual_intervention" : "rolled_back",
        this.now(),
      );
    }
  }

  private async assertPreflight(
    report: FleetAttestation,
    deviceId: string,
    plan: FleetPlan,
  ): Promise<void> {
    assertManifestHash(report.previousManifestSha256);
    assertManifestHash(report.evidenceSha256);
    if (
      report.deviceId !== deviceId ||
      report.previousManifestSha256 !== plan.rollbackManifestSha256 ||
      !report.identityVerified ||
      !report.stagedRollbackVerified ||
      !report.stagedTargetVerified ||
      !report.consentSupported ||
      report.health !== "healthy" ||
      !(await this.evidence.verifyPreflight(report))
    ) {
      throw new FleetPreflightError(`verified preflight failed for ${deviceId}`);
    }
  }

  private async assertSwitch(
    receipt: FleetSwitchReceipt,
    deviceId: string,
    previous: string,
    expected: string,
  ): Promise<void> {
    assertManifestHash(receipt.deviceReceiptHash);
    if (
      receipt.deviceId !== deviceId ||
      receipt.previousManifestSha256 !== previous ||
      receipt.activeManifestSha256 !== expected ||
      !receipt.identityVerified ||
      !(await this.evidence.verifySwitch(receipt))
    ) {
      throw new FleetPreflightError(`verified fleet switch receipt mismatch for ${deviceId}`);
    }
  }

  private async assertHealthy(
    receipt: FleetVerifyReceipt,
    deviceId: string,
    expected: string,
  ): Promise<void> {
    assertManifestHash(receipt.deviceReceiptHash);
    if (
      receipt.deviceId !== deviceId ||
      receipt.activeManifestSha256 !== expected ||
      receipt.health !== "healthy" ||
      !receipt.identityVerified ||
      !(await this.evidence.verifyHealth(receipt))
    ) {
      throw new FleetPreflightError(`device health or release verification failed for ${deviceId}`);
    }
  }
}
