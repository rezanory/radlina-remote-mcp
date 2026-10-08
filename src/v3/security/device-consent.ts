import { createPublicKey, randomUUID, verify } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import { canonicalJson, sha256 } from "../../utils/json.js";
import {
  buildApprovalMessage,
  consentDecisionSchema,
  consentDispatchScopeSchema,
  consentRequestInputSchema,
  type ConsentAccessDecision,
  type ConsentDeviceTrustPort,
  type ConsentDispatchScope,
  type ConsentDuration,
  type ConsentGrant,
  type ConsentRequest,
  type ConsentRequestInput,
  type SignedConsentDecision,
  type VerifiedDevicePrincipal,
} from "./consent-contracts.js";

const REQUEST_TTL_MS = 10 * 60_000;
const MAX_CLOCK_SKEW_MS = 120_000;
const GENESIS_HASH = "0".repeat(64);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const DURATION_LIMIT_MS: Record<Exclude<ConsentDuration, "permanent">, number> = {
  once: 10 * 60_000,
  "15m": 15 * 60_000,
  "1h": 60 * 60_000,
  "8h": 8 * 60 * 60_000,
  "24h": 24 * 60 * 60_000,
  custom: 30 * 24 * 60 * 60_000,
};

export class CrossDeviceConsentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CrossDeviceConsentError";
  }
}

/** All mutating operations below use BEGIN IMMEDIATE, making one-shot consumption atomic. */
export class SqliteCrossDeviceConsentAuthority {
  readonly db: DatabaseSync;

  constructor(
    databaseFile: string,
    private readonly trustedDevices: ConsentDeviceTrustPort,
    private readonly now: () => number = () => Date.now(),
  ) {
    mkdirSync(path.dirname(databaseFile), { recursive: true });
    this.db = new DatabaseSync(databaseFile, { enableForeignKeyConstraints: true });
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS v3_consent_requests (
        request_id TEXT PRIMARY KEY,
        idempotency_key TEXT NOT NULL UNIQUE,
        payload_json TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('pending','approved','denied'))
      );
      CREATE TABLE IF NOT EXISTS v3_consent_grants (
        grant_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE REFERENCES v3_consent_requests(request_id),
        payload_json TEXT NOT NULL,
        remaining_uses INTEGER,
        revoked_at_ms INTEGER
      );
      CREATE TABLE IF NOT EXISTS v3_consent_uses (
        attempt_id TEXT PRIMARY KEY,
        grant_id TEXT NOT NULL REFERENCES v3_consent_grants(grant_id),
        used_at_ms INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS v3_consent_decision_nonces (
        nonce TEXT PRIMARY KEY
      );
      CREATE TABLE IF NOT EXISTS v3_consent_decision_proofs (
        request_id TEXT PRIMARY KEY REFERENCES v3_consent_requests(request_id),
        evidence_json TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS v3_consent_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        payload_json TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL
      );
    `);
  }

  private transaction<T>(operation: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  private trusted(deviceId: string) {
    const device = this.trustedDevices.get(deviceId);
    if (!device || device.deviceId !== deviceId || device.trustState !== "trusted") {
      throw new CrossDeviceConsentError(`device ${deviceId} is not enrolled and trusted`);
    }
    if (!device.approvalPublicKeyPem || !/^[0-9a-f]{64}$/u.test(device.approvalKeyFingerprint)) {
      throw new CrossDeviceConsentError("pinned target approval key is unavailable");
    }
    const key = createPublicKey(device.approvalPublicKeyPem);
    const fingerprint = sha256(key.export({ type: "spki", format: "der" }));
    if (fingerprint !== device.approvalKeyFingerprint) {
      throw new CrossDeviceConsentError("enrolled device key fingerprint mismatch");
    }
    return { device, key };
  }

  private assertAttested(principal: VerifiedDevicePrincipal, expectedId: string): void {
    if (!principal.attested || principal.deviceId !== expectedId) {
      throw new CrossDeviceConsentError("authenticated device identity does not match");
    }
    this.trusted(expectedId);
  }

  request(
    inputRaw: ConsentRequestInput,
    authenticatedOrigin: VerifiedDevicePrincipal,
    idempotencyKey: string,
  ): ConsentRequest {
    const input = consentRequestInputSchema.parse(inputRaw);
    if (!UUID_PATTERN.test(idempotencyKey)) {
      throw new CrossDeviceConsentError("valid idempotency key is required");
    }
    this.assertAttested(authenticatedOrigin, input.sourceDeviceId);
    if (authenticatedOrigin.subject !== input.subject) {
      throw new CrossDeviceConsentError("request subject does not match authenticated principal");
    }
    this.trusted(input.targetDeviceId);

    return this.transaction(() => {
      const existing = this.db
        .prepare("SELECT payload_json,state FROM v3_consent_requests WHERE idempotency_key=?")
        .get(idempotencyKey) as
        { payload_json: string; state: ConsentRequest["state"] } | undefined;
      if (existing) {
        const record = {
          ...(JSON.parse(existing.payload_json) as ConsentRequest),
          state: existing.state,
        };
        if (record.requestHash !== sha256(canonicalJson(input))) {
          throw new CrossDeviceConsentError(
            "idempotency key collision with different consent scope",
          );
        }
        return record;
      }
      const now = this.now();
      const record: ConsentRequest = {
        ...input,
        requestId: randomUUID(),
        requestHash: sha256(canonicalJson(input)),
        requestedAtMs: now,
        requestExpiresAtMs: now + REQUEST_TTL_MS,
        state: "pending",
      };
      this.db
        .prepare(
          "INSERT INTO v3_consent_requests(request_id,idempotency_key,payload_json,state) VALUES(?,?,?,?)",
        )
        .run(record.requestId, idempotencyKey, canonicalJson(record), record.state);
      this.appendEvent({
        kind: "requested",
        requestId: record.requestId,
        requestHash: record.requestHash,
        sourceDeviceId: record.sourceDeviceId,
        targetDeviceId: record.targetDeviceId,
        atMs: now,
      });
      return record;
    });
  }

  getRequest(requestId: string): ConsentRequest | undefined {
    const row = this.db
      .prepare("SELECT payload_json,state FROM v3_consent_requests WHERE request_id=?")
      .get(requestId) as { payload_json: string; state: ConsentRequest["state"] } | undefined;
    if (!row) return undefined;
    return { ...(JSON.parse(row.payload_json) as ConsentRequest), state: row.state };
  }

  /** Recipient inbox. Only the locally attested target can view approval prompts. */
  pendingForTarget(recipient: VerifiedDevicePrincipal): ConsentRequest[] {
    this.assertAttested(recipient, recipient.deviceId);
    const rows = this.db
      .prepare("SELECT request_id FROM v3_consent_requests WHERE state='pending' ORDER BY rowid")
      .all() as Array<{ request_id: string }>;
    const now = this.now();
    return rows
      .map((row) => this.getRequest(row.request_id))
      .filter(
        (request): request is ConsentRequest =>
          request !== undefined &&
          request.targetDeviceId === recipient.deviceId &&
          request.requestExpiresAtMs > now,
      )
      .slice(0, 100);
  }

  /** Recipient grant-management list, excluding expired, revoked and consumed-once entries. */
  activeGrantsForTarget(recipient: VerifiedDevicePrincipal): ConsentGrant[] {
    this.assertAttested(recipient, recipient.deviceId);
    const rows = this.db
      .prepare(
        "SELECT grant_id FROM v3_consent_grants WHERE revoked_at_ms IS NULL ORDER BY rowid DESC",
      )
      .all() as Array<{ grant_id: string }>;
    const now = this.now();
    return rows
      .map((row) => this.getGrant(row.grant_id))
      .filter(
        (grant): grant is ConsentGrant =>
          grant !== undefined &&
          grant.targetDeviceId === recipient.deviceId &&
          (grant.validUntilMs === null || grant.validUntilMs > now) &&
          (grant.remainingUses === null || grant.remainingUses > 0),
      )
      .slice(0, 100);
  }

  getGrant(grantId: string): ConsentGrant | undefined {
    const row = this.db
      .prepare(
        "SELECT payload_json,remaining_uses,revoked_at_ms FROM v3_consent_grants WHERE grant_id=?",
      )
      .get(grantId) as
      | {
          payload_json: string;
          remaining_uses: number | null;
          revoked_at_ms: number | null;
        }
      | undefined;
    if (!row) return undefined;
    return {
      ...(JSON.parse(row.payload_json) as ConsentGrant),
      remainingUses: row.remaining_uses,
      revokedAtMs: row.revoked_at_ms,
    };
  }

  decide(
    decisionRaw: SignedConsentDecision,
    authenticatedTarget: VerifiedDevicePrincipal,
  ): { request: ConsentRequest; grant: ConsentGrant | null } {
    const decision = consentDecisionSchema.parse(decisionRaw);
    const request = this.getRequest(decision.requestId);
    if (!request) throw new CrossDeviceConsentError("consent request not found");
    this.assertAttested(authenticatedTarget, request.targetDeviceId);
    if (authenticatedTarget.localUserApproved !== true) {
      throw new CrossDeviceConsentError("target-device interactive human authorization required");
    }
    if (request.state !== "pending")
      throw new CrossDeviceConsentError("consent request already decided");
    const now = this.now();
    if (request.requestExpiresAtMs <= now) {
      throw new CrossDeviceConsentError("consent request expired");
    }
    if (Math.abs(decision.signedAtMs - now) > MAX_CLOCK_SKEW_MS) {
      throw new CrossDeviceConsentError("stale or future-dated approval signature");
    }
    if (decision.decision === "deny") {
      if (decision.duration !== "once" || decision.validUntilMs !== null) {
        throw new CrossDeviceConsentError("denial must not carry a grant lifetime");
      }
    } else if (decision.duration === "permanent") {
      if (decision.validUntilMs !== null) {
        throw new CrossDeviceConsentError("permanent approval must have an explicit null expiry");
      }
    } else {
      const limit = DURATION_LIMIT_MS[decision.duration];
      if (
        decision.validUntilMs === null ||
        decision.validUntilMs <= now ||
        decision.validUntilMs > now + limit
      ) {
        throw new CrossDeviceConsentError("approval lifetime exceeds the selected duration");
      }
    }

    const { device, key } = this.trusted(request.targetDeviceId);
    const unsigned = {
      requestId: decision.requestId,
      decision: decision.decision,
      duration: decision.duration,
      validUntilMs: decision.validUntilMs,
      signedAtMs: decision.signedAtMs,
      nonce: decision.nonce,
    };
    const payload = buildApprovalMessage(request, unsigned);
    const signature = Buffer.from(decision.signatureBase64, "base64");
    if (
      signature.length !== 64 ||
      !verify(null, Buffer.from(canonicalJson(payload), "utf8"), key, signature)
    ) {
      throw new CrossDeviceConsentError("invalid target-device approval signature");
    }

    const proofEvidence = {
      payload,
      signatureBase64: decision.signatureBase64,
      approvalPublicKeyPem: device.approvalPublicKeyPem,
      approvalKeyFingerprint: device.approvalKeyFingerprint,
    };
    const proofHash = sha256(canonicalJson(proofEvidence));

    return this.transaction(() => {
      const actual = this.getRequest(request.requestId);
      if (actual?.state !== "pending") {
        throw new CrossDeviceConsentError("concurrent request decision or replay denied");
      }
      const nonceExists = this.db
        .prepare("SELECT nonce FROM v3_consent_decision_nonces WHERE nonce=?")
        .get(decision.nonce);
      if (nonceExists) throw new CrossDeviceConsentError("approval nonce already used");
      this.db
        .prepare("INSERT INTO v3_consent_decision_nonces(nonce) VALUES(?)")
        .run(decision.nonce);
      this.db
        .prepare("INSERT INTO v3_consent_decision_proofs(request_id,evidence_json) VALUES(?,?)")
        .run(request.requestId, canonicalJson(proofEvidence));
      this.db
        .prepare("UPDATE v3_consent_requests SET state=? WHERE request_id=?")
        .run(decision.decision === "approve" ? "approved" : "denied", request.requestId);

      let grant: ConsentGrant | null = null;
      if (decision.decision === "approve") {
        grant = {
          sourceDeviceId: request.sourceDeviceId,
          targetDeviceId: request.targetDeviceId,
          subject: request.subject,
          capability: request.capability,
          resourceKey: request.resourceKey,
          inputSha256: request.inputSha256,
          purpose: request.purpose,
          grantId: randomUUID(),
          requestId: request.requestId,
          duration: decision.duration,
          approvedAtMs: now,
          validUntilMs: decision.validUntilMs,
          ownerKeyFingerprint: device.approvalKeyFingerprint,
          remainingUses: decision.duration === "once" ? 1 : null,
          revokedAtMs: null,
        };
        this.db
          .prepare(
            "INSERT INTO v3_consent_grants(grant_id,request_id,payload_json,remaining_uses,revoked_at_ms) VALUES(?,?,?,?,?)",
          )
          .run(grant.grantId, grant.requestId, canonicalJson(grant), grant.remainingUses, null);
      }
      this.appendEvent({
        kind: decision.decision === "approve" ? "approved" : "denied",
        requestId: request.requestId,
        grantId: grant?.grantId ?? null,
        sourceDeviceId: request.sourceDeviceId,
        targetDeviceId: request.targetDeviceId,
        duration: decision.duration,
        validUntilMs: decision.validUntilMs,
        approvalKeyFingerprint: device.approvalKeyFingerprint,
        decisionProofHash: proofHash,
        atMs: now,
      });
      return {
        request: { ...request, state: decision.decision === "approve" ? "approved" : "denied" },
        grant,
      };
    });
  }

  /** Authorize and atomically consume a grant BEFORE a cross-device execution attempt. */
  consume(
    rawScope: ConsentDispatchScope,
    origin: VerifiedDevicePrincipal,
    attemptId: string,
  ): ConsentAccessDecision {
    const scope = consentDispatchScopeSchema.parse(rawScope);
    if (!UUID_PATTERN.test(attemptId)) {
      return { allowed: false, reason: "invalid execution attempt identity" };
    }
    try {
      this.assertAttested(origin, scope.sourceDeviceId);
      if (origin.subject !== scope.subject) {
        throw new CrossDeviceConsentError("request subject mismatch");
      }
      if (scope.sourceDeviceId === scope.targetDeviceId) {
        return {
          allowed: true,
          reason: "same trusted device; cross-device consent not applicable",
        };
      }
      const target = this.trusted(scope.targetDeviceId);
      return this.transaction(() => {
        if (
          this.db
            .prepare("SELECT attempt_id FROM v3_consent_uses WHERE attempt_id=?")
            .get(attemptId)
        ) {
          return { allowed: false, reason: "execution attempt already authorized; replay blocked" };
        }
        const rows = this.db
          .prepare(
            "SELECT grant_id FROM v3_consent_grants WHERE revoked_at_ms IS NULL ORDER BY rowid DESC",
          )
          .all() as Array<{ grant_id: string }>;
        const now = this.now();
        for (const row of rows) {
          const grant = this.getGrant(row.grant_id);
          if (
            !grant ||
            grant.sourceDeviceId !== scope.sourceDeviceId ||
            grant.targetDeviceId !== scope.targetDeviceId ||
            grant.subject !== scope.subject ||
            grant.capability !== scope.capability ||
            grant.resourceKey !== scope.resourceKey ||
            grant.inputSha256 !== scope.inputSha256 ||
            grant.ownerKeyFingerprint !== target.device.approvalKeyFingerprint ||
            grant.revokedAtMs !== null ||
            (grant.validUntilMs !== null && grant.validUntilMs <= now) ||
            (grant.remainingUses !== null && grant.remainingUses <= 0)
          )
            continue;
          if (grant.remainingUses !== null) {
            const changed = this.db
              .prepare(
                "UPDATE v3_consent_grants SET remaining_uses=remaining_uses-1 WHERE grant_id=? AND remaining_uses>0 AND revoked_at_ms IS NULL",
              )
              .run(grant.grantId);
            if (Number(changed.changes) !== 1) continue;
          }
          this.db
            .prepare("INSERT INTO v3_consent_uses(attempt_id,grant_id,used_at_ms) VALUES(?,?,?)")
            .run(attemptId, grant.grantId, now);
          this.appendEvent({
            kind: "consumed",
            grantId: grant.grantId,
            requestId: grant.requestId,
            attemptId,
            sourceDeviceId: grant.sourceDeviceId,
            targetDeviceId: grant.targetDeviceId,
            atMs: now,
          });
          return {
            allowed: true,
            reason: "target-signed scoped consent consumed",
            grantId: grant.grantId,
          };
        }
        this.appendEvent({
          kind: "denied_execution",
          sourceDeviceId: scope.sourceDeviceId,
          targetDeviceId: scope.targetDeviceId,
          scopeHash: sha256(canonicalJson(scope)),
          attemptId,
          atMs: now,
        });
        return {
          allowed: false,
          reason: "no active target-signed consent for exact device, subject, capability and input",
        };
      });
    } catch (error) {
      return {
        allowed: false,
        reason: error instanceof Error ? error.message : "consent verification failed",
      };
    }
  }

  /** The recipient can revoke access immediately; origin cannot revoke a target's authority. */
  revoke(grantId: string, authenticatedTarget: VerifiedDevicePrincipal): ConsentGrant {
    const current = this.getGrant(grantId);
    if (!current) throw new CrossDeviceConsentError("grant not found");
    this.assertAttested(authenticatedTarget, current.targetDeviceId);
    if (authenticatedTarget.localUserApproved !== true) {
      throw new CrossDeviceConsentError("local recipient confirmation required for revocation");
    }
    return this.transaction(() => {
      const existing = this.getGrant(grantId);
      if (!existing) throw new CrossDeviceConsentError("grant not found");
      if (existing.revokedAtMs !== null) return existing;
      const now = this.now();
      this.db
        .prepare(
          "UPDATE v3_consent_grants SET revoked_at_ms=? WHERE grant_id=? AND revoked_at_ms IS NULL",
        )
        .run(now, grantId);
      this.appendEvent({
        kind: "revoked",
        grantId,
        requestId: existing.requestId,
        byTargetDeviceId: existing.targetDeviceId,
        atMs: now,
      });
      return { ...existing, revokedAtMs: now };
    });
  }

  /** Independently rechecks the recipient signature retained for audit review. */
  verifyDecisionProof(requestId: string): boolean {
    try {
      const request = this.getRequest(requestId);
      const row = this.db
        .prepare("SELECT evidence_json FROM v3_consent_decision_proofs WHERE request_id=?")
        .get(requestId) as { evidence_json: string } | undefined;
      if (!row || !request) return false;
      const evidence = JSON.parse(row.evidence_json) as {
        payload: ReturnType<typeof buildApprovalMessage>;
        signatureBase64: string;
        approvalPublicKeyPem: string;
        approvalKeyFingerprint: string;
      };
      const { payload } = evidence;
      if (payload.requestId !== requestId || payload.requestHash !== request.requestHash)
        return false;
      if (
        payload.targetDeviceId !== request.targetDeviceId ||
        payload.sourceDeviceId !== request.sourceDeviceId
      )
        return false;
      const reconstructed = buildApprovalMessage(request, {
        requestId: payload.requestId,
        decision: payload.decision,
        duration: payload.duration,
        validUntilMs: payload.validUntilMs,
        signedAtMs: payload.signedAtMs,
        nonce: payload.nonce,
      });
      if (canonicalJson(reconstructed) !== canonicalJson(payload)) return false;
      const key = createPublicKey(evidence.approvalPublicKeyPem);
      if (sha256(key.export({ type: "spki", format: "der" })) !== evidence.approvalKeyFingerprint)
        return false;
      const signature = Buffer.from(evidence.signatureBase64, "base64");
      if (
        signature.length !== 64 ||
        !verify(null, Buffer.from(canonicalJson(payload), "utf8"), key, signature)
      )
        return false;
      const evidenceHash = sha256(canonicalJson(evidence));
      const rows = this.db
        .prepare("SELECT payload_json FROM v3_consent_events ORDER BY sequence")
        .all() as Array<{ payload_json: string }>;
      return (
        rows.some((eventRow) => {
          const event = JSON.parse(eventRow.payload_json) as {
            requestId?: string;
            decisionProofHash?: string;
          };
          return event.requestId === requestId && event.decisionProofHash === evidenceHash;
        }) && this.verifyAuditChain().valid
      );
    } catch {
      return false;
    }
  }

  /** Verifies append-only event linkage. S03 must anchor the final hash externally. */
  verifyAuditChain(): { valid: boolean; events: number; headHash: string } {
    const rows = this.db
      .prepare(
        "SELECT payload_json,previous_hash,event_hash FROM v3_consent_events ORDER BY sequence",
      )
      .all() as Array<{ payload_json: string; previous_hash: string; event_hash: string }>;
    let previous = GENESIS_HASH;
    for (const row of rows) {
      if (
        row.previous_hash !== previous ||
        sha256(previous + "|" + row.payload_json) !== row.event_hash
      ) {
        return { valid: false, events: rows.length, headHash: previous };
      }
      previous = row.event_hash;
    }
    return { valid: true, events: rows.length, headHash: previous };
  }

  close(): void {
    this.db.close();
  }

  private appendEvent(event: Record<string, unknown>): void {
    const last = this.db
      .prepare("SELECT event_hash FROM v3_consent_events ORDER BY sequence DESC LIMIT 1")
      .get() as { event_hash: string } | undefined;
    const previous = last?.event_hash ?? GENESIS_HASH;
    const payload = canonicalJson(event);
    this.db
      .prepare("INSERT INTO v3_consent_events(payload_json,previous_hash,event_hash) VALUES(?,?,?)")
      .run(payload, previous, sha256(previous + "|" + payload));
  }
}
