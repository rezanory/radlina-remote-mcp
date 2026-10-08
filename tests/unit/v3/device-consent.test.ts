import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { canonicalJson, sha256 } from "../../../src/utils/json.js";
import {
  buildApprovalMessage,
  type ConsentRequest,
  type ConsentRequestInput,
  type ConsentDuration,
  type PinnedConsentDevice,
  type VerifiedDevicePrincipal,
} from "../../../src/v3/security/consent-contracts.js";
import { SqliteCrossDeviceConsentAuthority } from "../../../src/v3/security/device-consent.js";
import {
  ConsentGatedExecutionDispatchPort,
  consentRequestForDispatch,
  type VerifiedWorkflowOriginPort,
} from "../../../src/v3/security/consent-dispatch.js";
import type {
  WorkflowDispatchInput,
  ExecutionDispatchPort,
} from "../../../src/v3/workflow/runtime.js";

const windowsKeys = generateKeyPairSync("ed25519");
const macKeys = generateKeyPairSync("ed25519");
const differentMacKeys = generateKeyPairSync("ed25519");
const keyInfo = (deviceId: string, publicKey: typeof macKeys.publicKey): PinnedConsentDevice => ({
  deviceId,
  trustState: "trusted",
  approvalPublicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  approvalKeyFingerprint: sha256(publicKey.export({ type: "spki", format: "der" })),
});
const trusted = new Map<string, PinnedConsentDevice>([
  ["windows-main", keyInfo("windows-main", windowsKeys.publicKey)],
  ["macbook-main", keyInfo("macbook-main", macKeys.publicKey)],
]);
const source: VerifiedDevicePrincipal = {
  deviceId: "windows-main",
  subject: "owner",
  attested: true,
};
const recipient: VerifiedDevicePrincipal = {
  deviceId: "macbook-main",
  subject: "macbook-owner",
  attested: true,
  localUserApproved: true,
};
const inputHash = sha256(canonicalJson({ path: "/Users/owner/notes.txt", readOnly: true }));
const scope: ConsentRequestInput = {
  sourceDeviceId: "windows-main",
  targetDeviceId: "macbook-main",
  subject: "owner",
  capability: "filesystem.read",
  resourceKey: `exact-input:${inputHash}`,
  inputSha256: inputHash,
  purpose: "Read exactly one requested note",
};
const roots: string[] = [];
const stores: SqliteCrossDeviceConsentAuthority[] = [];
let clock: number;
let store: SqliteCrossDeviceConsentAuthority;

beforeEach(async () => {
  trusted.set("macbook-main", keyInfo("macbook-main", macKeys.publicKey));
  trusted.set("windows-main", keyInfo("windows-main", windowsKeys.publicKey));
  clock = 1_790_000_000_000;
  const root = await mkdtemp(path.join(tmpdir(), "radlina-cross-device-consent-"));
  roots.push(root);
  store = new SqliteCrossDeviceConsentAuthority(
    path.join(root, "consent.sqlite3"),
    { get: (deviceId) => trusted.get(deviceId) },
    () => clock,
  );
  stores.push(store);
});

afterEach(async () => {
  for (const entry of stores.splice(0)) entry.close();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

function request(input: ConsentRequestInput = scope, principal = source): ConsentRequest {
  return store.request(input, principal, randomUUID());
}
function approve(
  record: ConsentRequest,
  duration: ConsentDuration = "once",
  until: number | null = clock + 300_000,
  overrides: {
    principal?: VerifiedDevicePrincipal;
    signingKey?: typeof macKeys.privateKey;
    decision?: "approve" | "deny";
    signedAtMs?: number;
  } = {},
) {
  const unsigned = {
    requestId: record.requestId,
    decision: overrides.decision ?? ("approve" as const),
    duration,
    validUntilMs: until,
    signedAtMs: overrides.signedAtMs ?? clock,
    nonce: randomUUID(),
  };
  const message = buildApprovalMessage(record, unsigned);
  const signatureBase64 = sign(
    null,
    Buffer.from(canonicalJson(message), "utf8"),
    overrides.signingKey ?? macKeys.privateKey,
  ).toString("base64");
  return store.decide({ ...unsigned, signatureBase64 }, overrides.principal ?? recipient);
}
function use(input: ConsentRequestInput = scope, principal = source, attempt = randomUUID()) {
  return store.consume(
    {
      sourceDeviceId: input.sourceDeviceId,
      targetDeviceId: input.targetDeviceId,
      subject: input.subject,
      capability: input.capability,
      resourceKey: input.resourceKey,
      inputSha256: input.inputSha256,
    },
    principal,
    attempt,
  );
}

describe("V3 recipient-signed cross-device consent S02 extension", () => {
  it("denies cross-device execution by default, without leaking a consent grant", () => {
    const decision = use();
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("no active target-signed");
    expect(store.verifyAuditChain()).toMatchObject({ valid: true, events: 1 });
  });

  it("allows one exact Windows-to-Mac operation once after a signed target approval", () => {
    const req = request();
    const accepted = approve(req);
    expect(accepted.grant?.duration).toBe("once");
    expect(use()).toMatchObject({ allowed: true, grantId: accepted.grant?.grantId });
    expect(use().allowed).toBe(false);
    expect(store.getGrant(accepted.grant!.grantId)?.remainingUses).toBe(0);
    expect(store.verifyAuditChain().valid).toBe(true);
  });

  it("does not infer reverse direction from Windows-to-Mac approval", () => {
    approve(request());
    expect(
      store.consume(
        {
          ...scope,
          sourceDeviceId: "macbook-main",
          targetDeviceId: "windows-main",
          subject: "macbook-owner",
        },
        recipient,
        randomUUID(),
      ).allowed,
    ).toBe(false);
  });

  it("requires a trusted, attested originating device and bound principal", () => {
    expect(() => request(scope, { ...source, attested: false })).toThrow(/authenticated device/u);
    expect(() => request(scope, { ...source, deviceId: "macbook-main" })).toThrow(
      /authenticated device/u,
    );
    expect(() => request(scope, { ...source, subject: "impersonated" })).toThrow(
      /subject does not match/u,
    );
    expect(use(scope, { ...source, attested: false }).allowed).toBe(false);
  });

  it("requires the target's local human approval and matching device identity", () => {
    const req = request();
    expect(() =>
      approve(req, "once", clock + 300_000, {
        principal: { ...recipient, localUserApproved: false },
      }),
    ).toThrow(/interactive human authorization/u);
    expect(() =>
      approve(req, "once", clock + 300_000, {
        principal: { ...recipient, deviceId: "windows-main" },
      }),
    ).toThrow(/authenticated device/u);
    expect(store.getRequest(req.requestId)?.state).toBe("pending");
  });

  it("rejects forged approval signatures and approvals for changed request contents", () => {
    const req = request();
    expect(() =>
      approve(req, "once", clock + 300_000, {
        signingKey: differentMacKeys.privateKey,
      }),
    ).toThrow(/invalid target-device approval signature/u);
    expect(use().allowed).toBe(false);
  });

  it("rejects stale approvals and expires unanswered permission requests", () => {
    const req = request();
    expect(() => approve(req, "once", clock + 100_000, { signedAtMs: clock - 200_000 })).toThrow(
      /stale or future-dated/u,
    );
    clock += 600_001;
    expect(() => approve(req, "once", clock + 100_000)).toThrow(/request expired/u);
  });

  it("enforces 1h expiration and forbids scope, capability or content widening", () => {
    const record = request();
    approve(record, "1h", clock + 3_600_000);
    expect(use({ ...scope, inputSha256: "b".repeat(64) }).allowed).toBe(false);
    expect(use({ ...scope, capability: "process.exec" }).allowed).toBe(false);
    expect(use({ ...scope, resourceKey: "other-file" }).allowed).toBe(false);
    expect(use({ ...scope, subject: "other" }).allowed).toBe(false);
    expect(use().allowed).toBe(true);
    clock += 3_600_001;
    expect(use().allowed).toBe(false);
  });

  it("rejects invalid grant windows, including excessive custom lifetimes", () => {
    const req = request();
    expect(() => approve(req, "1h", clock + 24 * 60 * 60_000)).toThrow(/lifetime exceeds/u);
    expect(() => approve(req, "custom", clock + 31 * 24 * 60 * 60_000)).toThrow(
      /lifetime exceeds/u,
    );
    expect(() => approve(req, "permanent", clock + 30_000)).toThrow(/explicit null expiry/u);
    expect(store.getRequest(req.requestId)?.state).toBe("pending");
  });

  it("permits explicit scoped permanent access until immediate recipient revocation", () => {
    const req = request();
    const grant = approve(req, "permanent", null).grant!;
    clock += 80 * 24 * 60 * 60_000;
    expect(use().allowed).toBe(true);
    expect(use().allowed).toBe(true);
    expect(() => store.revoke(grant.grantId, source)).toThrow(/authenticated device/u);
    expect(() => store.revoke(grant.grantId, { ...recipient, localUserApproved: false })).toThrow(
      /local recipient confirmation/u,
    );
    expect(store.revoke(grant.grantId, recipient).revokedAtMs).toBe(clock);
    expect(use().allowed).toBe(false);
  });

  it("denies future dispatch after target approval key rotation or trust revocation", () => {
    approve(request(), "permanent", null);
    expect(use().allowed).toBe(true);
    trusted.set("macbook-main", keyInfo("macbook-main", differentMacKeys.publicKey));
    expect(use().allowed).toBe(false);
    trusted.set("macbook-main", {
      ...keyInfo("macbook-main", macKeys.publicKey),
      trustState: "revoked",
    });
    expect(use().allowed).toBe(false);
  });

  it("persists permanent approval and revocation across a real SQLite reopen", () => {
    const req = request();
    const grant = approve(req, "permanent", null).grant!;
    expect(store.verifyDecisionProof(req.requestId)).toBe(true);
    const root = roots.at(-1)!;
    store.close();
    stores.pop();
    store = new SqliteCrossDeviceConsentAuthority(
      path.join(root, "consent.sqlite3"),
      { get: (deviceId) => trusted.get(deviceId) },
      () => clock,
    );
    stores.push(store);
    expect(store.getGrant(grant.grantId)?.duration).toBe("permanent");
    expect(store.verifyDecisionProof(req.requestId)).toBe(true);
    expect(use().allowed).toBe(true);
    store.revoke(grant.grantId, recipient);
    store.close();
    stores.pop();
    store = new SqliteCrossDeviceConsentAuthority(
      path.join(root, "consent.sqlite3"),
      { get: (deviceId) => trusted.get(deviceId) },
      () => clock,
    );
    stores.push(store);
    expect(use().allowed).toBe(false);
    expect(store.verifyAuditChain().valid).toBe(true);
  });

  it("prevents idempotency changes, denial replays and duplicate execution attempt IDs", () => {
    const idempotencyKey = randomUUID();
    const req = store.request(scope, source, idempotencyKey);
    expect(store.request(scope, source, idempotencyKey).requestId).toBe(req.requestId);
    expect(() =>
      store.request({ ...scope, resourceKey: "another" }, source, idempotencyKey),
    ).toThrow(/idempotency key collision/u);
    const denied = approve(req, "once", null, { decision: "deny" });
    expect(denied.grant).toBeNull();
    expect(() => approve(req, "once", null, { decision: "deny" })).toThrow(/already decided/u);
    const allowedReq = request();
    approve(allowedReq, "permanent", null);
    const attempt = randomUUID();
    expect(use(scope, source, attempt).allowed).toBe(true);
    expect(use(scope, source, attempt).allowed).toBe(false);
  });

  it("atomically consumes a one-use consent and detects a tampered audit event", () => {
    approve(request());
    const a = use();
    const b = use();
    expect([a.allowed, b.allowed].filter(Boolean)).toHaveLength(1);
    expect(store.verifyAuditChain().valid).toBe(true);
    store.db.exec("UPDATE v3_consent_events SET payload_json='tampered' WHERE sequence=1");
    expect(store.verifyAuditChain().valid).toBe(false);
  });

  it("exposes pending prompts and active grants only to their attested recipient", () => {
    const req = request();
    expect(store.pendingForTarget(recipient).map((x) => x.requestId)).toEqual([req.requestId]);
    expect(store.pendingForTarget(source)).toEqual([]);
    expect(() => store.pendingForTarget({ ...recipient, attested: false })).toThrow(
      /authenticated device/u,
    );
    const approved = approve(req, "1h", clock + 3_600_000).grant!;
    expect(store.pendingForTarget(recipient)).toEqual([]);
    expect(store.activeGrantsForTarget(recipient).map((x) => x.grantId)).toEqual([
      approved.grantId,
    ]);
    expect(store.activeGrantsForTarget(source)).toEqual([]);
    store.revoke(approved.grantId, recipient);
    expect(store.activeGrantsForTarget(recipient)).toEqual([]);
  });

  it("retains independently verifiable recipient-signed decision evidence", () => {
    const req = request();
    approve(req, "1h", clock + 3_600_000);
    expect(store.verifyDecisionProof(req.requestId)).toBe(true);
    store.db
      .prepare("UPDATE v3_consent_decision_proofs SET evidence_json=? WHERE request_id=?")
      .run('{"tampered":true}', req.requestId);
    expect(store.verifyDecisionProof(req.requestId)).toBe(false);
  });

  it("does not treat a local-only operation as remote authorization", () => {
    const result = store.consume(
      {
        sourceDeviceId: "windows-main",
        targetDeviceId: "windows-main",
        subject: "owner",
        capability: "device.health",
        resourceKey: "local",
        inputSha256: "a".repeat(64),
      },
      source,
      randomUUID(),
    );
    expect(result.allowed).toBe(true);
    expect(result.reason).toContain("same trusted device");
  });

  it("rejects wildcard resource access even if a target might later approve it", () => {
    expect(() => request({ ...scope, resourceKey: "*" })).toThrow();
    expect(() => request({ ...scope, resourceKey: "C:/home/**" })).toThrow();
  });
});

describe("V3 canonical dispatch consent enforcement adapter", () => {
  const node = {
    id: "health",
    capability: "device.health",
    input: { test: true },
    dependsOn: [],
    target: { deviceId: "macbook-main" },
    maxAttempts: 1,
    timeoutMs: 5_000,
    executionPolicy: {
      failureMode: "fail-workflow",
      allowDynamicReroute: false,
      unknownOutcome: "manual-resume",
    },
    expectedOutput: {
      contractId: "device.health/v1",
      artifactMode: "inline",
      maxBytes: 1024,
    },
  } as const;

  function input(targetDeviceId: string | null = "macbook-main"): WorkflowDispatchInput {
    return {
      workflowExecutionId: "wf-consent",
      subject: "owner",
      attempt: 1,
      node: {
        ...node,
        target: targetDeviceId ? { deviceId: targetDeviceId } : { platform: "macos" },
        dependsOn: [],
      },
    };
  }

  it("never calls the underlying dispatcher without consent", async () => {
    let callCount = 0;
    const target: ExecutionDispatchPort = {
      execute: async (request) => {
        callCount++;
        return {
          receipt: {
            workflowExecutionId: request.workflowExecutionId,
            nodeId: request.node.id,
            attempt: request.attempt,
            resolvedDeviceId: "macbook-main",
            capability: request.node.capability,
            inputSha256: sha256(canonicalJson(request.node.input)),
            startedAt: "2026-10-08T19:00:00Z",
            terminalState: "completed",
            outputSha256: "a".repeat(64),
            localAuditReceiptHash: "a".repeat(64),
            globalCorrelationId: "test-corr",
            traceId: "test-trace",
          },
        };
      },
    };
    const origins: VerifiedWorkflowOriginPort = { resolve: () => source };
    const guarded = new ConsentGatedExecutionDispatchPort(target, store, origins);
    await expect(guarded.execute(input())).rejects.toThrow(/no active target-signed/u);
    expect(callCount).toBe(0);
    await expect(guarded.execute(input(null))).rejects.toThrow();
    expect(callCount).toBe(0);

    const requested = store.request(
      consentRequestForDispatch(input(), source, "inspect target device"),
      source,
      randomUUID(),
    );
    approve(requested, "once", clock + 60_000);
    await expect(guarded.execute(input())).resolves.toBeDefined();
    expect(callCount).toBe(1);
    await expect(guarded.execute(input())).rejects.toThrow();
    expect(callCount).toBe(1);
  });

  it("denies when immutable submitting-device identity is missing or forged", async () => {
    const dispatch: ExecutionDispatchPort = {
      execute: async () => {
        throw Error("must not execute");
      },
    };
    const absent = new ConsentGatedExecutionDispatchPort(dispatch, store, {
      resolve: () => undefined,
    });
    await expect(absent.execute(input())).rejects.toThrow(/verified workflow origin/u);
    const forged = new ConsentGatedExecutionDispatchPort(dispatch, store, {
      resolve: () => ({ ...source, subject: "other" }),
    });
    await expect(forged.execute(input())).rejects.toThrow(/verified workflow origin/u);
  });
});
