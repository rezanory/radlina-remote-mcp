import { createPublicKey, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { canonicalJson, sha256 } from "../../src/utils/json.js";
import {
  buildApprovalMessage,
  type PinnedConsentDevice,
} from "../../src/v3/security/consent-contracts.js";
import { SqliteCrossDeviceConsentAuthority } from "../../src/v3/security/device-consent.js";

const root = await mkdtemp(path.join(tmpdir(), "radlina-consent-local-acceptance-"));
const targetKeys = generateKeyPairSync("ed25519");
const originKeys = generateKeyPairSync("ed25519");
const now = Date.now();
const device = (id: string, key: typeof targetKeys.publicKey): PinnedConsentDevice => ({
  deviceId: id,
  trustState: "trusted",
  approvalPublicKeyPem: key.export({ type: "spki", format: "pem" }).toString(),
  approvalKeyFingerprint: sha256(
    createPublicKey(key.export({ type: "spki", format: "pem" })).export({
      type: "spki",
      format: "der",
    }),
  ),
});
const trust = new Map([
  ["windows-main", device("windows-main", originKeys.publicKey)],
  ["macbook-main", device("macbook-main", targetKeys.publicKey)],
]);
const authority = new SqliteCrossDeviceConsentAuthority(
  path.join(root, "consent.sqlite3"),
  { get: (id) => trust.get(id) },
  () => now,
);
try {
  const origin = { deviceId: "windows-main", subject: "local-fixture-owner", attested: true };
  const target = {
    deviceId: "macbook-main",
    subject: "local-fixture-target",
    attested: true,
    localUserApproved: true,
  };
  const inputSha256 = sha256(canonicalJson({ action: "device.health" }));
  const scope = {
    sourceDeviceId: origin.deviceId,
    targetDeviceId: target.deviceId,
    subject: origin.subject,
    capability: "device.health",
    resourceKey: `exact-input:${inputSha256}`,
    inputSha256,
  };
  const deniedBefore = authority.consume(scope, origin, randomUUID());
  const request = authority.request(
    { ...scope, purpose: "Synthetic local consent acceptance (not a MacBook enrollment)" },
    origin,
    randomUUID(),
  );
  const unsigned = {
    requestId: request.requestId,
    decision: "approve" as const,
    duration: "once" as const,
    validUntilMs: now + 60_000,
    signedAtMs: now,
    nonce: randomUUID(),
  };
  const signatureBase64 = sign(
    null,
    Buffer.from(canonicalJson(buildApprovalMessage(request, unsigned))),
    targetKeys.privateKey,
  ).toString("base64");
  const approved = authority.decide({ ...unsigned, signatureBase64 }, target);
  const acceptedOnce = authority.consume(scope, origin, randomUUID());
  const deniedReplay = authority.consume(scope, origin, randomUUID());
  const proofVerified = authority.verifyDecisionProof(request.requestId);
  const auditChain = authority.verifyAuditChain();
  const pass =
    !deniedBefore.allowed &&
    approved.grant?.remainingUses === 1 &&
    acceptedOnce.allowed &&
    !deniedReplay.allowed &&
    proofVerified &&
    auditChain.valid;
  process.stdout.write(
    JSON.stringify({
      input: {
        origin: origin.deviceId,
        destination: target.deviceId,
        capability: scope.capability,
      },
      runtime: { processPlatform: process.platform, SQLite: "node:sqlite", signature: "Ed25519" },
      execution: {
        deniedBefore: !deniedBefore.allowed,
        approvedOnce: approved.grant?.duration === "once",
        acceptedOnce: acceptedOnce.allowed,
        deniedReplay: !deniedReplay.allowed,
        proofVerified,
        auditChain,
      },
      output: { requestHash: request.requestHash, grantId: approved.grant?.grantId ?? null },
      acceptance: pass ? "LOCAL_COMPONENT_PASS" : "FAIL",
      productionAcceptance: "NOT_GRANTED_REAL_MACBOOK_AND_NETWORK_ENFORCEMENT_PENDING",
      syntheticFixture: true,
    }) + "\n",
  );
  if (!pass) process.exitCode = 1;
} finally {
  authority.close();
  await rm(root, { recursive: true, force: true });
}
