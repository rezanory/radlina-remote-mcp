import { describe, expect, it } from "vitest";

import {
  createDistributedAuditRecord,
  HmacDistributedAuditSigner,
  verifyDistributedAuditRecord,
  type DistributedAuditPayload,
} from "../../../src/v3/audit/distributed.js";

const hash = "a".repeat(64);
const signer = new HmacDistributedAuditSigner(Buffer.alloc(32, 7));

function payload(overrides: Partial<DistributedAuditPayload> = {}): DistributedAuditPayload {
  return {
    globalCorrelationId: "corr-1",
    traceId: "trace-1",
    subject: "owner",
    profile: "radlina",
    workflowExecutionId: "wf-1",
    nodeId: "health",
    attempt: 1,
    resolvedDeviceId: "windows-main",
    capability: "device.health",
    policyDecision: {
      allowed: true,
      reason: "authorized",
      requiredScope: "device:read",
      risk: "low",
    },
    inputSha256: hash,
    outputSha256: hash,
    localAuditReceiptHash: hash,
    requestedAt: "2026-10-07T12:00:00+03:00",
    endedAt: "2026-10-07T12:00:01+03:00",
    terminalState: "completed",
    ...overrides,
  };
}

describe("V3 distributed audit", () => {
  it("creates a signed global receipt correlated to the exact device and local audit hash", () => {
    const record = createDistributedAuditRecord(payload(), signer);
    expect(record.resolvedDeviceId).toBe("windows-main");
    expect(record.localAuditReceiptHash).toBe(hash);
    expect(record.recordHash).toMatch(/^[0-9a-f]{64}$/u);
    expect(verifyDistributedAuditRecord(record, signer)).toBe(true);
  });

  it("detects tampering in execution identity or output evidence", () => {
    const record = createDistributedAuditRecord(payload(), signer);
    expect(
      verifyDistributedAuditRecord({ ...record, resolvedDeviceId: "macbook-main" }, signer),
    ).toBe(false);
    expect(verifyDistributedAuditRecord({ ...record, outputSha256: "b".repeat(64) }, signer)).toBe(
      false,
    );
  });

  it("detects signature tampering", () => {
    const record = createDistributedAuditRecord(payload(), signer);
    expect(verifyDistributedAuditRecord({ ...record, signature: "b".repeat(64) }, signer)).toBe(
      false,
    );
  });

  it("fails closed when an execution receipt tries to claim a denied policy decision", () => {
    expect(() =>
      createDistributedAuditRecord(
        payload({
          policyDecision: {
            allowed: false,
            reason: "denied",
            requiredScope: "device:read",
            risk: "low",
          },
        }),
        signer,
      ),
    ).toThrow(/cannot claim a denied policy decision/u);
  });

  it("requires a sufficiently strong HMAC key", () => {
    expect(() => new HmacDistributedAuditSigner(Buffer.alloc(16, 1))).toThrow(/at least 32 bytes/u);
  });
});
