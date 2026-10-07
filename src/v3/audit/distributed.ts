import { createHmac, timingSafeEqual } from "node:crypto";

import * as z from "zod/v4";

import { canonicalJson, sha256 } from "../../utils/json.js";

const hashSchema = z.string().regex(/^[0-9a-f]{64}$/u);

export const distributedAuditPayloadSchema = z.object({
  globalCorrelationId: z.string().min(1).max(200),
  traceId: z.string().min(1).max(200),
  subject: z.string().min(1).max(200),
  profile: z.string().min(1).max(100),
  workflowExecutionId: z.string().min(1).max(200),
  nodeId: z.string().min(1).max(128),
  attempt: z.number().int().positive(),
  resolvedDeviceId: z.string().min(1).max(128),
  capability: z.string().min(1).max(128),
  policyDecision: z.object({
    allowed: z.boolean(),
    reason: z.string().min(1).max(1000),
    requiredScope: z.string().min(1).max(128),
    risk: z.enum(["low", "medium", "high", "critical"]),
  }),
  inputSha256: hashSchema,
  outputSha256: hashSchema.nullable(),
  localAuditReceiptHash: hashSchema,
  requestedAt: z.string().min(1).max(128),
  endedAt: z.string().min(1).max(128),
  terminalState: z.enum(["completed", "failed", "cancelled", "interrupted"]),
});

export type DistributedAuditPayload = z.infer<typeof distributedAuditPayloadSchema>;

export const signedDistributedAuditRecordSchema = distributedAuditPayloadSchema.extend({
  recordHash: hashSchema,
  signature: hashSchema,
});

export type SignedDistributedAuditRecord = z.infer<typeof signedDistributedAuditRecordSchema>;

export interface DistributedAuditSigner {
  sign(recordHash: string): string;
  verify(recordHash: string, signature: string): boolean;
}

export class HmacDistributedAuditSigner implements DistributedAuditSigner {
  constructor(private readonly key: Uint8Array) {
    if (key.byteLength < 32)
      throw new Error("distributed audit HMAC key must be at least 32 bytes");
  }

  sign(recordHash: string): string {
    return createHmac("sha256", this.key).update(recordHash).digest("hex");
  }

  verify(recordHash: string, signature: string): boolean {
    const expected = this.sign(recordHash);
    if (signature.length !== expected.length) return false;
    return timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  }
}

export function createDistributedAuditRecord(
  input: DistributedAuditPayload,
  signer: DistributedAuditSigner,
): SignedDistributedAuditRecord {
  const payload = distributedAuditPayloadSchema.parse(input);
  if (!payload.policyDecision.allowed) {
    throw new Error("execution receipt cannot claim a denied policy decision");
  }
  const recordHash = sha256(canonicalJson(payload));
  return signedDistributedAuditRecordSchema.parse({
    ...payload,
    recordHash,
    signature: signer.sign(recordHash),
  });
}

export function verifyDistributedAuditRecord(
  input: SignedDistributedAuditRecord,
  signer: DistributedAuditSigner,
): boolean {
  const record = signedDistributedAuditRecordSchema.parse(input);
  const { recordHash, signature, ...payload } = record;
  const expectedHash = sha256(canonicalJson(payload));
  return recordHash === expectedHash && signer.verify(recordHash, signature);
}
