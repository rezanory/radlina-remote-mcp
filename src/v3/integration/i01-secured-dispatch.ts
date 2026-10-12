/**
 * I01 exact-device execution composition; NOT enabled without owner/recipient
 * attestation, real transport and an external S03 anchor. No automatic retries.
 */
import { createPublicKey, randomUUID, verify } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import * as z from "zod/v4";
import { canonicalJson, sha256 } from "../../utils/json.js";
import { createDistributedAuditRecord, type DistributedAuditSigner, type SignedDistributedAuditRecord } from "../audit/distributed.js";
import { agentExecuteRequestSchema, agentExecutionReceiptSchema } from "../device/agent-protocol.js";
import { consentRequestForDispatch, type VerifiedWorkflowOriginPort } from "../security/consent-dispatch.js";
import type { VerifiedDevicePrincipal } from "../security/consent-contracts.js";
import { SqliteCrossDeviceConsentAuthority } from "../security/device-consent.js";
import type { WorkflowDispatchInput, WorkflowDispatchResult, ExecutionDispatchPort } from "../workflow/runtime.js";

const digest = z.string().regex(/^[0-9a-f]{64}$/u);
export const i01ExactOperationSchema = agentExecuteRequestSchema.extend({
  schema: z.literal("radlina.v3.i01.exact-device-dispatch/v1"),
  sourceDeviceId: z.string().min(1).max(64),
  subject: z.string().min(1).max(200),
  recipientApprovalHash: digest,
  issuedAtMs: z.number().int().positive(),
  expiresAtMs: z.number().int().positive(),
  nonce: z.string().uuid(),
}).strict();
export type I01ExactSignedOperation = z.infer<typeof i01ExactOperationSchema>;
export type I01OwnerSignedEnvelope = {
  operation: I01ExactSignedOperation;
  ownerSignatureBase64: string;
  recipientApproval: I01SignedRecipientApproval;
};
export const i01RecipientApprovalSchema = z.object({
  schema: z.literal("radlina.v3.i01.recipient-approval/v1"),
  operationSha256: digest,
  sourceDeviceId: z.string().min(1).max(64),
  targetDeviceId: z.string().min(1).max(64),
  subject: z.string().min(1).max(200),
  localUserApproved: z.literal(true),
  nonce: z.string().uuid(),
  issuedAtMs: z.number().int().positive(),
  expiresAtMs: z.number().int().positive(),
}).strict();
export type I01SignedRecipientApproval = {
  approval: z.infer<typeof i01RecipientApprovalSchema>;
  deviceSignatureBase64: string;
};
export const i01SignedDeviceResponseSchema = z.object({
  schema: z.literal("radlina.v3.i01.signed-device-response/v1"),
  requestId: z.string().uuid(),
  receipt: agentExecutionReceiptSchema,
  output: z.unknown().optional(),
  outputSha256: digest.nullable(),
  deviceSignatureBase64: z.string().min(80).max(200),
}).strict();
export type I01SignedDeviceResponse = z.infer<typeof i01SignedDeviceResponseSchema>;
export const i01SignedOwnerEnvelopeSchema = z.object({
  operation: i01ExactOperationSchema,
  ownerSignatureBase64: z.string().min(80).max(200),
  recipientApproval: z.object({
    approval: i01RecipientApprovalSchema,
    deviceSignatureBase64: z.string().min(80).max(200),
  }).strict(),
}).strict();

export interface I01TrustedDeviceResolver {
  /** Must consult actual P03 dual-signed registry + fresh signed heartbeat. */
  resolve(deviceId: string, capability: string): {
    deviceId: string;
    agentInstanceId: string;
    devicePublicKeyPem: string;
    devicePublicKeyFingerprint: string;
    heartbeatFresh: true;
  };
}
export interface I01OwnerScopeAuthority {
  /** Real OAuth owner identity, verified independently of workflow input. */
  authorize(principal: VerifiedDevicePrincipal, capability: string, targetId: string): Promise<void>;
}
export interface I01TargetLocalConsent {
  /** Signed decision from physical recipient UI, never server-side emulation. */
  approveExact(input: {
    operationSha256: string; source: VerifiedDevicePrincipal;
    targetDeviceId: string; subject: string;
    capability: string; inputSha256: string; resourceDescription: string;
  }): Promise<I01SignedRecipientApproval>;
}
export interface I01OwnerSigner {
  /** Private Ed25519 remains under owner DPAPI/Keychain; never returned. */
  sign(message: string): Promise<string>;
}
export interface I01PinnedTransport {
  /** Target must verify controller signature, P03 identity and local grant anew. */
  sendExact(targetId: string, envelope: I01OwnerSignedEnvelope): Promise<I01SignedDeviceResponse>;
  /** Read-only original sealed transport evidence for explicit OAuth-owner
   * reconciliation. Must NEVER claim or execute another native operation. */
  readOriginalReturned?(requestId:string):Promise<{
    envelope:I01OwnerSignedEnvelope;response:I01SignedDeviceResponse;
  }|null>;
}
export interface I01ExternalAuditAnchor {
  /** External durable S03 anchor is mandatory to return a completed workflow. */
  anchor(record: SignedDistributedAuditRecord, ownerEnvelope: I01OwnerSignedEnvelope,
    reply: I01SignedDeviceResponse, targetPublicKeyPem: string): Promise<{
    accepted: true; recordHash: string; anchorId: string;
  }>;
}
export class I01DispatchDenied extends Error {
  constructor(message: string) { super(message); this.name = "I01DispatchDenied"; }
}
function validSignature(pem: string, message: unknown, base64: string): boolean {
  try {
    const sig = Buffer.from(base64, "base64");
    return sig.length === 64 && sig.toString("base64") === base64 &&
      verify(null, Buffer.from(canonicalJson(message)), createPublicKey(pem), sig);
  } catch { return false; }
}

export class I01DurableDispatchJournal {
  readonly db: DatabaseSync;
  constructor(databaseFile: string) {
    if (!path.isAbsolute(databaseFile) || databaseFile.toLowerCase().includes("\\v2\\")) {
      throw new I01DispatchDenied("isolated absolute V3 database required");
    }
    mkdirSync(path.dirname(databaseFile), {recursive:true});
    this.db = new DatabaseSync(databaseFile, {enableForeignKeyConstraints:true});
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS v3_i01_operations (" +
      "operation_key TEXT PRIMARY KEY, request_hash TEXT NOT NULL, target_device_id TEXT NOT NULL, " +
      "request_id TEXT NOT NULL UNIQUE, state TEXT NOT NULL CHECK(state IN ('pending','completed','uncertain')), " +
      "receipt_hash TEXT, audit_anchor_id TEXT, created_at_ms INTEGER NOT NULL, completed_at_ms INTEGER);"
    );
  }
  reserve(key: string, hash: string, target: string, requestId: string): void {
    const previous = this.db.prepare(
      "SELECT request_hash FROM v3_i01_operations WHERE operation_key=?"
    ).get(key) as {request_hash:string}|undefined;
    if (previous) {
      if (previous.request_hash !== hash) throw new I01DispatchDenied("idempotency key collides with different content");
      throw new I01DispatchDenied("prior outcome unknown or completed: no automatic remote retry");
    }
    this.db.prepare(
      "INSERT INTO v3_i01_operations(operation_key,request_hash,target_device_id,request_id,state,created_at_ms) " +
      "VALUES(?,?,?,?,'pending',?)"
    ).run(key, hash, target, requestId, Date.now());
  }
  complete(key: string, receipt: string, audit: string): void {
    const result = this.db.prepare(
      "UPDATE v3_i01_operations SET state='completed',receipt_hash=?,audit_anchor_id=?,completed_at_ms=? " +
      "WHERE operation_key=? AND state='pending'"
    ).run(receipt, audit, Date.now(), key);
    if (Number(result.changes) !== 1) throw new I01DispatchDenied("journal CAS mismatch");
  }
  getForManualReconciliation(key:string):{
    requestId:string;requestHash:string;targetDeviceId:string;state:string;
  }|undefined{
    const row=this.db.prepare(
      "SELECT request_id,request_hash,target_device_id,state "+
      "FROM v3_i01_operations WHERE operation_key=?",
    ).get(key) as {
      request_id:string;request_hash:string;target_device_id:string;state:string;
    }|undefined;
    return row?{requestId:row.request_id,requestHash:row.request_hash,
      targetDeviceId:row.target_device_id,state:row.state}:undefined;
  }
  completeManually(key:string,receipt:string,anchor:string):void{
    if(!/^[a-f0-9]{64}$/u.test(receipt)||!anchor||anchor.length>256)
      throw new I01DispatchDenied("independent signed I01 recovery evidence required");
    const result=this.db.prepare(
      "UPDATE v3_i01_operations SET state='completed',receipt_hash=?,"+
      "audit_anchor_id=?,completed_at_ms=? WHERE operation_key=? AND state='uncertain'",
    ).run(receipt,anchor,Date.now(),key);
    if(Number(result.changes)!==1)
      throw new I01DispatchDenied("unknown exact I01 operation cannot be reconciled twice");
  }
  uncertain(key: string): void {
    this.db.prepare("UPDATE v3_i01_operations SET state='uncertain' WHERE operation_key=? AND state='pending'").run(key);
  }
  close(): void { this.db.close(); }
}

/**
 * Adapter for the canonical V3 WorkflowRuntime. Deliberately not installed
 * by default; production must inject all eleven real verified ports.
 */
export class I01ConsentAndAuditDispatcher implements ExecutionDispatchPort {
  constructor(
    private readonly journal: I01DurableDispatchJournal,
    private readonly devices: I01TrustedDeviceResolver,
    private readonly origins: VerifiedWorkflowOriginPort,
    private readonly owner: I01OwnerScopeAuthority,
    private readonly consent: SqliteCrossDeviceConsentAuthority,
    private readonly recipient: I01TargetLocalConsent,
    private readonly signer: I01OwnerSigner,
    private readonly transport: I01PinnedTransport,
    private readonly auditSigner: DistributedAuditSigner,
    private readonly auditAnchor: I01ExternalAuditAnchor,
    private readonly now: () => number = () => Date.now(),
  ) {}
  async execute(input: WorkflowDispatchInput): Promise<WorkflowDispatchResult> {
    const target = input.node.target.deviceId;
    if (!target || input.node.executionPolicy.allowDynamicReroute) {
      throw new I01DispatchDenied("only owner-selected exact target permitted; never dynamic reroute");
    }
    const origin = this.origins.resolve({workflowExecutionId:input.workflowExecutionId,subject:input.subject});
    if (!origin?.attested || !origin.deviceId || origin.subject !== input.subject ||
      origin.deviceId === target) throw new I01DispatchDenied("verified distinct source identity required");
    const enrolled = this.devices.resolve(target,input.node.capability);
    if (enrolled.deviceId !== target || !enrolled.heartbeatFresh) {
      throw new I01DispatchDenied("physical target P03 trust or signed heartbeat is stale");
    }
    await this.owner.authorize(origin,input.node.capability,target);
    const scope = consentRequestForDispatch(input,origin,"exact remote device operation");
    const inputHash = sha256(canonicalJson(input.node.input));
    if (scope.inputSha256 !== inputHash) throw new I01DispatchDenied("input hash mismatch");
    const operationHash = sha256(canonicalJson({
      workflowExecutionId:input.workflowExecutionId,nodeId:input.node.id,attempt:input.attempt,
      sourceDeviceId:origin.deviceId,targetDeviceId:target,subject:input.subject,
      capability:input.node.capability,inputSha256:inputHash,
    }));
    const local = await this.recipient.approveExact({
      operationSha256:operationHash,source:origin,targetDeviceId:target,subject:input.subject,
      capability:input.node.capability,inputSha256:inputHash,
      resourceDescription: typeof input.node.input["name"]==="string" ?
        String(input.node.input["name"]).slice(0,150) : "exact input SHA256: "+inputHash,
    });
    const approval = i01RecipientApprovalSchema.parse(local.approval);
    if (approval.operationSha256 !== operationHash ||
      approval.targetDeviceId !== target || approval.sourceDeviceId !== origin.deviceId ||
      approval.subject !== input.subject || approval.issuedAtMs > this.now() ||
      approval.expiresAtMs <= this.now() ||
      approval.expiresAtMs - approval.issuedAtMs > 120000 ||
      !validSignature(enrolled.devicePublicKeyPem,approval,local.deviceSignatureBase64)) {
      throw new I01DispatchDenied("target-local human approval missing or unsigned");
    }
    const granted = this.consent.consume({
      sourceDeviceId:scope.sourceDeviceId,targetDeviceId:scope.targetDeviceId,
      subject:scope.subject,capability:scope.capability,resourceKey:scope.resourceKey,
      inputSha256:scope.inputSha256,
    },origin,randomUUID());
    if (!granted.allowed) throw new I01DispatchDenied(granted.reason);
    const issued = this.now();
    const request = i01ExactOperationSchema.parse({
      schema:"radlina.v3.i01.exact-device-dispatch/v1",
      requestId:randomUUID(),workflowExecutionId:input.workflowExecutionId,
      nodeId:input.node.id,attempt:input.attempt,
      targetDeviceId:target,capability:input.node.capability,input:input.node.input,
      inputSha256:inputHash,timeoutMs:input.node.timeoutMs,
      globalCorrelationId:randomUUID(),traceId:randomUUID(),
      sourceDeviceId:origin.deviceId,subject:input.subject,
      recipientApprovalHash:sha256(canonicalJson(local)),
      issuedAtMs:issued,expiresAtMs:issued+Math.min(input.node.timeoutMs,120000),nonce:randomUUID(),
    });
    const key = sha256(canonicalJson({
      workflow:input.workflowExecutionId,node:input.node.id,attempt:input.attempt,
    }));
    const canonical = canonicalJson(request);
    const signature = await this.signer.sign(canonical);
    if (!signature || Buffer.from(signature,"base64").length !== 64) {
      throw new I01DispatchDenied("protected owner signer is unavailable");
    }
    this.journal.reserve(key,sha256(canonical),target,request.requestId);
    try {
      const ownerEnvelope: I01OwnerSignedEnvelope={operation:request,ownerSignatureBase64:signature,recipientApproval:local};
      const raw = await this.transport.sendExact(target,ownerEnvelope);
      const response = i01SignedDeviceResponseSchema.parse(raw);
      const receipt = response.receipt;
      const actualOutputHash = response.output === undefined ? null : sha256(canonicalJson(response.output));
      const signedReceipt = {
        schema:response.schema,requestId:response.requestId,
        receipt,outputSha256:response.outputSha256,
      };
      if (response.requestId !== request.requestId ||
        receipt.resolvedDeviceId !== target ||
        receipt.agentInstanceId !== enrolled.agentInstanceId ||
        receipt.workflowExecutionId !== request.workflowExecutionId ||
        receipt.nodeId !== request.nodeId || receipt.attempt !== request.attempt ||
        receipt.capability !== request.capability || receipt.inputSha256 !== inputHash ||
        receipt.globalCorrelationId !== request.globalCorrelationId ||
        receipt.traceId !== request.traceId || receipt.outputSha256 !== response.outputSha256 ||
        actualOutputHash !== response.outputSha256 ||
        !validSignature(enrolled.devicePublicKeyPem,signedReceipt,response.deviceSignatureBase64)) {
        throw new I01DispatchDenied("device signed receipt does not bind to exact execution");
      }
      const distributed = createDistributedAuditRecord({
        globalCorrelationId:request.globalCorrelationId,traceId:request.traceId,
        subject:input.subject,profile:"v3-exact",workflowExecutionId:request.workflowExecutionId,
        nodeId:request.nodeId,attempt:request.attempt,resolvedDeviceId:target,
        capability:request.capability,policyDecision:{
          allowed:true,reason:"verified owner scope, S02E consent, target-local Ed25519 approval",
          requiredScope:"device:execute",risk:"high",
        },
        inputSha256:inputHash,outputSha256:response.outputSha256,
        localAuditReceiptHash:receipt.localAuditReceiptHash,
        requestedAt:receipt.startedAt,endedAt:receipt.endedAt,terminalState:receipt.terminalState,
      },this.auditSigner);
      const anchor = await this.auditAnchor.anchor(distributed,ownerEnvelope,response,enrolled.devicePublicKeyPem);
      if (!anchor.accepted || anchor.recordHash !== distributed.recordHash || !anchor.anchorId) {
        throw new I01DispatchDenied("external S03 immutable audit anchor missing");
      }
      this.journal.complete(key,sha256(canonicalJson(receipt)),anchor.anchorId);
      return {receipt,...(response.output === undefined ? {} : {output:response.output})};
    } catch (error) {
      this.journal.uncertain(key);
      throw error;
    }
  }
  /** Explicit OAuth-owner recovery: ONLY the previously persisted original
   * P03-signed result may be externally witnessed. Never sends a command. */
  async reconcileUnknown(input:{workflowExecutionId:string;nodeId:string;
    subject:string;sourceDeviceId:string;targetDeviceId:string;
  }):Promise<WorkflowDispatchResult>{
    const origin=this.origins.resolve({
      workflowExecutionId:input.workflowExecutionId,subject:input.subject,
    });
    if(!origin?.attested||origin.deviceId!==input.sourceDeviceId||
      origin.deviceId===input.targetDeviceId)
      throw new I01DispatchDenied("exact OAuth-bound reconciliation owner/source required");
    const key=sha256(canonicalJson({
      workflow:input.workflowExecutionId,node:input.nodeId,attempt:1,
    }));
    const saved=this.journal.getForManualReconciliation(key);
    if(!saved||saved.state!=="uncertain"||
      saved.targetDeviceId!==input.targetDeviceId||
      !this.transport.readOriginalReturned)
      throw new I01DispatchDenied("no exact unknown I01 receipt ready for manual reconciliation");
    const original=await this.transport.readOriginalReturned(saved.requestId);
    if(!original)throw new I01DispatchDenied("original signed recipient receipt not yet delivered");
    const {envelope,response}=original,op=envelope.operation,receipt=response.receipt;
    if(saved.requestHash!==sha256(canonicalJson(op))||
      op.requestId!==saved.requestId||op.workflowExecutionId!==input.workflowExecutionId||
      op.nodeId!==input.nodeId||op.sourceDeviceId!==input.sourceDeviceId||
      op.targetDeviceId!==input.targetDeviceId||op.subject!==input.subject||
      op.attempt!==1||response.requestId!==op.requestId)
      throw new I01DispatchDenied("original owner operation is not the same unknown workflow");
    const enrolled=this.devices.resolve(input.targetDeviceId,op.capability);
    await this.owner.authorize(origin,op.capability,input.targetDeviceId);
    const approval=envelope.recipientApproval;
    if(op.recipientApprovalHash!==sha256(canonicalJson(approval))||
      !validSignature(enrolled.devicePublicKeyPem,approval.approval,approval.deviceSignatureBase64))
      throw new I01DispatchDenied("original recipient Ed25519 consent proof invalid");
    const signedReceipt={schema:response.schema,requestId:response.requestId,
      receipt:response.receipt,outputSha256:response.outputSha256};
    if(receipt.resolvedDeviceId!==op.targetDeviceId||
      receipt.agentInstanceId!==enrolled.agentInstanceId||
      receipt.workflowExecutionId!==op.workflowExecutionId||
      receipt.nodeId!==op.nodeId||receipt.attempt!==op.attempt||
      receipt.capability!==op.capability||receipt.inputSha256!==op.inputSha256||
      receipt.globalCorrelationId!==op.globalCorrelationId||receipt.traceId!==op.traceId||
      receipt.outputSha256!==response.outputSha256||
      (response.output===undefined?null:sha256(canonicalJson(response.output)))!==response.outputSha256||
      !validSignature(enrolled.devicePublicKeyPem,signedReceipt,response.deviceSignatureBase64))
      throw new I01DispatchDenied("original device-signed execution receipt invalid");
    const distributed=createDistributedAuditRecord({
      globalCorrelationId:op.globalCorrelationId,traceId:op.traceId,
      subject:input.subject,profile:"v3-exact",workflowExecutionId:op.workflowExecutionId,
      nodeId:op.nodeId,attempt:op.attempt,resolvedDeviceId:op.targetDeviceId,
      capability:op.capability,policyDecision:{
        allowed:true,reason:"verified owner scope, S02E consent, target-local Ed25519 approval",
        requiredScope:"device:execute",risk:"high",
      },
      inputSha256:op.inputSha256,outputSha256:response.outputSha256,
      localAuditReceiptHash:receipt.localAuditReceiptHash,
      requestedAt:receipt.startedAt,endedAt:receipt.endedAt,terminalState:receipt.terminalState,
    },this.auditSigner);
    const anchor=await this.auditAnchor.anchor(distributed,envelope,response,
      enrolled.devicePublicKeyPem);
    if(!anchor.accepted||anchor.recordHash!==distributed.recordHash||!anchor.anchorId)
      throw new I01DispatchDenied("independent S03 recovery ACK missing or signed hash changed");
    this.journal.completeManually(key,sha256(canonicalJson(receipt)),anchor.anchorId);
    return{receipt,...(response.output===undefined?{}:{output:response.output})};
  }
  async cancel(): Promise<void> {
    throw new I01DispatchDenied("unsigned/unbound cancellation cannot be dispatched");
  }
}
