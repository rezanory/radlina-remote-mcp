/**
 * I01 recipient-side counterpart, deliberately NOT an inbound remote shell.
 * A real Mac/Windows target accepts only one exact owner-signed operation after
 * its own interactive human consent, live identity check and durable local audit.
 */
import { createPublicKey, verify } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { canonicalJson, sha256 } from "../../utils/json.js";
import { agentExecutionReceiptSchema } from "../device/agent-protocol.js";
import {
  i01RecipientApprovalSchema,
  i01SignedOwnerEnvelopeSchema,
  type I01ExactSignedOperation,
  type I01SignedDeviceResponse,
} from "./i01-secured-dispatch.js";

const HASH = /^[0-9a-f]{64}$/u;
export interface I01TargetIdentity {
  deviceId: string;
  agentInstanceId: string;
  publicKeyPem: string;
  publicKeyFingerprint: string;
  verifiedSignedHeartbeatFresh: true;
  installedCapabilities: ReadonlySet<string>;
}
export interface I01TargetPeerPresence {
  /** Source Tailnet identity must be observed by the TARGET itself, not request. */
  physicallyVerifiedController(): Promise<boolean>;
}
export interface I01TargetLocalApprovalStore {
  /** Authenticated native UI decision persisted on the recipient, never forwarded caller claims. */
  requireMatchingInteractiveGrant(input: {
    nonce: string;
    operationSha256: string;
    sourceDeviceId: string;
    targetDeviceId: string;
    subject: string;
    capability: string;
    inputSha256: string;
    expiresAtMs: number;
  }): Promise<boolean>;
}
export interface I01TargetNativeCapabilities {
  /** Only installed, explicitly allowlisted capabilities. No raw shell fallback. */
  executeExact(capability: string, input: Record<string,unknown>, timeoutMs: number): Promise<unknown>;
}
export interface I01TargetProtectedSigner {
  signCanonical(payload: string): Promise<string>;
}
export interface I01TargetLocalAudit {
  /** Local append-only receipt, persisted before releasing a result. */
  anchor(input: {
    sourceDeviceId: string;
    targetDeviceId: string;
    requestId: string;
    capability: string;
    inputSha256: string;
    outputSha256: string | null;
    startedAt: string;
    endedAt: string;
  }): Promise<{durable:true; localAuditReceiptHash:string}>;
}
export class I01TargetDenied extends Error {
  constructor(message:string){super(message);this.name="I01TargetDenied";}
}
function exactSignature(pem:string,message:unknown,signature:string):boolean{
  try{
    const proof=Buffer.from(signature,"base64");
    return proof.length===64&&proof.toString("base64")===signature&&
      verify(null,Buffer.from(canonicalJson(message)),createPublicKey(pem),proof);
  }catch{return false;}
}

function operationIdentityHash(operation:I01ExactSignedOperation):string{
  return sha256(canonicalJson({
    workflowExecutionId:operation.workflowExecutionId,
    nodeId:operation.nodeId,attempt:operation.attempt,
    sourceDeviceId:operation.sourceDeviceId,
    targetDeviceId:operation.targetDeviceId,
    subject:operation.subject,capability:operation.capability,
    inputSha256:operation.inputSha256,
  }));
}
export class I01TargetReplayLedger{
  readonly db:DatabaseSync;
  constructor(file:string){
    if(!path.isAbsolute(file)||file.toLowerCase().includes("\\v2\\"))
      throw new I01TargetDenied("isolated device-specific V3 replay ledger required");
    mkdirSync(path.dirname(file),{recursive:true});
    this.db=new DatabaseSync(file,{enableForeignKeyConstraints:true});
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS v3_i01_target_operations("+
      "request_id TEXT PRIMARY KEY,nonce TEXT NOT NULL UNIQUE,operation_hash TEXT NOT NULL,"+
      "state TEXT NOT NULL CHECK(state IN ('pending','completed','uncertain')),"+
      "local_audit_hash TEXT,created_at_ms INTEGER NOT NULL);"
    );
  }
  reserve(requestId:string,nonce:string,operationHash:string):void{
    // Unique constraints serialize duplicate arrivals in SQLite; no network retry.
    this.db.prepare(
      "INSERT INTO v3_i01_target_operations(request_id,nonce,operation_hash,state,created_at_ms) "+
      "VALUES(?,?,?,'pending',?)"
    ).run(requestId,nonce,operationHash,Date.now());
  }
  complete(requestId:string,auditHash:string):void{
    const changed=this.db.prepare(
      "UPDATE v3_i01_target_operations SET state='completed',local_audit_hash=? "+
      "WHERE request_id=? AND state='pending'"
    ).run(auditHash,requestId);
    if(Number(changed.changes)!==1)throw new I01TargetDenied("target receipt persistence CAS failed");
  }
  uncertain(requestId:string):void{
    this.db.prepare(
      "UPDATE v3_i01_target_operations SET state='uncertain' "+
      "WHERE request_id=? AND state='pending'"
    ).run(requestId);
  }
  close():void{this.db.close();}
}

/**
 * Bind this only to an authenticated physical agent listener. Caller network
 * access alone does not satisfy any of the independent authorization gates.
 */
export class I01RecipientExecutionAgent{
  constructor(
    private readonly device:I01TargetIdentity,
    private readonly ownerPublicKeyPem:string,
    private readonly ownerFingerprint:string,
    private readonly peer:I01TargetPeerPresence,
    private readonly approval:I01TargetLocalApprovalStore,
    private readonly capability:I01TargetNativeCapabilities,
    private readonly signer:I01TargetProtectedSigner,
    private readonly audit:I01TargetLocalAudit,
    private readonly journal:I01TargetReplayLedger,
    private readonly now:()=>number=()=>Date.now(),
  ){
    const fingerprint=sha256(createPublicKey(ownerPublicKeyPem).export({type:"spki",format:"der"}));
    if(fingerprint!==ownerFingerprint||!HASH.test(device.publicKeyFingerprint)||!device.deviceId)
      throw new I01TargetDenied("physical P03 owner and device pins required");
  }
  async receive(raw:unknown):Promise<I01SignedDeviceResponse>{
    const input = i01SignedOwnerEnvelopeSchema.parse(raw);
    const op=input.operation;
    if(op.schema!=="radlina.v3.i01.exact-device-dispatch/v1"||
      op.targetDeviceId!==this.device.deviceId||
      !this.device.verifiedSignedHeartbeatFresh||
      !this.device.installedCapabilities.has(op.capability)||
      op.inputSha256!==sha256(canonicalJson(op.input))||
      op.issuedAtMs>this.now()||op.expiresAtMs<=this.now()||
      op.expiresAtMs-op.issuedAtMs>120000||
      op.timeoutMs>120000||
      !exactSignature(this.ownerPublicKeyPem,op,input.ownerSignatureBase64)){
      throw new I01TargetDenied("bound signed owner operation invalid or expired");
    }
    const approval=i01RecipientApprovalSchema.parse(input.recipientApproval.approval);
    const opHash=operationIdentityHash(op);
    if(approval.operationSha256!==opHash||
      approval.sourceDeviceId!==op.sourceDeviceId||
      approval.targetDeviceId!==op.targetDeviceId||
      approval.subject!==op.subject||
      op.recipientApprovalHash!==sha256(canonicalJson(input.recipientApproval))||
      approval.issuedAtMs>this.now()||
      approval.expiresAtMs<=this.now()||
      approval.expiresAtMs-approval.issuedAtMs>120000||
      !exactSignature(this.device.publicKeyPem,approval,input.recipientApproval.deviceSignatureBase64)){
      throw new I01TargetDenied("recipient target local signed approval invalid");
    }
    if(!await this.peer.physicallyVerifiedController()) {
      throw new I01TargetDenied("physical source device identity not observed by recipient");
    }
    if(!await this.approval.requireMatchingInteractiveGrant({
      nonce:approval.nonce,
      operationSha256:opHash,
      sourceDeviceId:op.sourceDeviceId,targetDeviceId:op.targetDeviceId,
      subject:op.subject,capability:op.capability,
      inputSha256:op.inputSha256,expiresAtMs:approval.expiresAtMs,
    })){
      throw new I01TargetDenied("recipient must approve exact operation in its own local UI");
    }
    this.journal.reserve(op.requestId,op.nonce,sha256(canonicalJson(op)));
    const startedAt=new Date(this.now()).toISOString();
    try{
      const output=await this.capability.executeExact(op.capability,op.input,op.timeoutMs);
      const endedAt=new Date(this.now()).toISOString();
      const outputSha256=output===undefined?null:sha256(canonicalJson(output));
      const anchored=await this.audit.anchor({
        sourceDeviceId:op.sourceDeviceId,targetDeviceId:op.targetDeviceId,
        requestId:op.requestId,capability:op.capability,inputSha256:op.inputSha256,
        outputSha256,startedAt,endedAt,
      });
      if(!anchored.durable||!HASH.test(anchored.localAuditReceiptHash))
        throw new I01TargetDenied("target-local immutable audit receipt missing");
      const receipt=agentExecutionReceiptSchema.parse({
        workflowExecutionId:op.workflowExecutionId,nodeId:op.nodeId,
        attempt:op.attempt,resolvedDeviceId:this.device.deviceId,
        capability:op.capability,inputSha256:op.inputSha256,
        startedAt,endedAt,terminalState:"completed",
        outputSha256,localAuditReceiptHash:anchored.localAuditReceiptHash,
        globalCorrelationId:op.globalCorrelationId,traceId:op.traceId,
        agentInstanceId:this.device.agentInstanceId,errorCode:null,
      });
      const signedData={
        schema:"radlina.v3.i01.signed-device-response/v1" as const,
        requestId:op.requestId,
        receipt,
        outputSha256,
      };
      const deviceSignatureBase64=await this.signer.signCanonical(canonicalJson(signedData));
      if(Buffer.from(deviceSignatureBase64,"base64").length!==64)
        throw new I01TargetDenied("protected recipient device signing key unavailable");
      this.journal.complete(op.requestId,anchored.localAuditReceiptHash);
      return {
        ...signedData,
        ...(output===undefined?{}:{output}),
        deviceSignatureBase64,
      };
    }catch(error){
      this.journal.uncertain(op.requestId);
      throw error;
    }
  }
}
