/**
 * I01 durable V3 relay for devices without inbound public sockets.
 * The physical Mac pulls exact owner-signed work with a device-key session;
 * it cannot claim Windows work, and lease expiry NEVER re-dispatches a mutation.
 *
 * No listener is registered by importing this module. Production composition
 * must supply sealed storage, P03 target authentication and target-local UI.
 */
import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { createPublicKey, randomUUID, verify } from "node:crypto";
import { canonicalJson, sha256 } from "../../utils/json.js";
import {
  i01SignedOwnerEnvelopeSchema,
  i01SignedDeviceResponseSchema,
  type I01PinnedTransport as I01BoundDeviceTransport,
  type I01OwnerSignedEnvelope,
  type I01SignedDeviceResponse,
} from "./i01-secured-dispatch.js";

export interface I01SealedOutboxData {
  /** Dedicated V3 DPAPI/Keychain data key; never store plaintext payloads in WAL. */
  seal(value:Uint8Array):Promise<Uint8Array>;
  unseal(value:Uint8Array):Promise<Uint8Array>;
}
export interface I01PhysicalDeviceSession {
  /** Target P03 Keychain signature, fresh request nonce, live pinned Tailnet peer. */
  assertPhysicalAgent(input:{
    deviceId:string;nonce:string;signedAtMs:number;signatureBase64:string;
  }):Promise<void>;
  /** Trusted P03 registry identity, never supplied by an HTTP caller. */
  trustedDeviceReceiptKey?(deviceId:string):{
    devicePublicKeyPem:string;agentInstanceId:string;
  };
}
export type I01SignedPull = {
  deviceId:string;
  nonce:string;
  signedAtMs:number;
  signatureBase64:string;
};
export type I01LeasedPhysicalOperation = {
  leaseId:string;
  targetDeviceId:string;
  envelope:I01OwnerSignedEnvelope;
};
export class I01OutboxDenied extends Error {
  constructor(message:string){super(message);this.name="I01OutboxDenied";}
}
type OutboxRow = {
  request_id:string;
  device_id:string;
  state:"ready"|"leased"|"returned"|"unknown";
  sealed_message:Uint8Array;
  sealed_result:Uint8Array|null;
  operation_hash:string;
  expires_at_ms:number;
  lease_id:string|null;
};
export class I01DurableSealedOutbox implements I01BoundDeviceTransport {
  readonly db:DatabaseSync;
  constructor(
    databaseFile:string,
    private readonly crypt:I01SealedOutboxData,
    private readonly authenticate:I01PhysicalDeviceSession,
    private readonly now:()=>number=()=>Date.now(),
  ){
    if(!path.isAbsolute(databaseFile)||databaseFile.toLowerCase().includes("\\v2\\"))
      throw new I01OutboxDenied("independent V3 sealed outbox path required");
    mkdirSync(path.dirname(databaseFile),{recursive:true});
    this.db=new DatabaseSync(databaseFile,{enableForeignKeyConstraints:true});
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS v3_i01_outbox("+
      "request_id TEXT PRIMARY KEY,device_id TEXT NOT NULL,"+
      "operation_hash TEXT NOT NULL, sealed_message BLOB NOT NULL,"+
      "sealed_result BLOB,expires_at_ms INTEGER NOT NULL,"+
      "state TEXT NOT NULL CHECK(state IN ('ready','leased','returned','unknown')),"+
      "lease_id TEXT UNIQUE,created_at_ms INTEGER NOT NULL,completed_at_ms INTEGER);"
    );
  }
  private row(id:string):OutboxRow|undefined {
    return this.db.prepare(
      "SELECT request_id,device_id,operation_hash,sealed_message,sealed_result,"+
      "expires_at_ms,state,lease_id FROM v3_i01_outbox WHERE request_id=?"
    ).get(id) as OutboxRow|undefined;
  }
  async sendExact(deviceId:string,raw:I01OwnerSignedEnvelope):Promise<I01SignedDeviceResponse>{
    const envelope=i01SignedOwnerEnvelopeSchema.parse(raw);
    const op=envelope.operation;
    if(!["macbook-main","windows-main"].includes(deviceId)||
      op.targetDeviceId!==deviceId||op.expiresAtMs<=this.now()||
      op.expiresAtMs-op.issuedAtMs>120000||
      !envelope.ownerSignatureBase64||
      !envelope.recipientApproval.deviceSignatureBase64){
      throw new I01OutboxDenied("exact signed operation and target approval required");
    }
    const canonical=canonicalJson(envelope);
    const digest=sha256(canonical);
    const sealed=await this.crypt.seal(Buffer.from(canonical,"utf8"));
    if(sealed.byteLength<32||sealed.byteLength>262144)
      throw new I01OutboxDenied("sealed exact operation envelope outside bounds");
    const current=this.row(op.requestId);
    if(current)throw new I01OutboxDenied(
      current.operation_hash===digest ? "existing operation must be reconciled" : "request ID collision"
    );
    this.db.prepare(
      "INSERT INTO v3_i01_outbox(request_id,device_id,operation_hash,sealed_message,expires_at_ms,state,created_at_ms) "+
      "VALUES(?,?,?,?,?,'ready',?)"
    ).run(op.requestId,deviceId,digest,sealed,op.expiresAtMs,this.now());
    while(this.now()<op.expiresAtMs){
      const result=this.row(op.requestId);
      if(result?.state==="returned"&&result.sealed_result){
        const raw=await this.crypt.unseal(result.sealed_result);
        if(raw.byteLength>262144)throw new I01OutboxDenied("bounded sealed result required");
        return i01SignedDeviceResponseSchema.parse(JSON.parse(Buffer.from(raw).toString("utf8")));
      }
      if(result?.state==="unknown")break;
      await new Promise<void>(resolve=>setTimeout(resolve,250));
    }
    // If a network response was lost, the physical action may have completed.
    // Never place this message back into the executable queue automatically.
    this.db.prepare(
      "UPDATE v3_i01_outbox SET state='unknown' WHERE request_id=? AND state IN ('ready','leased')"
    ).run(op.requestId);
    throw new I01OutboxDenied("remote outcome unknown, manual signed reconciliation required");
  }
  async claimNext(session:I01SignedPull):Promise<I01LeasedPhysicalOperation|null>{
    if(!["macbook-main","windows-main"].includes(session.deviceId)||
      !session.nonce||Math.abs(this.now()-session.signedAtMs)>60000)
      throw new I01OutboxDenied("signed physical polling session stale");
    await this.authenticate.assertPhysicalAgent(session);
    const row=this.db.prepare(
      "SELECT request_id FROM v3_i01_outbox "+
      "WHERE device_id=? AND state='ready' AND expires_at_ms>? "+
      "ORDER BY created_at_ms LIMIT 1"
    ).get(session.deviceId,this.now()) as {request_id:string}|undefined;
    if(!row)return null;
    const leaseId=randomUUID();
    const changed=this.db.prepare(
      "UPDATE v3_i01_outbox SET state='leased',lease_id=? "+
      "WHERE request_id=? AND device_id=? AND state='ready' AND expires_at_ms>?"
    ).run(leaseId,row.request_id,session.deviceId,this.now());
    if(Number(changed.changes)!==1)return null;
    const leased=this.row(row.request_id);
    if(!leased||leased.lease_id!==leaseId)
      throw new I01OutboxDenied("physical claim CAS mismatch");
    const raw=await this.crypt.unseal(leased.sealed_message);
    if(raw.byteLength>262144)throw new I01OutboxDenied("oversized signed operation");
    const envelope=i01SignedOwnerEnvelopeSchema.parse(JSON.parse(Buffer.from(raw).toString("utf8")));
    if(envelope.operation.targetDeviceId!==session.deviceId||
      sha256(canonicalJson(envelope))!==leased.operation_hash){
      throw new I01OutboxDenied("physical target or sealed owner envelope changed");
    }
    return {leaseId,targetDeviceId:session.deviceId,envelope};
  }
  /** Re-delivery of the SAME signed original is safe even after the lease
   * expires; never claim or execute a new native operation on replay. */
  async deliverSignedResult(
    session:I01SignedPull,leaseId:string,response:I01SignedDeviceResponse,
  ):Promise<void>{
    if(!leaseId||!response.requestId||
      !["macbook-main","windows-main"].includes(session.deviceId)||
      Math.abs(this.now()-session.signedAtMs)>60000)
      throw new I01OutboxDenied("fresh P03-signed target delivery session required");
    await this.authenticate.assertPhysicalAgent(session);
    const reply=i01SignedDeviceResponseSchema.parse(response);
    const row=this.row(reply.requestId);
    if(!row||row.device_id!==session.deviceId||row.lease_id!==leaseId||
      !["leased","unknown","returned"].includes(row.state))
      throw new I01OutboxDenied("original exact leased operation not found");
    const owner=i01SignedOwnerEnvelopeSchema.parse(JSON.parse(
      Buffer.from(await this.crypt.unseal(row.sealed_message)).toString("utf8"),
    ));
    if(sha256(canonicalJson(owner))!==row.operation_hash||
      owner.operation.requestId!==reply.requestId||
      owner.operation.targetDeviceId!==session.deviceId)
      throw new I01OutboxDenied("recovered original owner-signed command changed");
    const pinned=this.authenticate.trustedDeviceReceiptKey?.(session.deviceId);
    if(!pinned)throw new I01OutboxDenied("enrolled P03 device signing key missing");
    const receipt=reply.receipt,op=owner.operation;
    const signedData={schema:reply.schema,requestId:reply.requestId,
      receipt,outputSha256:reply.outputSha256};
    const proof=Buffer.from(reply.deviceSignatureBase64,"base64");
    if(reply.schema!=="radlina.v3.i01.signed-device-response/v1"||
      receipt.resolvedDeviceId!==session.deviceId||
      receipt.agentInstanceId!==pinned.agentInstanceId||
      receipt.workflowExecutionId!==op.workflowExecutionId||
      receipt.nodeId!==op.nodeId||receipt.attempt!==op.attempt||
      receipt.capability!==op.capability||receipt.inputSha256!==op.inputSha256||
      receipt.globalCorrelationId!==op.globalCorrelationId||
      receipt.traceId!==op.traceId||
      (reply.output===undefined?null:sha256(canonicalJson(reply.output)))!==reply.outputSha256||
      proof.length!==64||proof.toString("base64")!==reply.deviceSignatureBase64||
      !verify(null,Buffer.from(canonicalJson(signedData)),
        createPublicKey(pinned.devicePublicKeyPem),proof))
      throw new I01OutboxDenied("original P03 target-signed receipt invalid");
    const canonical=canonicalJson(reply);
    if(row.state==="returned"){
      if(!row.sealed_result||
        canonicalJson(JSON.parse(Buffer.from(await this.crypt.unseal(row.sealed_result)).toString("utf8")))!==canonical)
        throw new I01OutboxDenied("conflicting original signed recipient receipt");
      return; // Idempotent ACK; never re-execute a native capability.
    }
    const sealed=await this.crypt.seal(Buffer.from(canonical,"utf8"));
    if(sealed.byteLength>262144)
      throw new I01OutboxDenied("sealed exact recipient receipt exceeds bound");
    const written=this.db.prepare(
      "UPDATE v3_i01_outbox SET state='returned',sealed_result=?,completed_at_ms=? "+
      "WHERE request_id=? AND lease_id=? AND state IN ('leased','unknown') "+
      "AND sealed_result IS NULL",
    ).run(sealed,this.now(),reply.requestId,leaseId);
    if(Number(written.changes)!==1)
      throw new I01OutboxDenied("original signed recipient result CAS conflicted");
    // S03/owner manual reconcilers must still independently anchor the result.
  }
  async readOriginalReturned(requestId:string):Promise<{
    envelope:I01OwnerSignedEnvelope;response:I01SignedDeviceResponse;
  }|null>{
    const row=this.row(requestId);
    if(!row||row.state!=="returned"||!row.sealed_result)return null;
    const original=await this.crypt.unseal(row.sealed_message);
    const result=await this.crypt.unseal(row.sealed_result);
    if(original.length>262144||result.length>262144)
      throw new I01OutboxDenied("original sealed manual-reconcile evidence oversized");
    const envelope=i01SignedOwnerEnvelopeSchema.parse(JSON.parse(Buffer.from(original).toString("utf8")));
    const response=i01SignedDeviceResponseSchema.parse(JSON.parse(Buffer.from(result).toString("utf8")));
    if(envelope.operation.requestId!==requestId||response.requestId!==requestId||
      envelope.operation.targetDeviceId!==row.device_id||
      sha256(canonicalJson(envelope))!==row.operation_hash)
      throw new I01OutboxDenied("sealed original result/owner command mismatch");
    return{envelope,response};
  }
  close():void{this.db.close();}
}
