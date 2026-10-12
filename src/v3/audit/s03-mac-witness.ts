/**
 * S03 independent macOS audit witness.
 *
 * This service is a separately deployed, dedicated V3 macOS process; it does
 * not share the Windows V3 controller filesystem. Both I01/F01 witnesses must
 * include the original OWNER Ed25519 signed command and target P03 Ed25519
 * signed receipt, so the witness does not blindly trust controller assertions.
 *
 * No start, key generation or deployment occurs by importing this module.
 */
import { createPublicKey, verify } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import { DatabaseSync } from "node:sqlite";
import * as z from "zod/v4";
import { canonicalJson, sha256 } from "../../utils/json.js";
import { i01SignedOwnerEnvelopeSchema, i01SignedDeviceResponseSchema } from "../integration/i01-secured-dispatch.js";
import { f01SignedCommandSchema } from "../fleet/physical-adapters.js";
import { signedDistributedAuditRecordSchema } from "./distributed.js";
import type { S03AnchorAcknowledgment, S03AnchorEvent } from "./s03-remote-anchor.js";

const HASH=z.string().regex(/^[0-9a-f]{64}$/u);
const SERVER_MAC_ID="macbook-main-s03" as const;
const eventSchema=z.object({
  schema:z.literal("radlina.v3.s03.external-event/v1"),
  kind:z.enum(["execution","fleet"]),
  recordHash:HASH,
  event:z.unknown(),
  issuedAt:z.string().datetime({offset:true}),
}).strict();
const fleetReplySchema=z.object({
  schema:z.literal("radlina.v3.f01.signed-fleet-reply/v1"),
  operationId:z.string().uuid(),
  deviceId:z.enum(["macbook-main","windows-main"]),
  agentInstanceId:z.string().uuid(),
  payload:z.unknown(),
  deviceSignatureBase64:z.string().min(80).max(200),
}).strict();
const exactFleetEvidence=z.object({
  schema:z.literal("radlina.v3.f01.audit-witness-request/v1"),
  planId:z.string().uuid(),deviceId:z.enum(["macbook-main","windows-main"]),
  commandHash:HASH,deviceReceiptHash:HASH,
  devicePublicKeyPem:z.string().includes("BEGIN PUBLIC KEY").max(4096),
  ownerSignedCommand:f01SignedCommandSchema,
  signedReply:fleetReplySchema,
}).strict();
const executionEvidence=z.object({
  record:signedDistributedAuditRecordSchema,
  ownerEnvelope:i01SignedOwnerEnvelopeSchema,
  reply:i01SignedDeviceResponseSchema,
  targetPublicKeyPem:z.string().includes("BEGIN PUBLIC KEY").max(4096),
}).strict();
export interface S03WitnessSigningKey {
  /** Physically separate macOS Keychain-backed audit witness P03 key. */
  readonly publicKeyPem:string;
  signCanonical(payload:string):Promise<string>;
}
export type S03PinnedParticipant = {
  publicKeyFingerprint:string;
  agentInstanceId:string;
};
export type S03WitnessTrustPolicy = {
  schema:"radlina.v3.s03.witness-pins/v1";
  ownerPublicKeyPem:string;
  ownerKeyFingerprint:string;
  physicalDevices:{
    "windows-main":S03PinnedParticipant;
    "macbook-main":S03PinnedParticipant;
  };
};
export class S03WitnessDenied extends Error {
  constructor(msg:string){super(msg);this.name="S03WitnessDenied";}
}
function exactSignature(key:string,record:unknown,proof:string):boolean{
  try{
    const raw=Buffer.from(proof,"base64");
    return raw.length===64&&raw.toString("base64")===proof&&
      verify(null,Buffer.from(canonicalJson(record)),createPublicKey(key),raw);
  }catch{return false;}
}
function identityCheck(policy:S03WitnessTrustPolicy,deviceId:string,key:string,instance:string){
  const pinned=policy.physicalDevices[deviceId as keyof typeof policy.physicalDevices];
  if(!pinned||sha256(createPublicKey(key).export({type:"spki",format:"der"}))!==pinned.publicKeyFingerprint||
    pinned.agentInstanceId!==instance){
    throw new S03WitnessDenied("independent device P03 key/instance pin mismatch");
  }
}
function independentlyVerify(event:S03AnchorEvent,policy:S03WitnessTrustPolicy):void{
  if(Math.abs(Date.now()-Date.parse(event.issuedAt))>60000||
    event.recordHash.length!==64){
    throw new S03WitnessDenied("S03 event expired or malformed");
  }
  if(event.kind==="execution"){
    const input=executionEvidence.parse(event.event);
    const op=input.ownerEnvelope.operation;
    const grant=input.ownerEnvelope.recipientApproval;
    const response=input.reply;
    const receipt=response.receipt;
    const record=input.record;
    const expectedHash=sha256(canonicalJson((({recordHash,signature,...rest})=>rest)(record)));
    if(event.recordHash!==record.recordHash||record.recordHash!==expectedHash||
      !exactSignature(policy.ownerPublicKeyPem,op,input.ownerEnvelope.ownerSignatureBase64)){
      throw new S03WitnessDenied("owner signed command / distributed record mismatch");
    }
    identityCheck(policy,op.targetDeviceId,input.targetPublicKeyPem,receipt.agentInstanceId);
    if(op.recipientApprovalHash!==sha256(canonicalJson(grant))||
      !exactSignature(input.targetPublicKeyPem,grant.approval,grant.deviceSignatureBase64)||
      !grant.approval.localUserApproved||
      grant.approval.targetDeviceId!==op.targetDeviceId||
      grant.approval.sourceDeviceId!==op.sourceDeviceId){
      throw new S03WitnessDenied("recipient physical signature/approval mismatch");
    }
    const signedResponse={
      schema:response.schema,requestId:response.requestId,
      receipt:response.receipt,outputSha256:response.outputSha256,
    };
    if(!exactSignature(input.targetPublicKeyPem,signedResponse,response.deviceSignatureBase64)||
      response.requestId!==op.requestId||
      receipt.workflowExecutionId!==op.workflowExecutionId||
      receipt.nodeId!==op.nodeId||receipt.attempt!==op.attempt||
      receipt.capability!==op.capability||receipt.inputSha256!==op.inputSha256||
      receipt.resolvedDeviceId!==op.targetDeviceId||
      receipt.globalCorrelationId!==op.globalCorrelationId||
      receipt.traceId!==op.traceId||
      record.workflowExecutionId!==op.workflowExecutionId||
      record.nodeId!==op.nodeId||record.resolvedDeviceId!==op.targetDeviceId||
      record.localAuditReceiptHash!==receipt.localAuditReceiptHash||
      record.inputSha256!==op.inputSha256||
      record.outputSha256!==response.outputSha256||
      (response.output===undefined?null:sha256(canonicalJson(response.output)))!==response.outputSha256){
      throw new S03WitnessDenied("target signed execution output/correlation mismatch");
    }
  }else{
    const input=exactFleetEvidence.parse(event.event);
    const command=input.ownerSignedCommand.command;
    const reply=input.signedReply;
    const toSign={
      schema:reply.schema,operationId:reply.operationId,deviceId:reply.deviceId,
      agentInstanceId:reply.agentInstanceId,payload:reply.payload,
    };
    identityCheck(policy,input.deviceId,input.devicePublicKeyPem,reply.agentInstanceId);
    if(event.recordHash!==sha256(canonicalJson(input))||
      !exactSignature(policy.ownerPublicKeyPem,command,input.ownerSignedCommand.ownerSignatureBase64)||
      !exactSignature(input.devicePublicKeyPem,toSign,reply.deviceSignatureBase64)||
      reply.deviceId!==command.deviceId||
      reply.operationId!==command.operationId||
      input.planId!==command.planId||
      input.deviceId!==command.deviceId||
      input.commandHash!==sha256(canonicalJson(command))||
      input.deviceReceiptHash!==sha256(canonicalJson(reply.payload))||
      command.issuedAtMs>Date.now()||
      command.expiresAtMs<=command.issuedAtMs||
      command.expiresAtMs-command.issuedAtMs>90000){
      throw new S03WitnessDenied("owner/recipient signed physical fleet manifest receipt mismatch");
    }
  }
}
export class S03MacIndependentWitnessJournal {
  readonly db:DatabaseSync;
  constructor(
    file:string,
    private readonly signer:S03WitnessSigningKey,
    private readonly policy:S03WitnessTrustPolicy,
  ){
    if(process.platform!=="darwin"||os.hostname()!=="amirs-MacBook-Pro.local"||
      !path.isAbsolute(file)||file.includes("v2")||
      sha256(createPublicKey(policy.ownerPublicKeyPem).export({type:"spki",format:"der"}))!==
        policy.ownerKeyFingerprint){
      throw new S03WitnessDenied("physical Mac independent owner-pinned V3 audit witness required");
    }
    mkdirSync(path.dirname(file),{recursive:true,mode:0o700});
    this.db=new DatabaseSync(file,{enableForeignKeyConstraints:true});
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec("CREATE TABLE IF NOT EXISTS v3_s03_external_chain("+
      "sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_hash TEXT UNIQUE NOT NULL,"+
      "prev_hash TEXT NOT NULL,chain_head TEXT UNIQUE NOT NULL,"+
      "record_hash TEXT NOT NULL,event_json TEXT NOT NULL,"+
      "ack_json TEXT NOT NULL,ack_signature TEXT NOT NULL);");
    this.db.exec(
      "CREATE TRIGGER IF NOT EXISTS s03_no_update BEFORE UPDATE ON v3_s03_external_chain "+
      "BEGIN SELECT RAISE(ABORT,'append_only'); END;"+
      "CREATE TRIGGER IF NOT EXISTS s03_no_delete BEFORE DELETE ON v3_s03_external_chain "+
      "BEGIN SELECT RAISE(ABORT,'append_only'); END;"
    );
  }
  async anchor(payload:unknown):Promise<{
    receipt:S03AnchorAcknowledgment;deviceSignatureBase64:string;
  }>{
    const event=eventSchema.parse(payload);
    independentlyVerify(event,this.policy);
    const hash=sha256(canonicalJson(event));
    const exists=this.db.prepare(
      "SELECT ack_json,ack_signature FROM v3_s03_external_chain WHERE event_hash=?"
    ).get(hash) as {ack_json:string;ack_signature:string}|undefined;
    if(exists)return{
      receipt:JSON.parse(exists.ack_json) as S03AnchorAcknowledgment,
      deviceSignatureBase64:exists.ack_signature,
    };
    this.db.exec("BEGIN IMMEDIATE");
    try{
      const last=this.db.prepare(
        "SELECT sequence,chain_head FROM v3_s03_external_chain ORDER BY sequence DESC LIMIT 1"
      ).get() as {sequence:number;chain_head:string}|undefined;
      const sequence=(last?.sequence??0)+1;
      const before=last?.chain_head??"0".repeat(64);
      const chainHead=sha256(canonicalJson({before,eventHash:hash,sequence}));
      const receipt:S03AnchorAcknowledgment={
        schema:"radlina.v3.s03.external-anchor/v1",
        auditNode:SERVER_MAC_ID,eventHash:hash,recordHash:event.recordHash,
        chainHead,sequence,anchoredAt:new Date().toISOString(),
      };
      const proof=await this.signer.signCanonical(canonicalJson(receipt));
      if(!exactSignature(this.signer.publicKeyPem,receipt,proof))
        throw new S03WitnessDenied("independent Mac audit signing failed");
      this.db.prepare(
        "INSERT INTO v3_s03_external_chain(event_hash,prev_hash,chain_head,record_hash,"+
        "event_json,ack_json,ack_signature) VALUES(?,?,?,?,?,?,?)"
      ).run(hash,before,chainHead,event.recordHash,canonicalJson(event),canonicalJson(receipt),proof);
      this.db.exec("COMMIT");
      return{receipt,deviceSignatureBase64:proof};
    }catch(error){this.db.exec("ROLLBACK");throw error;}
  }
  close():void{this.db.close();}
}
