/**
 * Target-side F01 V3 release agent (source only, no service actions here).
 * OS-specific release switching must be implemented behind LocalV3ReleaseHost,
 * and MUST NOT modify Radlina Remote MCP V2 or its service/registry.
 */
import { createPublicKey, verify } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { canonicalJson, sha256 } from "../../utils/json.js";
import type {
  FleetAttestation, FleetSwitchReceipt, FleetVerifyReceipt, FleetOperation,
} from "./contracts.js";
import { f01SignedCommandSchema, type F01PhysicalCommand, type F01SignedReply } from "./physical-adapters.js";

type NativeFleetResult = FleetAttestation | FleetSwitchReceipt | FleetVerifyReceipt;
export interface LocalV3ReleaseHost {
  readonly deviceId: "windows-main" | "macbook-main";
  readonly dedicatedV3ReleaseRoot: string;
  /** Exact manifest digest of a locally staged, verified V3 release. */
  verifyStagedManifest(hash: string): Promise<boolean>;
  currentManifest(): Promise<string>;
  /** V3-only service activation via a provider-specific reversible pointer. */
  activateExactManifest(hash: string, expectedPreviousHash: string): Promise<void>;
  verifyActiveRelease(hash: string): Promise<{health: "healthy"|"degraded"|"unhealthy"|"unknown"}>;
}
export interface F01TargetKeyPort {
  deviceId: "windows-main"|"macbook-main";
  agentInstanceId: string;
  publicKeyFingerprint: string;
  liveP03KeyAndHeartbeat(): Promise<boolean>;
  signReceipt(payload: string): Promise<string>;
}
export interface F01TargetHumanApproval {
  /** Target-local user explicitly approves this exact operation and release digests. */
  check(operation: F01PhysicalCommand): Promise<boolean>;
}
export interface F01TargetLocalReceiptJournal {
  append(input: {
    commandHash: string; deviceId: string; action: FleetOperation;
    before: string; after: string; terminal: "completed";
  }): Promise<{durable:true; localReceiptHash:string}>;
}
export class F01RecipientDenied extends Error {
  constructor(message:string){super(message);this.name="F01RecipientDenied";}
}
function verifiedOwnerSignature(keyPem:string,command:F01PhysicalCommand,signature:string):boolean{
  try{
    const proof=Buffer.from(signature,"base64");
    return proof.length===64&&proof.toString("base64")===signature&&
      verify(null,Buffer.from(canonicalJson(command)),createPublicKey(keyPem),proof);
  }catch{return false;}
}
export class F01LocalReplayStore {
  readonly db:DatabaseSync;
  constructor(file:string){
    if(!path.isAbsolute(file)||file.toLowerCase().includes("\\v2\\"))
      throw new F01RecipientDenied("independent physical V3 target journal required");
    mkdirSync(path.dirname(file),{recursive:true});
    this.db=new DatabaseSync(file,{enableForeignKeyConstraints:true});
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS v3_f01_target_switches("+
      "operation_id TEXT PRIMARY KEY, nonce TEXT NOT NULL UNIQUE, command_hash TEXT NOT NULL,"+
      "state TEXT NOT NULL CHECK(state IN ('pending','anchored','uncertain')),"+
      "local_receipt_hash TEXT, created_at_ms INTEGER NOT NULL);"
    );
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS v3_f01_target_signed_replies("+
      "operation_id TEXT PRIMARY KEY REFERENCES v3_f01_target_switches(operation_id),"+
      "response_json TEXT NOT NULL,response_sha256 TEXT NOT NULL,created_at_ms INTEGER NOT NULL);"
    );
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS v3_f01_target_delivery_leases("+
      "operation_id TEXT PRIMARY KEY,lease_id TEXT NOT NULL UNIQUE,reported_at_ms INTEGER);"
    );
  }
  recordLease(operationId:string,leaseId:string):void{
    const check=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
    if(!check.test(operationId)||!check.test(leaseId))
      throw new F01RecipientDenied("exact original fleet lease UUID required");
    this.db.prepare(
      "INSERT OR IGNORE INTO v3_f01_target_delivery_leases(operation_id,lease_id) VALUES(?,?)",
    ).run(operationId,leaseId);
    const saved=this.db.prepare(
      "SELECT lease_id FROM v3_f01_target_delivery_leases WHERE operation_id=?",
    ).get(operationId) as {lease_id:string}|undefined;
    if(saved?.lease_id!==leaseId)
      throw new F01RecipientDenied("different native fleet lease replay denied");
  }
  nextUndelivered():{operationId:string;leaseId:string;reply:F01SignedReply<NativeFleetResult>}|undefined{
    const row=this.db.prepare(
      "SELECT l.operation_id,l.lease_id FROM v3_f01_target_delivery_leases l "+
      "JOIN v3_f01_target_switches o ON o.operation_id=l.operation_id "+
      "JOIN v3_f01_target_signed_replies r ON r.operation_id=l.operation_id "+
      "WHERE l.reported_at_ms IS NULL AND o.state='anchored' "+
      "ORDER BY o.created_at_ms LIMIT 1",
    ).get() as {operation_id:string;lease_id:string}|undefined;
    if(!row)return undefined;
    const reply=this.getAnchoredSigned(row.operation_id);
    if(!reply)throw new F01RecipientDenied("original signed release reply missing");
    return{operationId:row.operation_id,leaseId:row.lease_id,reply};
  }
  markReported(operationId:string):void{
    const updated=this.db.prepare(
      "UPDATE v3_f01_target_delivery_leases SET reported_at_ms=? "+
      "WHERE operation_id=? AND reported_at_ms IS NULL",
    ).run(Date.now(),operationId);
    if(Number(updated.changes)!==1){
      const saved=this.db.prepare(
        "SELECT reported_at_ms FROM v3_f01_target_delivery_leases WHERE operation_id=?",
      ).get(operationId) as {reported_at_ms:number|null}|undefined;
      if(!saved?.reported_at_ms)
        throw new F01RecipientDenied("fleet signed report acceptance not durably recorded");
    }
  }
  reserve(command:F01PhysicalCommand):void{
    this.db.prepare(
      "INSERT INTO v3_f01_target_switches(operation_id,nonce,command_hash,state,created_at_ms)"+
      " VALUES(?,?,?,'pending',?)"
    ).run(command.operationId,command.nonce,sha256(canonicalJson(command)),Date.now());
  }
  anchoredSigned(id:string,receiptHash:string,reply:F01SignedReply<NativeFleetResult>):void{
    if(!/^[a-f0-9]{64}$/u.test(receiptHash)||reply.operationId!==id)
      throw new F01RecipientDenied("exact F01 local receipt and operation id required");
    const serialized=canonicalJson(reply);
    if(Buffer.byteLength(serialized,"utf8")>256*1024)
      throw new F01RecipientDenied("bounded physical fleet signed receipt required");
    this.db.exec("BEGIN IMMEDIATE");
    try{
      const saved=this.db.prepare(
        "INSERT INTO v3_f01_target_signed_replies(operation_id,response_json,response_sha256,created_at_ms) "+
        "VALUES(?,?,?,?)",
      ).run(id,serialized,sha256(serialized),Date.now());
      const row=this.db.prepare(
        "UPDATE v3_f01_target_switches SET state='anchored',local_receipt_hash=? "+
        "WHERE operation_id=? AND state='pending'",
      ).run(receiptHash,id);
      if(Number(saved.changes)!==1||Number(row.changes)!==1)
        throw new F01RecipientDenied("target switch signed receipt durable CAS conflict");
      this.db.exec("COMMIT");
    }catch(error){this.db.exec("ROLLBACK");throw error;}
  }
  /** Owner-local recovery reads signed evidence; no native service execution. */
  getAnchoredSigned(id:string):F01SignedReply<NativeFleetResult>|undefined{
    const row=this.db.prepare(
      "SELECT r.response_json,r.response_sha256,o.state FROM v3_f01_target_signed_replies r "+
      "JOIN v3_f01_target_switches o ON o.operation_id=r.operation_id "+
      "WHERE r.operation_id=? LIMIT 1",
    ).get(id) as {response_json:string;response_sha256:string;state:string}|undefined;
    if(!row)return undefined;
    if(row.state!=="anchored"||sha256(row.response_json)!==row.response_sha256)
      throw new F01RecipientDenied("signed target fleet response integrity changed");
    return JSON.parse(row.response_json) as F01SignedReply<NativeFleetResult>;
  }
  uncertain(id:string):void{
    this.db.prepare(
      "UPDATE v3_f01_target_switches SET state='uncertain' "+
      "WHERE operation_id=? AND state='pending'"
    ).run(id);
  }
  close():void{this.db.close();}
}

/**
 * Target executes only after exact owner Ed25519 signature and local user grant.
 * An unknown physical activation outcome is never retried without reconciliation.
 */
export class F01PhysicalRecipientAgent{
  constructor(
    private readonly host:LocalV3ReleaseHost,
    private readonly identity:F01TargetKeyPort,
    private readonly ownerPublicKeyPem:string,
    private readonly ownerFingerprint:string,
    private readonly recipient:F01TargetHumanApproval,
    private readonly audit:F01TargetLocalReceiptJournal,
    private readonly journal:F01LocalReplayStore,
    private readonly now:()=>number=()=>Date.now(),
  ){
    if(
      host.deviceId!==identity.deviceId||
      !path.isAbsolute(host.dedicatedV3ReleaseRoot)||
      host.dedicatedV3ReleaseRoot.toLowerCase().includes("v2")||
      sha256(createPublicKey(ownerPublicKeyPem).export({type:"spki",format:"der"}))!==ownerFingerprint
    ) throw new F01RecipientDenied("physical V3-only recipient and pinned owner signer required");
  }
  async execute(raw:unknown):Promise<F01SignedReply<NativeFleetResult>>{
    const request=f01SignedCommandSchema.parse(raw);
    const command=request.command;
    if(command.schema!=="radlina.v3.f01.exact-fleet-operation/v1"||
      command.deviceId!==this.host.deviceId||
      command.issuedAtMs>this.now()||command.expiresAtMs<=this.now()||
      command.expiresAtMs-command.issuedAtMs>90000||
      command.targetManifestSha256===command.previousManifestSha256||
      !/^[0-9a-f]{64}$/u.test(command.targetManifestSha256)||
      !/^[0-9a-f]{64}$/u.test(command.previousManifestSha256)||
      !verifiedOwnerSignature(this.ownerPublicKeyPem,command,request.ownerSignatureBase64)||
      !await this.identity.liveP03KeyAndHeartbeat()||
      !await this.recipient.check(command)) {
      throw new F01RecipientDenied("exact owner/device signature, live trust or local release approval absent");
    }
    const previous=await this.host.currentManifest();
    const isPreflight=command.action==="fleet.preflight";
    const isVerify=command.action==="fleet.verify";
    const isRollback=command.action==="fleet.rollback";
    if(!isPreflight&&!isVerify&&!isRollback&&command.action!=="fleet.activate")
      throw new F01RecipientDenied("operation outside closed F01 contract");
    if((isPreflight||command.action==="fleet.activate")&&
      previous!==command.previousManifestSha256)
      throw new F01RecipientDenied("target physical V3 active release differs from owner plan");
    if(isRollback&&previous!==command.previousManifestSha256)
      throw new F01RecipientDenied("rollback must begin from the verified V3 canary release");
    if(!await this.host.verifyStagedManifest(command.targetManifestSha256)||
       !await this.host.verifyStagedManifest(command.previousManifestSha256)){
      throw new F01RecipientDenied("both exact locally staged V3 manifest hashes required");
    }
    this.journal.reserve(command);
    try{
      let after=previous;
      if(command.action==="fleet.activate"||isRollback){
        await this.host.activateExactManifest(command.targetManifestSha256,previous);
        after=command.targetManifestSha256;
      }
      const observed=await this.host.verifyActiveRelease(
        command.action==="fleet.preflight" ? previous : command.targetManifestSha256
      );
      const end=await this.host.currentManifest();
      if(end!==after)
        throw new F01RecipientDenied("physical V3 release pointer not equal to signed operation");
      const localReceipt=await this.audit.append({
        commandHash:sha256(canonicalJson(command)),
        deviceId:command.deviceId,action:command.action,before:previous,
        after:end,terminal:"completed",
      });
      if(!localReceipt.durable||
        !/^[0-9a-f]{64}$/u.test(localReceipt.localReceiptHash))
        throw new F01RecipientDenied("target durable audit not committed");
      const payload:NativeFleetResult=isPreflight?{
        deviceId:command.deviceId,previousManifestSha256:previous,
        stagedTargetVerified:true,stagedRollbackVerified:true,
        identityVerified:true,consentSupported:true,
        health:observed.health,evidenceSha256:localReceipt.localReceiptHash,
      }:isVerify?{
        deviceId:command.deviceId,activeManifestSha256:end,
        health:observed.health,identityVerified:true,
        deviceReceiptHash:localReceipt.localReceiptHash,
      }:{
        deviceId:command.deviceId,previousManifestSha256:previous,
        activeManifestSha256:end,identityVerified:true,
        deviceReceiptHash:localReceipt.localReceiptHash,
      };
      const response={
        schema:"radlina.v3.f01.signed-fleet-reply/v1" as const,
        operationId:command.operationId,
        deviceId:command.deviceId,
        agentInstanceId:this.identity.agentInstanceId,
        payload,
      };
      const signature=await this.identity.signReceipt(canonicalJson(response));
      if(Buffer.from(signature,"base64").length!==64)
        throw new F01RecipientDenied("recipient P03 release signing key unavailable");
      const signedReply:F01SignedReply<NativeFleetResult>={...response,deviceSignatureBase64:signature};
      this.journal.anchoredSigned(command.operationId,localReceipt.localReceiptHash,signedReply);
      return signedReply;
    }catch(error){
      this.journal.uncertain(command.operationId);
      throw error;
    }
  }
}
