/**
 * F01 sealed two-device fleet operation queue. Separate from I01 task queue:
 * a fleet command is not a generic process execution and is never retried.
 */
import { createPublicKey, randomUUID, verify } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { canonicalJson, sha256 } from "../../utils/json.js";
import {
  f01SignedCommandSchema,
  type F01PhysicalTransport, type F01SignedCommand, type F01SignedReply,
} from "./physical-adapters.js";
import type { I01SealedOutboxData,I01PhysicalDeviceSession,I01SignedPull } from "../integration/i01-sealed-outbox.js";

export class F01FleetQueueDenied extends Error {
  constructor(message:string){super(message);this.name="F01FleetQueueDenied";}
}
type Row={operation_id:string;device_id:string;command_hash:string;state:string;
  sealed_command:Uint8Array;sealed_reply:Uint8Array|null;lease_id:string|null;expires_at_ms:number;};
export class F01SealedFleetTransport implements F01PhysicalTransport {
  readonly db:DatabaseSync;
  constructor(
    file:string,
    private readonly crypt:I01SealedOutboxData,
    private readonly session:I01PhysicalDeviceSession,
    private readonly now:()=>number=()=>Date.now(),
  ){
    if(!path.isAbsolute(file)||file.toLowerCase().includes("\\v2\\"))
      throw new F01FleetQueueDenied("independent V3 F01 queue database required");
    mkdirSync(path.dirname(file),{recursive:true});
    this.db=new DatabaseSync(file,{enableForeignKeyConstraints:true});
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec("CREATE TABLE IF NOT EXISTS v3_f01_commands("+
      "operation_id TEXT PRIMARY KEY,device_id TEXT NOT NULL,command_hash TEXT NOT NULL,"+
      "sealed_command BLOB NOT NULL,sealed_reply BLOB,expires_at_ms INTEGER NOT NULL,"+
      "state TEXT NOT NULL CHECK(state IN ('ready','leased','returned','uncertain')),"+
      "lease_id TEXT UNIQUE,created_at_ms INTEGER NOT NULL);");
  }
  private row(id:string):Row|undefined {
    return this.db.prepare("SELECT operation_id,device_id,command_hash,state,"+
      "sealed_command,sealed_reply,lease_id,expires_at_ms "+
      "FROM v3_f01_commands WHERE operation_id=?").get(id) as Row|undefined;
  }
  async perform<T>(raw:F01SignedCommand):Promise<F01SignedReply<T>> {
    const signed=f01SignedCommandSchema.parse(raw);
    const op=signed.command;
    if(op.expiresAtMs<=this.now()||op.expiresAtMs-op.issuedAtMs>90000||
      !["macbook-main","windows-main"].includes(op.deviceId))
      throw new F01FleetQueueDenied("physical exact signed V3 fleet command expired");
    const encoded=canonicalJson(signed);
    const bytes=await this.crypt.seal(Buffer.from(encoded,"utf8"));
    if(bytes.byteLength>262144)throw new F01FleetQueueDenied("encrypted fleet command exceeds bound");
    const hash=sha256(encoded);
    const existing=this.row(op.operationId);
    if(existing)throw new F01FleetQueueDenied(
      existing.command_hash===hash?"unknown/previous fleet command cannot automatically retry":
        "fleet command identity collision"
    );
    this.db.prepare("INSERT INTO v3_f01_commands("+
      "operation_id,device_id,command_hash,sealed_command,expires_at_ms,state,created_at_ms) "+
      "VALUES(?,?,?,?,?,'ready',?)").run(
      op.operationId,op.deviceId,hash,bytes,op.expiresAtMs,this.now());
    while(this.now()<op.expiresAtMs){
      const row=this.row(op.operationId);
      if(row?.state==="returned"&&row.sealed_reply){
        const decrypted=await this.crypt.unseal(row.sealed_reply);
        if(decrypted.byteLength>262144)
          throw new F01FleetQueueDenied("fleet signed reply exceeds 256KiB");
        return JSON.parse(Buffer.from(decrypted).toString("utf8")) as F01SignedReply<T>;
      }
      if(row?.state==="uncertain")break;
      await new Promise<void>(resolve=>setTimeout(resolve,250));
    }
    this.db.prepare("UPDATE v3_f01_commands SET state='uncertain' "+
      "WHERE operation_id=? AND state IN ('ready','leased')").run(op.operationId);
    throw new F01FleetQueueDenied("fleet physical switch outcome uncertain; manual reconciliation required");
  }
  async claim(session:I01SignedPull):Promise<{
    leaseId:string;command:F01SignedCommand;
  }|null>{
    await this.session.assertPhysicalAgent(session);
    const row=this.db.prepare(
      "SELECT operation_id FROM v3_f01_commands WHERE device_id=? "+
      "AND state='ready' AND expires_at_ms>? ORDER BY created_at_ms LIMIT 1"
    ).get(session.deviceId,this.now()) as {operation_id:string}|undefined;
    if(!row)return null;
    const leaseId=randomUUID();
    const updated=this.db.prepare(
      "UPDATE v3_f01_commands SET state='leased',lease_id=? "+
      "WHERE operation_id=? AND device_id=? AND state='ready' AND expires_at_ms>?"
    ).run(leaseId,row.operation_id,session.deviceId,this.now());
    if(Number(updated.changes)!==1)return null;
    const claimed=this.row(row.operation_id);
    if(!claimed||claimed.lease_id!==leaseId)
      throw new F01FleetQueueDenied("physical fleet claim CAS failed");
    const decrypted=await this.crypt.unseal(claimed.sealed_command);
    const command=f01SignedCommandSchema.parse(JSON.parse(Buffer.from(decrypted).toString("utf8")));
    if(command.command.deviceId!==session.deviceId||
      sha256(canonicalJson(command))!==claimed.command_hash)
      throw new F01FleetQueueDenied("fleet command target or sealed input changed");
    return{leaseId,command};
  }
  /** Idempotent receipt re-delivery of the ORIGINAL signed fleet result.
   * Never retries or restages native fleet commands after expiry. */
  async report(session:I01SignedPull,leaseId:string,reply:F01SignedReply<unknown>):Promise<void>{
    await this.session.assertPhysicalAgent(session);
    const row=this.row(reply.operationId);
    if(!row||row.device_id!==session.deviceId||
      !["leased","uncertain","returned"].includes(row.state)||row.lease_id!==leaseId||
      reply.schema!=="radlina.v3.f01.signed-fleet-reply/v1"||
      reply.deviceId!==session.deviceId)
      throw new F01FleetQueueDenied("original physical F01 lease mismatch");
    const pinned=this.session.trustedDeviceReceiptKey?.(session.deviceId);
    if(!pinned||reply.agentInstanceId!==pinned.agentInstanceId)
      throw new F01FleetQueueDenied("enrolled target P03 signer unavailable");
    const issued=f01SignedCommandSchema.parse(JSON.parse(
      Buffer.from(await this.crypt.unseal(row.sealed_command)).toString("utf8"),
    ));
    if(issued.command.operationId!==reply.operationId||
      issued.command.deviceId!==session.deviceId||
      sha256(canonicalJson(issued))!==row.command_hash)
      throw new F01FleetQueueDenied("original sealed owner release command changed");
    const signedData={schema:reply.schema,operationId:reply.operationId,
      deviceId:reply.deviceId,agentInstanceId:reply.agentInstanceId,payload:reply.payload};
    const proof=Buffer.from(reply.deviceSignatureBase64??"","base64");
    if(proof.length!==64||proof.toString("base64")!==reply.deviceSignatureBase64||
      !verify(null,Buffer.from(canonicalJson(signedData)),
        createPublicKey(pinned.devicePublicKeyPem),proof))
      throw new F01FleetQueueDenied("P03 signed original F01 receipt invalid");
    const payload=canonicalJson(reply);
    if(row.state==="returned"){
      if(!row.sealed_reply||canonicalJson(JSON.parse(
        Buffer.from(await this.crypt.unseal(row.sealed_reply)).toString("utf8"),
      ))!==payload)throw new F01FleetQueueDenied("conflicting signed F01 report");
      return; // Repeated original receipt only; no additional native action.
    }
    const bytes=await this.crypt.seal(Buffer.from(payload,"utf8"));
    if(bytes.length>262144)throw new F01FleetQueueDenied("F01 signed report exceeds bound");
    const changed=this.db.prepare(
      "UPDATE v3_f01_commands SET state='returned',sealed_reply=? "+
      "WHERE operation_id=? AND lease_id=? AND state IN ('leased','uncertain') "+
      "AND sealed_reply IS NULL",
    ).run(bytes,reply.operationId,leaseId);
    if(Number(changed.changes)!==1)
      throw new F01FleetQueueDenied("original physical F01 receipt durable CAS failed");
    // F01 controller still independently verifies owner command and S03 anchor.
  }
  close():void{this.db.close();}
}
