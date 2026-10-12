/**
 * F01 exact-device sealed release queue. Both hosts must pull owner-signed
 * commands using P03 device-key signed sessions. A lost response is UNKNOWN,
 * not an opportunity to repeat an activation or rollback.
 */
import { mkdirSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { canonicalJson, sha256 } from "../../utils/json.js";
import { f01SignedCommandSchema, type F01PhysicalTransport, type F01SignedCommand, type F01SignedReply } from "./physical-adapters.js";
import type { I01PhysicalDeviceSession, I01SealedOutboxData, I01SignedPull } from "../integration/i01-sealed-outbox.js";

export type F01ClaimedCommand={
  leaseId:string;
  deviceId:"macbook-main"|"windows-main";
  request:F01SignedCommand;
};
export class F01OutboxDenied extends Error {
  constructor(m:string){super(m);this.name="F01OutboxDenied";}
}
type Row={
  operation_id:string;device_id:string;command_hash:string;
  sealed_command:Uint8Array;sealed_result:Uint8Array|null;
  expires_at_ms:number;state:"ready"|"claimed"|"returned"|"unknown";
  lease_id:string|null;
};
export class F01SealedPhysicalReleaseOutbox implements F01PhysicalTransport {
  readonly db:DatabaseSync;
  constructor(
    databaseFile:string,
    private readonly seal:I01SealedOutboxData,
    private readonly deviceSession:I01PhysicalDeviceSession,
    private readonly now:()=>number=()=>Date.now(),
  ){
    if(!path.isAbsolute(databaseFile)||databaseFile.toLowerCase().includes("\\v2\\"))
      throw new F01OutboxDenied("independent physical V3-only fleet outbox required");
    mkdirSync(path.dirname(databaseFile),{recursive:true});
    this.db=new DatabaseSync(databaseFile,{enableForeignKeyConstraints:true});
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS v3_f01_signed_outbox("+
      "operation_id TEXT PRIMARY KEY,device_id TEXT NOT NULL,"+
      "command_hash TEXT NOT NULL,sealed_command BLOB NOT NULL,"+
      "sealed_result BLOB,expires_at_ms INTEGER NOT NULL,"+
      "state TEXT NOT NULL CHECK(state IN ('ready','claimed','returned','unknown')),"+
      "lease_id TEXT UNIQUE,created_at_ms INTEGER NOT NULL);"
    );
  }
  private row(id:string):Row|undefined {
    return this.db.prepare(
      "SELECT operation_id,device_id,command_hash,sealed_command,sealed_result,"+
      "expires_at_ms,state,lease_id FROM v3_f01_signed_outbox WHERE operation_id=?"
    ).get(id) as Row|undefined;
  }
  async perform<T>(message:F01SignedCommand):Promise<F01SignedReply<T>>{
    const signed=f01SignedCommandSchema.parse(message);
    const op=signed.command;
    if(!["macbook-main","windows-main"].includes(op.deviceId)||op.expiresAtMs<=this.now()||
      op.expiresAtMs-op.issuedAtMs>90000||op.issuedAtMs>this.now()) {
      throw new F01OutboxDenied("bounded fresh owner signed fleet command required");
    }
    const canonical=canonicalJson(signed);
    const sealed=await this.seal.seal(Buffer.from(canonical,"utf8"));
    if(sealed.byteLength>256*1024)throw new F01OutboxDenied("sealed fleet command exceeds transport bounds");
    if(this.row(op.operationId))throw new F01OutboxDenied("existing fleet physical operation cannot repeat");
    this.db.prepare(
      "INSERT INTO v3_f01_signed_outbox(operation_id,device_id,command_hash,"+
      "sealed_command,expires_at_ms,state,created_at_ms) VALUES(?,?,?,?,?,'ready',?)"
    ).run(op.operationId,op.deviceId,sha256(canonical),sealed,op.expiresAtMs,this.now());
    while(this.now()<op.expiresAtMs){
      const state=this.row(op.operationId);
      if(state?.state==="returned"&&state.sealed_result){
        const bytes=await this.seal.unseal(state.sealed_result);
        if(bytes.byteLength>256*1024)throw new F01OutboxDenied("bounded fleet recipient proof required");
        return JSON.parse(Buffer.from(bytes).toString("utf8")) as F01SignedReply<T>;
      }
      if(state?.state==="unknown")break;
      await new Promise(resolve=>setTimeout(resolve,250));
    }
    this.db.prepare(
      "UPDATE v3_f01_signed_outbox SET state='unknown' WHERE operation_id=? "+
      "AND state IN ('ready','claimed')"
    ).run(op.operationId);
    throw new F01OutboxDenied("physical release outcome unknown; no automatic retries");
  }
  async claim(session:I01SignedPull):Promise<F01ClaimedCommand|null>{
    if(!["macbook-main","windows-main"].includes(session.deviceId))
      throw new F01OutboxDenied("exact enrolled P03 fleet recipient required");
    await this.deviceSession.assertPhysicalAgent(session);
    const next=this.db.prepare(
      "SELECT operation_id FROM v3_f01_signed_outbox "+
      "WHERE device_id=? AND state='ready' AND expires_at_ms>? "+
      "ORDER BY created_at_ms ASC LIMIT 1"
    ).get(session.deviceId,this.now()) as {operation_id:string}|undefined;
    if(!next)return null;
    const leaseId=randomUUID();
    const count=this.db.prepare(
      "UPDATE v3_f01_signed_outbox SET state='claimed',lease_id=? "+
      "WHERE operation_id=? AND device_id=? AND state='ready' AND expires_at_ms>?"
    ).run(leaseId,next.operation_id,session.deviceId,this.now());
    if(Number(count.changes)!==1)return null;
    const row=this.row(next.operation_id);
    if(!row||!row.lease_id||row.lease_id!==leaseId)
      throw new F01OutboxDenied("signed physical release lease CAS failed");
    const bytes=await this.seal.unseal(row.sealed_command);
    if(bytes.byteLength>256*1024)throw new F01OutboxDenied("oversized physical signed fleet command");
    const request=f01SignedCommandSchema.parse(JSON.parse(Buffer.from(bytes).toString("utf8")));
    if(sha256(canonicalJson(request))!==row.command_hash||
      request.command.deviceId!==session.deviceId)
      throw new F01OutboxDenied("fleet command changed after sealed persistence");
    return{leaseId,deviceId:session.deviceId,request};
  }
  async acknowledge(session:I01SignedPull,leaseId:string,result:F01SignedReply<unknown>):Promise<void>{
    await this.deviceSession.assertPhysicalAgent(session);
    const row=this.row(result.operationId);
    if(!row||row.device_id!==session.deviceId||row.lease_id!==leaseId||
      row.state!=="claimed"||row.expires_at_ms<=this.now()||
      result.schema!=="radlina.v3.f01.signed-fleet-reply/v1"||
      result.deviceId!==session.deviceId||!result.deviceSignatureBase64)
      throw new F01OutboxDenied("target signed fleet reply not leased by this physical device");
    const sealed=await this.seal.seal(Buffer.from(canonicalJson(result),"utf8"));
    if(sealed.byteLength>256*1024)throw new F01OutboxDenied("fleet signed reply exceeds transport limits");
    const wrote=this.db.prepare(
      "UPDATE v3_f01_signed_outbox SET state='returned',sealed_result=? "+
      "WHERE operation_id=? AND lease_id=? AND state='claimed'"
    ).run(sealed,result.operationId,leaseId);
    if(Number(wrote.changes)!==1)
      throw new F01OutboxDenied("durable fleet receipt CAS failed");
  }
  close():void{this.db.close();}
}
