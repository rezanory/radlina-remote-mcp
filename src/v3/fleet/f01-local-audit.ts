/**
 * F01 target-local append-only V3 service-change audit.
 * One protected file per target. Never stores V2 service configuration.
 */
import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { canonicalJson,sha256 } from "../../utils/json.js";
import type { F01TargetLocalReceiptJournal } from "./local-release-agent.js";
import type { FleetOperation } from "./contracts.js";

export class F01RecipientAuditDenied extends Error {
  constructor(message:string){super(message);this.name="F01RecipientAuditDenied";}
}
const digest=/^[0-9a-f]{64}$/u;
export class F01PhysicalLocalAuditChain implements F01TargetLocalReceiptJournal {
  readonly db:DatabaseSync;
  constructor(file:string,private readonly deviceId:"windows-main"|"macbook-main"){
    if(!path.isAbsolute(file)||file.toLowerCase().includes("\\v2\\"))
      throw new F01RecipientAuditDenied("target-local isolated V3 audit database required");
    mkdirSync(path.dirname(file),{recursive:true,mode:0o700});
    this.db=new DatabaseSync(file,{enableForeignKeyConstraints:true});
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS v3_f01_local_audit("+
      "sequence INTEGER PRIMARY KEY AUTOINCREMENT,"+
      "device_id TEXT NOT NULL,command_hash TEXT NOT NULL UNIQUE,"+
      "event_json TEXT NOT NULL,previous_hash TEXT NOT NULL,event_hash TEXT NOT NULL);"
    );
  }
  async append(input:{
    commandHash:string;deviceId:string;action:FleetOperation;
    before:string;after:string;terminal:"completed";
  }):Promise<{durable:true;localReceiptHash:string}>{
    if(input.deviceId!==this.deviceId||
      !digest.test(input.commandHash)||!digest.test(input.before)||!digest.test(input.after)||
      !["fleet.preflight","fleet.activate","fleet.verify","fleet.rollback"].includes(input.action)){
      throw new F01RecipientAuditDenied("exact physical V3 release action and release hash required");
    }
    this.db.exec("BEGIN IMMEDIATE");
    try{
      const already=this.db.prepare(
        "SELECT command_hash FROM v3_f01_local_audit WHERE command_hash=?"
      ).get(input.commandHash);
      if(already)throw new F01RecipientAuditDenied("duplicate fleet action audit cannot be replayed");
      const last=this.db.prepare(
        "SELECT event_hash FROM v3_f01_local_audit ORDER BY sequence DESC LIMIT 1"
      ).get() as {event_hash:string}|undefined;
      const previousHash=last?.event_hash??"0".repeat(64);
      const event={
        schema:"radlina.v3.f01.physical-target-audit/v1" as const,
        ...input,recordedAt:new Date().toISOString(),
      };
      const eventHash=sha256(canonicalJson({previousHash,event}));
      this.db.prepare(
        "INSERT INTO v3_f01_local_audit("+
        "device_id,command_hash,event_json,previous_hash,event_hash) VALUES(?,?,?,?,?)"
      ).run(input.deviceId,input.commandHash,canonicalJson(event),previousHash,eventHash);
      this.db.exec("COMMIT");
      return{durable:true,localReceiptHash:eventHash};
    }catch(error){
      this.db.exec("ROLLBACK");
      throw error;
    }
  }
  currentHead():string{
    const last=this.db.prepare(
      "SELECT event_hash FROM v3_f01_local_audit ORDER BY sequence DESC LIMIT 1"
    ).get() as {event_hash:string}|undefined;
    return last?.event_hash??"0".repeat(64);
  }
  close():void{this.db.close();}
}
