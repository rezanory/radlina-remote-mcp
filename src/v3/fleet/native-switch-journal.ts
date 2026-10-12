/**
 * F01 target-native switch journal. It is separate from the command replay
 * journal: a command may already have modified a native service even when its
 * HTTP acknowledgement is lost. Never infer successful rollout from a pointer.
 *
 * No automatic retries, release rollbacks or ambiguous-state forgiveness.
 * Unfinished journal entries intentionally block subsequent native switches
 * until a separately authorized operator reconciles the actual machine.
 */
import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";

const DIGEST=/^[a-f0-9]{64}$/u;
export type V3NativeSwitchPhase=
  "prepared"|"service_stopped"|"pointer_replaced"|
  "restart_requested"|"native_start_returned"|"uncertain";
type NativeSwitchRow={
  switch_id:string;before_manifest:string;after_manifest:string;
  phase:V3NativeSwitchPhase;created_at_ms:number;updated_at_ms:number;
};
export class V3NativeSwitchDenied extends Error{
  constructor(message:string){super(message);this.name="V3NativeSwitchDenied";}
}

export class V3NativeSwitchJournal{
  private readonly db:DatabaseSync;
  constructor(filename:string,private readonly deviceId:"windows-main"|"macbook-main"){
    if(!path.isAbsolute(filename)||filename.toLowerCase().includes("v2")||
      !/native-switch\.sqlite3$/u.test(filename)){
      throw new V3NativeSwitchDenied("isolated V3-only native switch journal required");
    }
    mkdirSync(path.dirname(filename),{recursive:true});
    this.db=new DatabaseSync(filename,{enableForeignKeyConstraints:true});
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS v3_native_switches ("+
      "switch_id TEXT PRIMARY KEY, device_id TEXT NOT NULL,"+
      "before_manifest TEXT NOT NULL, after_manifest TEXT NOT NULL,"+
      "phase TEXT NOT NULL CHECK(phase IN ("+
      "'prepared','service_stopped','pointer_replaced','restart_requested',"+
      "'native_start_returned','uncertain')),"+
      "created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL);"
    );
  }
  private transaction<T>(fn:()=>T):T{
    this.db.exec("BEGIN IMMEDIATE");
    try{
      const result=fn();
      this.db.exec("COMMIT");
      return result;
    }catch(e){this.db.exec("ROLLBACK");throw e;}
  }
  /** A pending or uncertain switch must be independently reconciled. */
  begin(before:string,after:string):string {
    if(!DIGEST.test(before)||!DIGEST.test(after)||before===after)
      throw new V3NativeSwitchDenied("two distinct exact manifest hashes required");
    return this.transaction(()=>{
      const prior=this.db.prepare(
        "SELECT switch_id FROM v3_native_switches WHERE "+
        "device_id=? AND phase<>'native_start_returned' LIMIT 1",
      ).get(this.deviceId) as {switch_id:string}|undefined;
      if(prior)throw new V3NativeSwitchDenied(
        "unreconciled F01 native switch exists: "+prior.switch_id,
      );
      const switchId=randomUUID(),now=Date.now();
      this.db.prepare(
        "INSERT INTO v3_native_switches("+
        "switch_id,device_id,before_manifest,after_manifest,phase,"+
        "created_at_ms,updated_at_ms) VALUES(?,?,?,?,'prepared',?,?)",
      ).run(switchId,this.deviceId,before,after,now,now);
      return switchId;
    });
  }
  advance(id:string,expected:V3NativeSwitchPhase,next:V3NativeSwitchPhase):void{
    const allowed:Readonly<Record<string,string>>={
      prepared:"service_stopped",
      service_stopped:"pointer_replaced",
      pointer_replaced:"restart_requested",
      restart_requested:"native_start_returned",
    };
    if(next!==allowed[expected]||next==="uncertain"||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(id)){
      throw new V3NativeSwitchDenied("invalid or unordered native switch transition");
    }
    const result=this.db.prepare(
      "UPDATE v3_native_switches SET phase=?,updated_at_ms=? "+
      "WHERE switch_id=? AND device_id=? AND phase=?",
    ).run(next,Date.now(),id,this.deviceId,expected);
    if(Number(result.changes)!==1)
      throw new V3NativeSwitchDenied("F01 native switch phase compare-and-swap conflict");
  }
  uncertain(id:string):void{
    this.db.prepare(
      "UPDATE v3_native_switches SET phase='uncertain',updated_at_ms=? "+
      "WHERE switch_id=? AND device_id=? AND phase<>'native_start_returned'",
    ).run(Date.now(),id,this.deviceId);
  }
  last():NativeSwitchRow|undefined{
    return this.db.prepare(
      "SELECT switch_id,before_manifest,after_manifest,phase,created_at_ms,updated_at_ms "+
      "FROM v3_native_switches WHERE device_id=? ORDER BY created_at_ms DESC LIMIT 1",
    ).get(this.deviceId) as NativeSwitchRow|undefined;
  }
  close():void{this.db.close();}
}
