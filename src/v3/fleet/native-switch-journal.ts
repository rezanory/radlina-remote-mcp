/**
 * F01 target-native switch journal. It is separate from the command replay
 * journal: a command may already have modified a native service even when its
 * HTTP acknowledgement is lost. Never infer successful rollout from a pointer.
 *
 * No automatic retries, release rollbacks or ambiguous-state forgiveness.
 * Unfinished journal entries intentionally block subsequent native switches
 * until a separately authorized operator reconciles the actual machine.
 */
import { createPublicKey, randomUUID, verify } from "node:crypto";
import { canonicalJson, sha256 } from "../../utils/json.js";
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
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS v3_native_switch_manual_reconciliations("+
      "switch_id TEXT PRIMARY KEY REFERENCES v3_native_switches(switch_id),"+
      "device_id TEXT NOT NULL,evidence_json TEXT NOT NULL,"+
      "evidence_sha256 TEXT NOT NULL,owner_signature TEXT NOT NULL,"+
      "reviewer_signature TEXT NOT NULL,recorded_at_ms INTEGER NOT NULL);"
    );
    this.db.exec(
      "CREATE TRIGGER IF NOT EXISTS v3_native_reconcile_no_update "+
      "BEFORE UPDATE ON v3_native_switch_manual_reconciliations "+
      "BEGIN SELECT RAISE(ABORT,'append_only'); END;"+
      "CREATE TRIGGER IF NOT EXISTS v3_native_reconcile_no_delete "+
      "BEFORE DELETE ON v3_native_switch_manual_reconciliations "+
      "BEGIN SELECT RAISE(ABORT,'append_only'); END;"
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
        "SELECT s.switch_id FROM v3_native_switches s "+
        "LEFT JOIN v3_native_switch_manual_reconciliations r ON r.switch_id=s.switch_id "+
        "WHERE s.device_id=? AND s.phase<>'native_start_returned' "+
        "AND r.switch_id IS NULL LIMIT 1",
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
  /** Manual release-block clearance, not operational release acceptance.
   * The caller MUST first independently observe the exact native release and
   * healthy service, and load pins from a separately SHA-pinned owner binding.
   * This function NEVER restarts a service, replays a command or fabricates S03.
   */
  reconcileUnknown(input:{
    evidence:{schema:"radlina.v3.f01.native-switch-reconciliation/v1";
      switchId:string;deviceId:"windows-main"|"macbook-main";
      beforeManifestSha256:string;afterManifestSha256:string;
      observedManifestSha256:string;observedHealth:"healthy";
      observedAtMs:number;nonce:string;codeExecutionPerformed:false;};
    ownerSignatureBase64:string;reviewerSignatureBase64:string;
    pins:{ownerPublicKeyPem:string;reviewerPublicKeyPem:string;
      ownerKeyFingerprint:string;reviewerKeyFingerprint:string;};
  }):void{
    const {evidence,pins}=input;
    const row=this.last();
    if(evidence.schema!=="radlina.v3.f01.native-switch-reconciliation/v1"||
      !row||row.switch_id!==evidence.switchId||
      !["prepared","service_stopped","pointer_replaced","restart_requested","uncertain"].includes(row.phase)||
      evidence.deviceId!==this.deviceId||
      evidence.beforeManifestSha256!==row.before_manifest||
      evidence.afterManifestSha256!==row.after_manifest||
      !DIGEST.test(evidence.observedManifestSha256)||
      ![row.before_manifest,row.after_manifest].includes(evidence.observedManifestSha256)||
      evidence.observedHealth!=="healthy"||evidence.codeExecutionPerformed!==false||
      !Number.isSafeInteger(evidence.observedAtMs)||
      Math.abs(Date.now()-evidence.observedAtMs)>120000||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(evidence.nonce)){
      throw new V3NativeSwitchDenied("exact healthy native release and original unknown switch proof required");
    }
    const ownerKey=createPublicKey(pins.ownerPublicKeyPem);
    const reviewerKey=createPublicKey(pins.reviewerPublicKeyPem);
    const ownerFp=sha256(ownerKey.export({type:"spki",format:"der"}));
    const reviewerFp=sha256(reviewerKey.export({type:"spki",format:"der"}));
    if(!DIGEST.test(pins.ownerKeyFingerprint)||!DIGEST.test(pins.reviewerKeyFingerprint)||
      ownerFp!==pins.ownerKeyFingerprint||reviewerFp!==pins.reviewerKeyFingerprint||
      ownerFp===reviewerFp){
      throw new V3NativeSwitchDenied("independently pinned, different owner/reviewer signing keys required");
    }
    const canonical=canonicalJson(evidence);
    const signed=(key:ReturnType<typeof createPublicKey>,base64:string)=>{
      const bytes=Buffer.from(base64,"base64");
      return bytes.length===64&&bytes.toString("base64")===base64&&
        verify(null,Buffer.from(canonical),key,bytes);
    };
    if(!signed(ownerKey,input.ownerSignatureBase64)||
      !signed(reviewerKey,input.reviewerSignatureBase64)){
      throw new V3NativeSwitchDenied("two independent exact native reconciliation signatures required");
    }
    this.transaction(()=>{
      const active=this.db.prepare(
        "SELECT phase,before_manifest,after_manifest FROM v3_native_switches "+
        "WHERE switch_id=? AND device_id=?",
      ).get(evidence.switchId,this.deviceId) as {
        phase:string;before_manifest:string;after_manifest:string;
      }|undefined;
      if(!active||active.before_manifest!==row.before_manifest||
        active.after_manifest!==row.after_manifest||
        active.phase!==row.phase)
        throw new V3NativeSwitchDenied("native unknown state changed before manual reconciliation");
      this.db.prepare(
        "INSERT INTO v3_native_switch_manual_reconciliations("+
        "switch_id,device_id,evidence_json,evidence_sha256,owner_signature,"+
        "reviewer_signature,recorded_at_ms) VALUES(?,?,?,?,?,?,?)",
      ).run(evidence.switchId,this.deviceId,canonical,sha256(canonical),
        input.ownerSignatureBase64,input.reviewerSignatureBase64,Date.now());
    });
  }
  last():NativeSwitchRow|undefined{
    return this.db.prepare(
      "SELECT switch_id,before_manifest,after_manifest,phase,created_at_ms,updated_at_ms "+
      "FROM v3_native_switches WHERE device_id=? ORDER BY created_at_ms DESC LIMIT 1",
    ).get(this.deviceId) as NativeSwitchRow|undefined;
  }
  close():void{this.db.close();}
}
