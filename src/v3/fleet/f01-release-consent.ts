/**
 * F01 physical release approval inbox. Each physical switch requires a
 * target-local user's exact decision and P03 Ed25519 device signature.
 * An owner-signed plan is NOT sufficient to approve a recipient release.
 */
import { createPublicKey, randomUUID, verify } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import * as z from "zod/v4";
import { canonicalJson } from "../../utils/json.js";
import type { F01RecipientLocalReleaseConsent } from "./physical-adapters.js";
import type { FleetRecipientConsentPort, FleetOperation } from "./contracts.js";
import type { I01PhysicalDeviceSession, I01SignedPull } from "../integration/i01-sealed-outbox.js";
import type { I01TrustedDeviceResolver } from "../integration/i01-secured-dispatch.js";

const digest=z.string().regex(/^[0-9a-f]{64}$/u);
const approval=z.object({
  schema:z.literal("radlina.v3.f01.recipient-release-consent/v1"),
  requestId:z.string().uuid(),
  deviceId:z.enum(["macbook-main","windows-main"]),
  planId:z.string().uuid(),
  operation:z.enum(["fleet.preflight","fleet.activate","fleet.verify","fleet.rollback"]),
  targetManifestSha256:digest,
  previousManifestSha256:digest,
  localUserApproved:z.literal(true),
  nonce:z.string().uuid(),
  issuedAtMs:z.number().int().positive(),
  expiresAtMs:z.number().int().positive(),
}).strict();
export type F01PhysicalReleaseConsent=z.infer<typeof approval>;
export class F01ReleaseConsentBlocked extends Error {
  constructor(message:string){super(message);this.name="F01ReleaseConsentBlocked";}
}
export class F01SignedReleaseConsentMailbox
  implements F01RecipientLocalReleaseConsent,FleetRecipientConsentPort {
  readonly db:DatabaseSync;
  constructor(
    file:string,
    private readonly sessions:I01PhysicalDeviceSession,
    private readonly physical:I01TrustedDeviceResolver,
    private readonly now:()=>number=()=>Date.now(),
  ){
    if(!path.isAbsolute(file)||file.toLowerCase().includes("\\v2\\"))
      throw new F01ReleaseConsentBlocked("independent V3 F01 release consent store required");
    mkdirSync(path.dirname(file),{recursive:true});
    this.db=new DatabaseSync(file,{enableForeignKeyConstraints:true});
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec("CREATE TABLE IF NOT EXISTS v3_f01_release_approvals("+
      "request_id TEXT PRIMARY KEY,plan_id TEXT NOT NULL,device_id TEXT NOT NULL,"+
      "action TEXT NOT NULL,target_hash TEXT NOT NULL,previous_hash TEXT NOT NULL,"+
      "state TEXT NOT NULL CHECK(state IN ('pending','claimed','approved','denied','consumed','expired')),"+
      "signed_approval_json TEXT,created_at_ms INTEGER NOT NULL,expires_at_ms INTEGER NOT NULL);"+
      "CREATE UNIQUE INDEX IF NOT EXISTS v3_f01_release_approvals_exact ON "+
      "v3_f01_release_approvals(plan_id,device_id,action,target_hash,previous_hash);");
  }
  async assertSignedLocalApproval(planId:string,deviceId:string,action:FleetOperation,
    target:string,previous:string):Promise<void>{
    if(!z.string().uuid().safeParse(planId).success||
      !["macbook-main","windows-main"].includes(deviceId)||
      !digest.safeParse(target).success||!digest.safeParse(previous).success){
      throw new F01ReleaseConsentBlocked("exact physical release SHA256 and plan required");
    }
    this.physical.resolve(deviceId,"device.health");
    let row=this.db.prepare(
      "SELECT request_id,state,expires_at_ms FROM v3_f01_release_approvals "+
      "WHERE plan_id=? AND device_id=? AND action=? AND target_hash=? AND previous_hash=?"
    ).get(planId,deviceId,action,target,previous) as{
      request_id:string;state:string;expires_at_ms:number;
    }|undefined;
    if(!row){
      const id=randomUUID(),now=this.now(),until=now+120000;
      this.db.prepare(
        "INSERT INTO v3_f01_release_approvals(request_id,plan_id,device_id,action,"+
        "target_hash,previous_hash,state,created_at_ms,expires_at_ms) "+
        "VALUES(?,?,?,?,?,?,'pending',?,?)"
      ).run(id,planId,deviceId,action,target,previous,now,until);
      row={request_id:id,state:"pending",expires_at_ms:until};
    }
    while(this.now()<row.expires_at_ms){
      const current=this.db.prepare(
        "SELECT state FROM v3_f01_release_approvals WHERE request_id=?"
      ).get(row.request_id) as {state:string}|undefined;
      if(current?.state==="approved")return;
      if(current?.state==="denied"||current?.state==="consumed"||
        current?.state==="expired")break;
      await new Promise<void>(resolve=>setTimeout(resolve,250));
    }
    throw new F01ReleaseConsentBlocked("physical target signed release approval missing or expired");
  }
  async require(deviceId:string,action:FleetOperation,planId:string):Promise<void>{
    if(!z.string().uuid().safeParse(planId).success||
      !["macbook-main","windows-main"].includes(deviceId)||
      !["fleet.preflight","fleet.activate","fleet.verify","fleet.rollback"].includes(action)){
      throw new F01ReleaseConsentBlocked("invalid exact physical fleet step");
    }
    // This controller admission step checks physical P03 trust only.
    // The actual per-manifest, target-local human signature is mandatory inside
    // assertSignedLocalApproval() BEFORE any F01 command enters the physical queue.
    this.physical.resolve(deviceId,"device.health");
  }
  async poll(session:I01SignedPull):Promise<{
    requestId:string;planId:string;deviceId:string;operation:FleetOperation;
    targetManifestSha256:string;previousManifestSha256:string;expiresAtMs:number;
  }|null>{
    await this.sessions.assertPhysicalAgent(session);
    const row=this.db.prepare(
      "SELECT request_id,plan_id,device_id,action,target_hash,previous_hash,expires_at_ms "+
      "FROM v3_f01_release_approvals WHERE device_id=? AND state='pending' AND expires_at_ms>? "+
      "ORDER BY created_at_ms LIMIT 1"
    ).get(session.deviceId,this.now()) as{
      request_id:string;plan_id:string;device_id:string;action:FleetOperation;
      target_hash:string;previous_hash:string;expires_at_ms:number;
    }|undefined;
    if(!row)return null;
    const update=this.db.prepare(
      "UPDATE v3_f01_release_approvals SET state='claimed' WHERE request_id=? "+
      "AND state='pending' AND expires_at_ms>?"
    ).run(row.request_id,this.now());
    if(Number(update.changes)!==1)return null;
    return{
      requestId:row.request_id,planId:row.plan_id,deviceId:row.device_id,
      operation:row.action,targetManifestSha256:row.target_hash,
      previousManifestSha256:row.previous_hash,expiresAtMs:row.expires_at_ms,
    };
  }
  async decide(session:I01SignedPull,raw:unknown):Promise<void>{
    await this.sessions.assertPhysicalAgent(session);
    const signed=z.object({
      approval,
      deviceSignatureBase64:z.string().min(80).max(200),
    }).strict().parse(raw);
    const entry=this.db.prepare(
      "SELECT state,plan_id,device_id,action,target_hash,previous_hash,expires_at_ms "+
      "FROM v3_f01_release_approvals WHERE request_id=?"
    ).get(signed.approval.requestId) as {
      state:string;plan_id:string;device_id:string;action:string;
      target_hash:string;previous_hash:string;expires_at_ms:number;
    }|undefined;
    const a=signed.approval;
    if(!entry||entry.state!=="claimed"||
      entry.device_id!==session.deviceId||a.deviceId!==session.deviceId||
      entry.plan_id!==a.planId||entry.action!==a.operation||
      entry.target_hash!==a.targetManifestSha256||
      entry.previous_hash!==a.previousManifestSha256||
      a.issuedAtMs>this.now()||a.expiresAtMs<=this.now()||
      a.expiresAtMs>entry.expires_at_ms||entry.expires_at_ms<=this.now()){
      throw new F01ReleaseConsentBlocked("physical signed release approval outside exact plan or TTL");
    }
    const physical=this.physical.resolve(session.deviceId,"device.health");
    const signature=Buffer.from(signed.deviceSignatureBase64,"base64");
    if(signature.length!==64||signature.toString("base64")!==signed.deviceSignatureBase64||
      !verify(null,Buffer.from(canonicalJson(a)),createPublicKey(physical.devicePublicKeyPem),signature)){
      throw new F01ReleaseConsentBlocked("physical device local F01 consent signature mismatch");
    }
    const updated=this.db.prepare(
      "UPDATE v3_f01_release_approvals SET state='approved',signed_approval_json=? "+
      "WHERE request_id=? AND state='claimed'"
    ).run(canonicalJson(signed),a.requestId);
    if(Number(updated.changes)!==1)
      throw new F01ReleaseConsentBlocked("physical F01 consent CAS conflict");
  }
  close():void{this.db.close();}
}
