/**
 * I01 durable target-local human consent inbox.
 *
 * The controller cannot create or sign a recipient grant. The target device
 * must poll with fresh P03 Ed25519 identity, present a prompt to its local
 * user, and return a P03-signed single-operation approval. Unknown/expired
 * outcomes are never silently approved.
 */
import { createPublicKey, randomUUID, verify } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import * as z from "zod/v4";
import { canonicalJson } from "../../utils/json.js";
import {
  i01RecipientApprovalSchema, type I01SignedRecipientApproval,
  type I01TargetLocalConsent,
} from "./i01-secured-dispatch.js";
import type { I01PhysicalDeviceSession, I01SignedPull } from "./i01-sealed-outbox.js";
import type { I01TrustedDeviceResolver } from "./i01-secured-dispatch.js";
import type { VerifiedDevicePrincipal } from "../security/consent-contracts.js";

const fingerprint=z.string().regex(/^[0-9a-f]{64}$/u);
const promptSchema=z.object({
  requestId:z.string().uuid(),
  operationSha256:fingerprint,
  sourceDeviceId:z.enum(["windows-main","macbook-main"]),
  targetDeviceId:z.enum(["macbook-main","windows-main"]),
  subject:z.string().min(1).max(200),
  capability:z.string().min(1).max(128),
  inputSha256:fingerprint,
  resourceDescription:z.string().min(1).max(200),
  issuedAtMs:z.number().int().positive(),
  expiresAtMs:z.number().int().positive(),
}).strict();
export type I01LocalConsentPrompt=z.infer<typeof promptSchema>;
export class I01LocalConsentDenied extends Error {
  constructor(message:string){super(message);this.name="I01LocalConsentDenied";}
}
export class I01SqliteTargetLocalConsentMailbox implements I01TargetLocalConsent {
  private readonly db:DatabaseSync;
  constructor(
    file:string,
    private readonly deviceSessions:I01PhysicalDeviceSession,
    private readonly registry:I01TrustedDeviceResolver,
    private readonly now:()=>number=()=>Date.now(),
  ){
    if(!path.isAbsolute(file)||file.toLowerCase().includes("\\v2\\"))
      throw new I01LocalConsentDenied("independent V3 signed recipient inbox file required");
    mkdirSync(path.dirname(file),{recursive:true});
    this.db=new DatabaseSync(file,{enableForeignKeyConstraints:true});
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec("CREATE TABLE IF NOT EXISTS v3_i01_local_consent("+
      "request_id TEXT PRIMARY KEY,operation_sha256 TEXT NOT NULL UNIQUE,"+
      "source_device_id TEXT NOT NULL,target_device_id TEXT NOT NULL,subject TEXT NOT NULL,"+
      "request_json TEXT NOT NULL,reply_json TEXT,"+
      "state TEXT NOT NULL CHECK(state IN ('pending','claimed','approved','denied','expired')),"+
      "created_at_ms INTEGER NOT NULL,expires_at_ms INTEGER NOT NULL);");
  }
  async approveExact(input:{
    operationSha256:string;source:VerifiedDevicePrincipal;
    targetDeviceId:string;subject:string;
    capability:string;inputSha256:string;resourceDescription:string;
  }):Promise<I01SignedRecipientApproval>{
    if(!input.source.attested||input.source.subject!==input.subject||
      input.source.deviceId===input.targetDeviceId||
      !["macbook-main","windows-main"].includes(input.targetDeviceId)||
      !fingerprint.safeParse(input.operationSha256).success){
      throw new I01LocalConsentDenied("physical source, exact target and operation hash mandatory");
    }
    const now=this.now();
    const record=promptSchema.parse({
      requestId:randomUUID(),operationSha256:input.operationSha256,
      sourceDeviceId:input.source.deviceId,
      targetDeviceId:input.targetDeviceId,subject:input.subject,
      capability:input.capability,inputSha256:input.inputSha256,
      resourceDescription:input.resourceDescription,
      issuedAtMs:now,expiresAtMs:now+120000,
    });
    this.db.prepare(
      "INSERT INTO v3_i01_local_consent(request_id,operation_sha256,source_device_id,"+
      "target_device_id,subject,request_json,state,created_at_ms,expires_at_ms) "+
      "VALUES(?,?,?,?,?,?,'pending',?,?)"
    ).run(
      record.requestId,record.operationSha256,record.sourceDeviceId,
      record.targetDeviceId,record.subject,canonicalJson(record),now,record.expiresAtMs
    );
    while(this.now()<record.expiresAtMs){
      const row=this.db.prepare(
        "SELECT state,reply_json FROM v3_i01_local_consent WHERE request_id=?"
      ).get(record.requestId) as {state:string;reply_json:string|null}|undefined;
      if(row?.state==="approved"&&row.reply_json) {
        const result=z.object({
          approval:i01RecipientApprovalSchema,
          deviceSignatureBase64:z.string().min(80).max(200),
        }).strict().parse(JSON.parse(row.reply_json));
        return result;
      }
      if(row?.state==="denied"||row?.state==="expired")break;
      await new Promise<void>(resolve=>setTimeout(resolve,250));
    }
    this.db.prepare(
      "UPDATE v3_i01_local_consent SET state='expired' WHERE request_id=? AND state IN ('pending','claimed')"
    ).run(record.requestId);
    throw new I01LocalConsentDenied("target-local decision denied, missing or expired");
  }
  async pollTarget(session:I01SignedPull):Promise<I01LocalConsentPrompt|null>{
    await this.deviceSessions.assertPhysicalAgent(session);
    const row=this.db.prepare(
      "SELECT request_id,request_json FROM v3_i01_local_consent "+
      "WHERE target_device_id=? AND state='pending' AND expires_at_ms>? "+
      "ORDER BY created_at_ms LIMIT 1"
    ).get(session.deviceId,this.now()) as {request_id:string;request_json:string}|undefined;
    if(!row)return null;
    const result=this.db.prepare(
      "UPDATE v3_i01_local_consent SET state='claimed' WHERE request_id=? "+
      "AND target_device_id=? AND state='pending' AND expires_at_ms>?"
    ).run(row.request_id,session.deviceId,this.now());
    if(Number(result.changes)!==1)return null;
    return promptSchema.parse(JSON.parse(row.request_json));
  }
  async submitTarget(session:I01SignedPull, signed:I01SignedRecipientApproval):Promise<void>{
    await this.deviceSessions.assertPhysicalAgent(session);
    const value=i01RecipientApprovalSchema.parse(signed.approval);
    const row=this.db.prepare(
      "SELECT request_id,request_json,state FROM v3_i01_local_consent "+
      "WHERE operation_sha256=? AND target_device_id=?"
    ).get(value.operationSha256,session.deviceId) as {
      request_id:string;request_json:string;state:string;
    }|undefined;
    if(!row||row.state!=="claimed")
      throw new I01LocalConsentDenied("no target-claimed physical consent request");
    const expected=promptSchema.parse(JSON.parse(row.request_json));
    if(value.sourceDeviceId!==expected.sourceDeviceId||
      value.targetDeviceId!==expected.targetDeviceId||
      value.subject!==expected.subject||
      value.issuedAtMs>this.now()||value.expiresAtMs<=this.now()||
      value.expiresAtMs-expected.issuedAtMs>120000||
      expected.expiresAtMs<=this.now()||
      value.issuedAtMs<expected.issuedAtMs||
      !value.localUserApproved){
      throw new I01LocalConsentDenied("recipient permission does not match exact bound prompt");
    }
    const target=this.registry.resolve(session.deviceId,"device.health");
    const signature=Buffer.from(signed.deviceSignatureBase64,"base64");
    if(signature.length!==64||signature.toString("base64")!==signed.deviceSignatureBase64||
      !verify(null,Buffer.from(canonicalJson(value)),
        createPublicKey(target.devicePublicKeyPem),signature)){
      throw new I01LocalConsentDenied("recipient approval not signed by actual P03 device key");
    }
    const saved=this.db.prepare(
      "UPDATE v3_i01_local_consent SET state='approved',reply_json=? "+
      "WHERE request_id=? AND state='claimed'"
    ).run(canonicalJson(signed),row.request_id);
    if(Number(saved.changes)!==1)
      throw new I01LocalConsentDenied("recipient approval journal CAS conflict");
  }
  async denyTarget(session:I01SignedPull, requestId:string):Promise<void>{
    await this.deviceSessions.assertPhysicalAgent(session);
    const saved=this.db.prepare(
      "UPDATE v3_i01_local_consent SET state='denied' "+
      "WHERE request_id=? AND target_device_id=? AND state='claimed'"
    ).run(requestId,session.deviceId);
    if(Number(saved.changes)!==1)throw new I01LocalConsentDenied("target denial request not active");
  }
  close():void{this.db.close();}
}
