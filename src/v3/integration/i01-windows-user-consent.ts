/**
 * I01 Windows cross-token physical-user consent bridge.
 *
 * V3 Windows P03 agent runs under SYSTEM (machine DPAPI), while the human
 * consent user-agent MUST run as LAPTOP-13QINEIF\Radlina with CurrentUser
 * DPAPI. Shared journal ACL must grant only SYSTEM, Administrators and the
 * pinned owner SID. The signed owner's local approval is checked again by the
 * SYSTEM recipient before the P03 device signs a recipient approval.
 */
import { createPublicKey, randomUUID, verify } from "node:crypto";
import { mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import * as z from "zod/v4";
import { canonicalJson, sha256 } from "../../utils/json.js";
import { I01WindowsPhysicalApprovalDialog } from "./i01-local-recipient-ports.js";
import { V3WindowsProtectedOwnerSigner } from "../security/windows-owner-signer.js";
import type { I01LocalConsentPrompt } from "./i01-local-consent-mailbox.js";

export const windowsLocalUserDecisionSchema=z.object({
  schema:z.literal("radlina.v3.i01.windows-local-user-decision/v1"),
  requestId:z.string().uuid(),
  promptHash:z.string().regex(/^[a-f0-9]{64}$/u),
  targetDeviceId:z.literal("windows-main"),
  sourceDeviceId:z.literal("macbook-main"),
  decision:z.enum(["approve","deny"]),
  nonce:z.string().uuid(),
  issuedAtMs:z.number().int().positive(),
  expiresAtMs:z.number().int().positive(),
}).strict();
export type WindowsLocalUserDecision=z.infer<typeof windowsLocalUserDecisionSchema>;
export class WindowsRecipientConsentDenied extends Error{
  constructor(msg:string){super(msg);this.name="WindowsRecipientConsentDenied";}
}
const sessionSchema=z.object({
  requestId:z.string().uuid(),
  operationSha256:z.string().regex(/^[a-f0-9]{64}$/u),
  sourceDeviceId:z.literal("macbook-main"),
  targetDeviceId:z.literal("windows-main"),
  subject:z.string().min(1).max(200),
  capability:z.string().min(1).max(128),
  inputSha256:z.string().regex(/^[a-f0-9]{64}$/u),
  resourceDescription:z.string().min(1).max(200),
  issuedAtMs:z.number().int().positive(),
  expiresAtMs:z.number().int().positive(),
}).strict();
type Row={request_id:string;prompt_json:string;prompt_sha256:string;
  state:"pending"|"claimed"|"approved"|"denied"|"expired";
  decision_json:string|null;decision_sig:string|null;expires_at_ms:number};
export class I01WindowsHumanConsentBridge {
  readonly db:DatabaseSync;
  constructor(file:string,private readonly ownerPublicKeyPem:string,
    private readonly now:()=>number=()=>Date.now()){
    if(process.platform!=="win32"||os.hostname().toLowerCase()!=="laptop-13qineif"||
      !path.win32.isAbsolute(file)||!file.toLowerCase().includes("\\v3-")||
      file.toLowerCase().includes("\\v2\\")){
      throw new WindowsRecipientConsentDenied("exact V3 physical Windows consent state required");
    }
    mkdirSync(path.win32.dirname(file),{recursive:true});
    this.db=new DatabaseSync(file,{enableForeignKeyConstraints:true});
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS v3_windows_human_approvals("+
      "request_id TEXT PRIMARY KEY,prompt_json TEXT NOT NULL,prompt_sha256 TEXT NOT NULL,"+
      "state TEXT NOT NULL CHECK(state IN ('pending','claimed','approved','denied','expired')),"+
      "decision_json TEXT,decision_sig TEXT,expires_at_ms INTEGER NOT NULL,created_at_ms INTEGER NOT NULL);"
    );
  }
  enqueue(prompt:I01LocalConsentPrompt):void{
    const normalized=sessionSchema.parse(prompt);
    const now=this.now();
    if(normalized.issuedAtMs>now||
      normalized.expiresAtMs<=now||
      normalized.expiresAtMs-normalized.issuedAtMs>120000){
      throw new WindowsRecipientConsentDenied("exact recipient prompt expired or in the future");
    }
    const json=canonicalJson(normalized);
    this.db.prepare(
      "INSERT INTO v3_windows_human_approvals("+
      "request_id,prompt_json,prompt_sha256,state,expires_at_ms,created_at_ms)"+
      " VALUES(?,?,?,'pending',?,?)"
    ).run(normalized.requestId,json,sha256(json),normalized.expiresAtMs,now);
  }
  async waitDecision(requestId:string):Promise<{
    decision:WindowsLocalUserDecision;ownerSignatureBase64:string;
  }>{
    const deadline=this.now()+120000;
    while(this.now()<deadline){
      const row=this.get(requestId);
      if(!row||row.expires_at_ms<=this.now()||
        row.state==="denied"||row.state==="expired")break;
      if(row.state==="approved"&&row.decision_json&&row.decision_sig){
        const decision=windowsLocalUserDecisionSchema.parse(JSON.parse(row.decision_json));
        const signature=Buffer.from(row.decision_sig,"base64");
        if(signature.length!==64||signature.toString("base64")!==row.decision_sig||
          decision.decision!=="approve"||
          decision.promptHash!==row.prompt_sha256||
          decision.requestId!==row.request_id||
          decision.issuedAtMs>this.now()||decision.expiresAtMs<=this.now()||
          !verify(null,Buffer.from(canonicalJson(decision)),
            createPublicKey(this.ownerPublicKeyPem),signature)){
          throw new WindowsRecipientConsentDenied("Windows physical owner proof invalid");
        }
        return{decision,ownerSignatureBase64:row.decision_sig};
      }
      await new Promise<void>(resolve=>setTimeout(resolve,250));
    }
    this.db.prepare(
      "UPDATE v3_windows_human_approvals SET state='expired' "+
      "WHERE request_id=? AND state IN ('pending','claimed')"
    ).run(requestId);
    throw new WindowsRecipientConsentDenied("no authenticated target-local Windows owner approval");
  }
  private get(id:string):Row|undefined{
    return this.db.prepare(
      "SELECT request_id,prompt_json,prompt_sha256,state,decision_json,decision_sig,expires_at_ms "+
      "FROM v3_windows_human_approvals WHERE request_id=?"
    ).get(id) as Row|undefined;
  }
  /**
   * Local UI process only. Owner signature is generated after the physical
   * user presses Approve; Deny/close is the default and leaves no grant.
   */
  async ownerInteractiveCycle():Promise<"idle"|"approved"|"denied">{
    if(os.userInfo().username.toLowerCase()!=="radlina")
      throw new WindowsRecipientConsentDenied("Windows physical user agent cannot run as SYSTEM");
    const next=this.db.prepare(
      "SELECT request_id FROM v3_windows_human_approvals WHERE state='pending' "+
      "AND expires_at_ms>? ORDER BY created_at_ms LIMIT 1"
    ).get(this.now()) as {request_id:string}|undefined;
    if(!next)return"idle";
    const acquired=this.db.prepare(
      "UPDATE v3_windows_human_approvals SET state='claimed' WHERE "+
      "request_id=? AND state='pending' AND expires_at_ms>?"
    ).run(next.request_id,this.now());
    if(Number(acquired.changes)!==1)return"idle";
    const row=this.get(next.request_id);
    if(!row)throw new WindowsRecipientConsentDenied("claimed local approval missing");
    const prompt=sessionSchema.parse(JSON.parse(row.prompt_json));
    const approved=await new I01WindowsPhysicalApprovalDialog().confirm(prompt);
    if(!approved){
      this.db.prepare("UPDATE v3_windows_human_approvals SET state='denied' "+
        "WHERE request_id=? AND state='claimed'").run(next.request_id);
      return"denied";
    }
    const signer=await V3WindowsProtectedOwnerSigner.open();
    const issuedAtMs=this.now();
    const decision:WindowsLocalUserDecision={
      schema:"radlina.v3.i01.windows-local-user-decision/v1",
      requestId:prompt.requestId,promptHash:row.prompt_sha256,
      targetDeviceId:"windows-main",sourceDeviceId:"macbook-main",
      decision:"approve",nonce:randomUUID(),issuedAtMs,
      expiresAtMs:Math.min(prompt.expiresAtMs,issuedAtMs+60000),
    };
    if(decision.expiresAtMs<=issuedAtMs)
      throw new WindowsRecipientConsentDenied("local user approval expired while dialog open");
    const signed=signer.signCanonical(canonicalJson(decision));
    const stored=this.db.prepare(
      "UPDATE v3_windows_human_approvals SET state='approved',decision_json=?,decision_sig=?"+
      " WHERE request_id=? AND state='claimed' AND expires_at_ms>?"
    ).run(canonicalJson(decision),signed,prompt.requestId,this.now());
    if(Number(stored.changes)!==1)
      throw new WindowsRecipientConsentDenied("physical owner decision persistence lost");
    return"approved";
  }
  close():void{this.db.close();}
}
