/**
 * I01 local recipient UI, one-time grants and target audit, both platforms.
 * No remote "approve=true" input may substitute the physical user's decision.
 */
import { execFile as execCallback } from "node:child_process";
import { mkdirSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { canonicalJson, sha256 } from "../../utils/json.js";
import type { I01LocalConsentPrompt } from "./i01-local-consent-mailbox.js";
import type {
  I01TargetLocalApprovalStore, I01TargetLocalAudit,
} from "./i01-recipient-agent.js";
import type { I01SignedRecipientApproval } from "./i01-secured-dispatch.js";
const execFile=promisify(execCallback);
export class I01LocalRecipientDenied extends Error {
  constructor(msg:string){super(msg);this.name="I01LocalRecipientDenied";}
}
export interface I01PhysicalTargetApprovalUI {
  /** Human must approve this exact operation, with Deny being default. */
  confirm(prompt:I01LocalConsentPrompt):Promise<boolean>;
}
export class I01MacPhysicalApprovalDialog implements I01PhysicalTargetApprovalUI {
  async confirm(prompt:I01LocalConsentPrompt):Promise<boolean>{
    if(process.platform!=="darwin"||os.hostname()!=="amirs-MacBook-Pro.local")
      throw new I01LocalRecipientDenied("real Mac approval UI required");
    const scope=[
      "Radlina V3 physical device consent",
      "Source: "+prompt.sourceDeviceId,
      "Target: "+prompt.targetDeviceId,
      "Subject: "+prompt.subject,
      "Operation: "+prompt.capability,
      "Resource: "+prompt.resourceDescription,
      "Input SHA256: "+prompt.inputSha256,
      "Operation SHA256: "+prompt.operationSha256,
      "Approval expires in up to 2 minutes.",
    ].join("\n");
    // Escape for AppleScript: no untrusted content may inject commands.
    const message=JSON.stringify(scope);
    const script="display dialog "+message+
      ' with title "Radlina V3 device consent" buttons {"Deny","Approve"} '+
      'default button "Deny" cancel button "Deny" with icon caution giving up after 90';
    try{
      const {stdout}=await execFile("/usr/bin/osascript",["-e",script],{
        timeout:95000,maxBuffer:2048,
      });
      return stdout.trim().startsWith("button returned:Approve");
    }catch{return false;}
  }
}
export class I01WindowsPhysicalApprovalDialog implements I01PhysicalTargetApprovalUI {
  async confirm(prompt:I01LocalConsentPrompt):Promise<boolean>{
    if(process.platform!=="win32"||os.hostname().toLowerCase()!=="laptop-13qineif"||
      os.userInfo().username.toLowerCase()!=="radlina")
      throw new I01LocalRecipientDenied("interactive Windows owner desktop required");
    const display=[
      "Radlina V3 device authorization",
      "From: "+prompt.sourceDeviceId,
      "To: "+prompt.targetDeviceId,
      "Operation: "+prompt.capability,
      "Resource: "+prompt.resourceDescription,
      "Operation hash: "+prompt.operationSha256,
      "Expires: "+new Date(prompt.expiresAtMs).toISOString(),
    ].join("\n");
    const encoded=Buffer.from(display,"utf16le").toString("base64");
    const script="$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Windows.Forms;"+
      "$text=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('"+encoded+"'));"+
      "$answer=[Windows.Forms.MessageBox]::Show($text,'Radlina V3 local consent',"+
      "[Windows.Forms.MessageBoxButtons]::YesNo,[Windows.Forms.MessageBoxIcon]::Warning,"+
      "[Windows.Forms.MessageBoxDefaultButton]::Button2);"+
      "if($answer -eq [Windows.Forms.DialogResult]::Yes){'APPROVED'}else{'DENIED'}";
    try{
      const {stdout}=await execFile("powershell.exe",
        ["-NoProfile","-NonInteractive","-Command",script],{
          timeout:95000,maxBuffer:2048,windowsHide:false,
        });
      return stdout.trim()==="APPROVED";
    }catch{return false;}
  }
}
type GrantInput={
  approval:I01SignedRecipientApproval;
  request:I01LocalConsentPrompt;
};
/** Private SQLite is target-local and contains only bounded one-time approvals. */
export class I01PhysicalLocalGrantAndAudit implements I01TargetLocalApprovalStore,I01TargetLocalAudit {
  readonly db:DatabaseSync;
  constructor(databaseFile:string,readonly deviceId:"macbook-main"|"windows-main"){
    if(!path.isAbsolute(databaseFile)||databaseFile.toLowerCase().includes("\\v2\\"))
      throw new I01LocalRecipientDenied("isolated absolute V3 target database required");
    mkdirSync(path.dirname(databaseFile),{recursive:true,mode:0o700});
    this.db=new DatabaseSync(databaseFile,{enableForeignKeyConstraints:true});
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS v3_i01_local_grants("+
      "operation_sha256 TEXT PRIMARY KEY, approval_nonce TEXT NOT NULL UNIQUE,"+
      "approval_json TEXT NOT NULL,used_at_ms INTEGER,expires_at_ms INTEGER NOT NULL);"+
      "CREATE TABLE IF NOT EXISTS v3_i01_target_audit("+
      "sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_json TEXT NOT NULL,"+
      "previous_hash TEXT NOT NULL,event_hash TEXT NOT NULL);"
    );
  }
  record({approval,request}:GrantInput):void{
    const scope=approval.approval;
    const now=Date.now();
    if(scope.schema!=="radlina.v3.i01.recipient-approval/v1"||
      scope.targetDeviceId!==this.deviceId||
      scope.operationSha256!==request.operationSha256||
      scope.sourceDeviceId!==request.sourceDeviceId||
      scope.subject!==request.subject||
      !scope.localUserApproved||scope.issuedAtMs>now||
      scope.issuedAtMs<request.issuedAtMs||
      scope.expiresAtMs<=now||scope.expiresAtMs>request.expiresAtMs||
      Buffer.from(approval.deviceSignatureBase64,"base64").length!==64) {
      throw new I01LocalRecipientDenied("locally approved exact P03 scope required");
    }
    this.db.prepare(
      "INSERT INTO v3_i01_local_grants(operation_sha256,approval_nonce,approval_json,expires_at_ms) "+
      "VALUES(?,?,?,?)"
    ).run(scope.operationSha256,scope.nonce,canonicalJson(approval),scope.expiresAtMs);
  }
  async requireMatchingInteractiveGrant(input:{
    nonce:string;operationSha256:string;sourceDeviceId:string;targetDeviceId:string;
    subject:string;capability:string;inputSha256:string;expiresAtMs:number;
  }):Promise<boolean>{
    if(input.targetDeviceId!==this.deviceId)return false;
    const row=this.db.prepare(
      "SELECT approval_json,used_at_ms,expires_at_ms FROM v3_i01_local_grants WHERE operation_sha256=? "+
      "AND approval_nonce=?"
    ).get(input.operationSha256,input.nonce) as {
      approval_json:string;used_at_ms:number|null;expires_at_ms:number;
    }|undefined;
    if(!row||row.used_at_ms!==null||row.expires_at_ms<=Date.now()||
      row.expires_at_ms!==input.expiresAtMs)return false;
    const raw=JSON.parse(row.approval_json) as I01SignedRecipientApproval;
    const proof=raw.approval;
    if(proof.sourceDeviceId!==input.sourceDeviceId||
      proof.targetDeviceId!==input.targetDeviceId||
      proof.subject!==input.subject||
      proof.operationSha256!==input.operationSha256||
      proof.nonce!==input.nonce)return false;
    const update=this.db.prepare(
      "UPDATE v3_i01_local_grants SET used_at_ms=? WHERE operation_sha256=? "+
      "AND approval_nonce=? AND used_at_ms IS NULL AND expires_at_ms>?"
    ).run(Date.now(),input.operationSha256,input.nonce,Date.now());
    return Number(update.changes)===1;
  }
  async anchor(input:{
    sourceDeviceId:string;targetDeviceId:string;requestId:string;capability:string;
    inputSha256:string;outputSha256:string|null;startedAt:string;endedAt:string;
  }):Promise<{durable:true;localAuditReceiptHash:string}>{
    if(input.targetDeviceId!==this.deviceId||!input.requestId||
      !/^[0-9a-f]{64}$/u.test(input.inputSha256)){
      throw new I01LocalRecipientDenied("bounded target-local audit receipt required");
    }
    this.db.exec("BEGIN IMMEDIATE");
    try{
      const last=this.db.prepare(
        "SELECT event_hash FROM v3_i01_target_audit ORDER BY sequence DESC LIMIT 1"
      ).get() as {event_hash:string}|undefined;
      const previous=last?.event_hash??"0".repeat(64);
      const event={...input,at:new Date().toISOString()};
      const hash=sha256(canonicalJson({previous,event}));
      this.db.prepare(
        "INSERT INTO v3_i01_target_audit(event_json,previous_hash,event_hash) VALUES(?,?,?)"
      ).run(canonicalJson(event),previous,hash);
      this.db.exec("COMMIT");
      return{durable:true,localAuditReceiptHash:hash};
    }catch(e){this.db.exec("ROLLBACK");throw e;}
  }
  close():void{this.db.close();}
}
