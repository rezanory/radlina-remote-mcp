/**
 * V3 owner-protected signing broker.
 *
 * Windows V3 service cannot use the interactive owner's CurrentUser DPAPI
 * private key. A separate logged-in owner agent reads sealed requests, shows a
 * physical owner approval UI, then signs exact bounded operations. No server
 * process is allowed to impersonate the owner.
 */
import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { canonicalJson, sha256 } from "../../utils/json.js";
import { i01ExactOperationSchema } from "../integration/i01-secured-dispatch.js";
import { f01ExactFleetCommandSchema } from "../fleet/physical-adapters.js";
import type { I01OwnerSigner } from "../integration/i01-secured-dispatch.js";
import type { F01OwnerProtectedSigner } from "../fleet/physical-adapters.js";
import { I01WindowsDpapiSealer } from "../integration/i01-physical-session.js";
import { I01WindowsPhysicalApprovalDialog } from "../integration/i01-local-recipient-ports.js";
import { V3WindowsProtectedOwnerSigner } from "./windows-owner-signer.js";

export class V3OwnerSignRequestDenied extends Error {
  constructor(msg:string){super(msg);this.name="V3OwnerSignRequestDenied";}
}
type RequestRow={
  request_id:string;operation_hash:string;sealed_payload:Uint8Array;
  requested_at_ms:number;expires_at_ms:number;
  state:"pending"|"claimed"|"approved"|"denied"|"expired";
  signature_base64:string|null;
};
export class V3OwnerProtectedSigningBroker implements I01OwnerSigner,F01OwnerProtectedSigner {
  readonly db:DatabaseSync;
  private readonly crypt:I01WindowsDpapiSealer;
  constructor(
    databaseFile:string,
    private readonly now:()=>number=()=>Date.now(),
  ){
    if(!path.win32.isAbsolute(databaseFile)||databaseFile.toLowerCase().includes("\\v2\\"))
      throw new V3OwnerSignRequestDenied("private isolated V3 owner signing inbox required");
    mkdirSync(path.dirname(databaseFile),{recursive:true});
    this.db=new DatabaseSync(databaseFile,{enableForeignKeyConstraints:true});
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS v3_owner_signing_inbox("+
      "request_id TEXT PRIMARY KEY,operation_hash TEXT NOT NULL UNIQUE,"+
      "sealed_payload BLOB NOT NULL,requested_at_ms INTEGER NOT NULL,expires_at_ms INTEGER NOT NULL,"+
      "state TEXT NOT NULL CHECK(state IN ('pending','claimed','approved','denied','expired')),"+
      "signature_base64 TEXT);"
    );
    this.crypt=new I01WindowsDpapiSealer();
  }
  async sign(message:string):Promise<string>{
    if(Buffer.byteLength(message,"utf8")>256*1024)
      throw new V3OwnerSignRequestDenied("owner sign operation too large");
    const value:unknown=JSON.parse(message);
    if(canonicalJson(value)!==message)
      throw new V3OwnerSignRequestDenied("canonical V3 owner operation required");
    const operation=value as Record<string,unknown>;
    const parsed=operation["schema"]==="radlina.v3.i01.exact-device-dispatch/v1"
      ?i01ExactOperationSchema.parse(value):
       operation["schema"]==="radlina.v3.f01.exact-fleet-operation/v1"
      ?f01ExactFleetCommandSchema.parse(value):null;
    if(parsed===null)
      throw new V3OwnerSignRequestDenied("owner broker does not sign unbounded messages");
    const current=this.now();
    if(parsed.expiresAtMs<=current||parsed.issuedAtMs>current||
      parsed.expiresAtMs-current>120000){
      throw new V3OwnerSignRequestDenied("owner operation signature request must be fresh");
    }
    const operationHash=sha256(message);
    const sealed=await this.crypt.seal(Buffer.from(message,"utf8"));
    const requestId=randomUUID();
    this.db.prepare(
      "INSERT INTO v3_owner_signing_inbox(request_id,operation_hash,sealed_payload,"+
      "requested_at_ms,expires_at_ms,state) VALUES(?,?,?,?,?,'pending')"
    ).run(requestId,operationHash,sealed,current,Math.min(parsed.expiresAtMs,current+90000));
    while(this.now()<Math.min(parsed.expiresAtMs,current+90000)){
      const row=this.db.prepare(
        "SELECT state,signature_base64 FROM v3_owner_signing_inbox WHERE request_id=?"
      ).get(requestId) as {state:string;signature_base64:string|null}|undefined;
      if(row?.state==="approved"&&row.signature_base64){
        return row.signature_base64;
      }
      if(row?.state==="denied"||row?.state==="expired")break;
      await new Promise(resolve=>setTimeout(resolve,250));
    }
    this.db.prepare(
      "UPDATE v3_owner_signing_inbox SET state='expired' WHERE request_id=? "+
      "AND state IN ('pending','claimed')"
    ).run(requestId);
    throw new V3OwnerSignRequestDenied("physical Windows owner did not sign exact request");
  }
  async signCanonical(message:string):Promise<string>{return await this.sign(message);}
  private read(requestId:string):RequestRow|undefined{
    return this.db.prepare(
      "SELECT request_id,operation_hash,sealed_payload,requested_at_ms,"+
      "expires_at_ms,state,signature_base64 FROM v3_owner_signing_inbox WHERE request_id=?"
    ).get(requestId) as RequestRow|undefined;
  }
  async nextForInteractiveOwner():Promise<{
    requestId:string;canonical:string;
  }|null>{
    if(process.platform!=="win32"||os.userInfo().username.toLowerCase()!=="radlina")
      throw new V3OwnerSignRequestDenied("logged-in Windows owner signing agent required");
    const row=this.db.prepare(
      "SELECT request_id FROM v3_owner_signing_inbox WHERE state='pending' "+
      "AND expires_at_ms>? ORDER BY requested_at_ms LIMIT 1"
    ).get(this.now()) as {request_id:string}|undefined;
    if(!row)return null;
    const claimed=this.db.prepare(
      "UPDATE v3_owner_signing_inbox SET state='claimed' WHERE "+
      "request_id=? AND state='pending' AND expires_at_ms>?"
    ).run(row.request_id,this.now());
    if(Number(claimed.changes)!==1)return null;
    const record=this.read(row.request_id);
    if(!record)throw new V3OwnerSignRequestDenied("claimed owner request missing");
    const bytes=await this.crypt.unseal(record.sealed_payload);
    try{
      const canonical=Buffer.from(bytes).toString("utf8");
      if(sha256(canonical)!==record.operation_hash)
        throw new V3OwnerSignRequestDenied("owner sealed operation integrity changed");
      return{requestId:record.request_id,canonical};
    }finally{Buffer.from(bytes).fill(0);}
  }
  async approveWithLocalHuman(input:{requestId:string;canonical:string}):Promise<boolean>{
    const record=this.read(input.requestId);
    if(!record||record.state!=="claimed"||record.expires_at_ms<=this.now()||
      sha256(input.canonical)!==record.operation_hash)
      throw new V3OwnerSignRequestDenied("owner approval request expired or mismatched");
    const message=JSON.parse(input.canonical) as Record<string,unknown>;
    const capability=message["capability"]??message["action"];
    const target=message["targetDeviceId"]??message["deviceId"];
    const yes=await new I01WindowsPhysicalApprovalDialog().confirm({
      requestId:input.requestId,operationSha256:record.operation_hash,
      sourceDeviceId:"windows-main",
      targetDeviceId:String(target)==="windows-main"?"windows-main":"macbook-main",
      subject:"owner approval",
      capability:String(capability),
      inputSha256:record.operation_hash,
      resourceDescription:"physical target: "+String(target),
      issuedAtMs:record.requested_at_ms,expiresAtMs:record.expires_at_ms,
    });
    if(!yes){
      this.db.prepare(
        "UPDATE v3_owner_signing_inbox SET state='denied' WHERE request_id=? AND state='claimed'"
      ).run(input.requestId);
      return false;
    }
    // Only this logged-in CurrentUser protected process can sign.
    const signer=await V3WindowsProtectedOwnerSigner.open();
    const signature=signer.signCanonical(input.canonical);
    const done=this.db.prepare(
      "UPDATE v3_owner_signing_inbox SET state='approved',signature_base64=? "+
      "WHERE request_id=? AND state='claimed' AND expires_at_ms>?"
    ).run(signature,input.requestId,this.now());
    if(Number(done.changes)!==1)
      throw new V3OwnerSignRequestDenied("owner signed decision not committed");
    return true;
  }
  close():void{this.db.close();}
}
