/**
 * S03 independent remote audit anchor client. Runs on V3 Windows controller,
 * but acceptance depends on an independently hosted, private-Keychain-signed
 * MAC audit witness. Never degrades to the same-disk local SQLite journal.
 */
import { createPublicKey, verify } from "node:crypto";
import { canonicalJson, sha256 } from "../../utils/json.js";
import {
  signedDistributedAuditRecordSchema,
  type SignedDistributedAuditRecord,
} from "./distributed.js";
import type { I01ExternalAuditAnchor } from "../integration/i01-secured-dispatch.js";
import type { F01IndependentAuditPort, F01SignedReply, F01SignedCommand } from "../fleet/physical-adapters.js";
import type { I01OwnerSignedEnvelope, I01SignedDeviceResponse } from "../integration/i01-secured-dispatch.js";

const HASH=/^[0-9a-f]{64}$/u;
export type S03AnchorEvent = {
  schema: "radlina.v3.s03.external-event/v1";
  kind: "execution"|"fleet";
  recordHash: string;
  event: unknown;
  issuedAt: string;
};
export type S03AnchorAcknowledgment = {
  schema:"radlina.v3.s03.external-anchor/v1";
  auditNode:"macbook-main-s03";
  eventHash:string;
  recordHash:string;
  chainHead:string;
  sequence:number;
  anchoredAt:string;
};
export class S03AnchorDenied extends Error{
  constructor(msg:string){super(msg);this.name="S03AnchorDenied";}
}
export interface S03AnchorTransport {
  persist(event:S03AnchorEvent):Promise<{
    receipt:S03AnchorAcknowledgment;
    deviceSignatureBase64:string;
  }>;
}
export class S03HttpsAuditTransport implements S03AnchorTransport {
  constructor(
    private readonly endpoint:"https://v3-audit.radlina.com/v1/anchor",
  ){}
  async persist(event:S03AnchorEvent){
    const body=canonicalJson(event);
    if(Buffer.byteLength(body,"utf8")>256*1024)
      throw new S03AnchorDenied("bounded external witness event required");
    const response=await fetch(this.endpoint,{
      method:"POST",body,
      headers:{"content-type":"application/json","accept":"application/json"},
      redirect:"error",signal:AbortSignal.timeout(16000),
    });
    if(response.status!==201)throw new S03AnchorDenied("external S03 witness refused signed event");
    const bytes=Buffer.from(await response.arrayBuffer());
    if(bytes.length>8*1024)throw new S03AnchorDenied("external S03 response exceeded limit");
    const parsed=JSON.parse(bytes.toString("utf8")) as {
      receipt:S03AnchorAcknowledgment;deviceSignatureBase64:string;
    };
    return parsed;
  }
}
function ed25519Signature(key:string,message:unknown,proof:string):boolean{
  try{
    const raw=Buffer.from(proof,"base64");
    return raw.byteLength===64&&raw.toString("base64")===proof&&
      verify(null,Buffer.from(canonicalJson(message)),createPublicKey(key),raw);
  }catch{return false;}
}
export class S03IndependentMacAuditAnchor implements I01ExternalAuditAnchor,F01IndependentAuditPort {
  readonly witnessKeyFingerprint:string;
  constructor(
    private readonly transport:S03AnchorTransport,
    private readonly witnessPublicKeyPem:string,
    expectedWitnessFingerprint:string,
  ){
    const key=createPublicKey(witnessPublicKeyPem);
    this.witnessKeyFingerprint=sha256(key.export({type:"spki",format:"der"}));
    if(!HASH.test(this.witnessKeyFingerprint)||key.asymmetricKeyType!=="ed25519"||
      this.witnessKeyFingerprint!==expectedWitnessFingerprint)
      throw new S03AnchorDenied("independent Ed25519 witness public key mandatory");
  }
  private async accept(kind:"execution"|"fleet",raw:unknown,recordHash:string){
    if(!HASH.test(recordHash))throw new S03AnchorDenied("external audit event hash malformed");
    const event:S03AnchorEvent={
      schema:"radlina.v3.s03.external-event/v1",
      kind,recordHash,event:raw,issuedAt:new Date().toISOString(),
    };
    const submittedHash=sha256(canonicalJson(event));
    const {receipt,deviceSignatureBase64}=await this.transport.persist(event);
    if(receipt.schema!=="radlina.v3.s03.external-anchor/v1"||
      receipt.auditNode!=="macbook-main-s03"||
      receipt.eventHash!==submittedHash||
      receipt.recordHash!==recordHash||
      !HASH.test(receipt.chainHead)||!Number.isSafeInteger(receipt.sequence)||
      receipt.sequence<1||Math.abs(Date.now()-Date.parse(receipt.anchoredAt))>60000||
      !ed25519Signature(this.witnessPublicKeyPem,receipt,deviceSignatureBase64)){
      throw new S03AnchorDenied("remote audit acknowledgment not independently signed or mismatched");
    }
    return{accepted:true as const,recordHash,anchorId:receipt.chainHead};
  }
  async anchor(record:SignedDistributedAuditRecord,
    ownerEnvelope:I01OwnerSignedEnvelope,
    reply:I01SignedDeviceResponse,
    targetPublicKeyPem:string){
    const parsed=signedDistributedAuditRecordSchema.parse(record);
    const evidence={record:parsed,ownerEnvelope,reply,targetPublicKeyPem};
    return await this.accept("execution",evidence,parsed.recordHash);
  }
  async anchorPhysicalReceipt(input:{
    planId:string;deviceId:string;commandHash:string;
    deviceReceiptHash:string;devicePublicKeyPem:string;
    ownerSignedCommand:F01SignedCommand;
    signedReply:F01SignedReply<unknown>;
  }){
    const exact={schema:"radlina.v3.f01.audit-witness-request/v1" as const,...input};
    if(!HASH.test(input.commandHash)||!HASH.test(input.deviceReceiptHash)||
      !["macbook-main","windows-main"].includes(input.deviceId)||
      input.signedReply.deviceId!==input.deviceId||
      sha256(canonicalJson(input.signedReply.payload))!==input.deviceReceiptHash){
      throw new S03AnchorDenied("exact signed physical F01 receipt missing");
    }
    const id=sha256(canonicalJson(exact));
    const saved=await this.accept("fleet",exact,id);
    return{durable:true as const,anchorId:saved.anchorId};
  }
}
