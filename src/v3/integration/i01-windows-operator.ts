/**
 * Physical Windows owner-desktop I01 recipient cycle. This is a separate
 * interactive task, never a service session 0 or V2 process.
 * P03 machine-private device identity must already exist and match the owner.
 */
import { randomUUID } from "node:crypto";
import os from "node:os";
import path from "node:path";
import * as z from "zod/v4";
import { canonicalJson,sha256 } from "../../utils/json.js";
import { WindowsProtectedDeviceIdentity } from "../device/windows-protected-identity.js";
import { observeLiveMacTailnetPeer } from "../device/mac-heartbeat-ingress.js";
import { SqliteDeviceRegistry } from "../device/registry.js";
import { I01RecipientExecutionAgent,I01TargetReplayLedger } from "./i01-recipient-agent.js";
import { I01WindowsPhysicalApprovalDialog,I01PhysicalLocalGrantAndAudit } from "./i01-local-recipient-ports.js";
import { I01SafeNativeTextCapabilities } from "./i01-native-files.js";
import { i01SignedOwnerEnvelopeSchema,i01SignedDeviceResponseSchema } from "./i01-secured-dispatch.js";
import { i01AgentSessionSchema } from "./i01-physical-session.js";
import { buildApprovalMessage } from "../security/consent-contracts.js";

const endpoint="https://v3-mcp.radlina.com";
const macTailnetPin="c7886ac103d4c05907ff8953ae60687d31303146a9b122cb55bff0dc1860bc9c";
const windowsDevicePin="fafcea842b3d0142b9cb24ff05455a09da409d44e7d08a483b39bb0596a7f5a0";
const ownerKeyPin="6259d21211f73fc9d2d7cc0174d9bfdc36424cd456878671ab5683468ca0fe93";
const operation=z.object({
  schema:z.literal("radlina.v3.i01.leased-exact-command/v1"),
  leaseId:z.string().uuid(),targetDeviceId:z.literal("windows-main"),
  envelope:i01SignedOwnerEnvelopeSchema,
}).strict();
type I01OneResult="idle"|"s02e"|"consent"|"execution";
async function post(route:string,body:unknown):Promise<{status:number;json:unknown}>{
  const encoded=canonicalJson(body);
  if(Buffer.byteLength(encoded,"utf8")>256*1024)throw Error("bounded physical I01 Windows envelope required");
  const response=await fetch(endpoint+route,{
    method:"POST",redirect:"error",signal:AbortSignal.timeout(20000),
    headers:{"content-type":"application/json","accept":"application/json"},
    body:encoded,
  });
  if(response.status===204)return{status:204,json:null};
  const bytes=Buffer.from(await response.arrayBuffer());
  if(bytes.length>256*1024)throw Error("physical Windows I01 response too large");
  return{status:response.status,json:JSON.parse(bytes.toString("utf8"))};
}
export async function runWindowsI01RecipientOnce(ownerPublicKeyPem:string):Promise<I01OneResult>{
  if(process.platform!=="win32"||os.hostname().toLowerCase()!=="laptop-13qineif"||
    os.userInfo().username.toLowerCase()!=="radlina"||
    process.env["RADLINA_V3_WINDOWS_OWNER_OPERATOR"]!=="1"||
    process.env["RADLINA_V3_PUBLIC_URL"]){
    throw Error("physical logged-in Windows owner operator required");
  }
  if(sha256((await import("node:crypto")).createPublicKey(ownerPublicKeyPem)
    .export({type:"spki",format:"der"}))!==ownerKeyPin){
    throw Error("exact physical V3 owner Ed25519 public pin required");
  }
  const agent=await WindowsProtectedDeviceIdentity.open(
    "E:\\radlina-v3-runtime\\windows-device-identity",
  );
  const identity=agent.publicIdentity();
  if(identity.fingerprint!==windowsDevicePin||identity.deviceId!=="windows-main"){
    throw Error("physical protected Windows P03 agent identity changed");
  }
  const registry=new SqliteDeviceRegistry("E:\\radlina-v3-oauth-standalone\\v3-devices.sqlite3");
  try{
    const record=registry.require("windows-main");
    const stamp=Date.parse(record.lastSeen);
    if(record.trustState!=="trusted"||record.status!=="online"||
      !Number.isFinite(stamp)||Date.now()-stamp>120000||stamp>Date.now()){
      throw Error("signed physical Windows P03 heartbeat missing or stale");
    }
  }finally{registry.close();}
  function session(){
    const claim=i01AgentSessionSchema.parse({
      schema:"radlina.v3.i01.device-session/v1",
      deviceId:"windows-main",nonce:randomUUID(),signedAtMs:Date.now(),
    });
    return{
      deviceId:claim.deviceId,nonce:claim.nonce,signedAtMs:claim.signedAtMs,
      signatureBase64:agent.signExactV3Receipt(canonicalJson(claim)),
    };
  }
  const recovery=new I01TargetReplayLedger(path.join(
    "E:\\radlina-v3-oauth-standalone","windows-owner-agent","target-once-operations.sqlite3",
  ));
  try{
    const pending=recovery.nextUndelivered();
    if(pending){
      const reported=await post("/v3/agent/report",{
        session:session(),leaseId:pending.leaseId,response:pending.reply,
      });
      if(reported.status!==202)
        throw Error("previous Windows signed receipt uncertain; never repeat native operation");
      recovery.markReported(pending.requestId);
      return"execution";
    }
  }finally{recovery.close();}
  const gui=new I01WindowsPhysicalApprovalDialog();
  const s02e=await post("/v3/agent/s02e-claim",{session:session()});
  if(s02e.status===200){
    const envelope=s02e.json as {schema?:string;request?:Record<string,unknown>};
    if(envelope.schema!=="radlina.v3.i01.s02e-owner-scoped-consent-request/v1"||
      !envelope.request||envelope.request["targetDeviceId"]!=="windows-main")
      throw Error("physical Windows S02E request mismatch");
    const r=envelope.request;
    const ownerSubject=String(r["subject"]);
    const confirmed=await gui.confirm({
      requestId:String(r["requestId"]),
      operationSha256:String(r["requestHash"]),
      sourceDeviceId:"macbook-main",targetDeviceId:"windows-main",
      subject:ownerSubject,capability:String(r["capability"]),
      inputSha256:String(r["inputSha256"]),
      resourceDescription:String(r["resourceKey"]),
      issuedAtMs:Number(r["requestedAtMs"]),
      expiresAtMs:Number(r["requestExpiresAtMs"]),
    });
    const now=Date.now();
    const unsigned:Parameters<typeof buildApprovalMessage>[1]={
      requestId:String(r["requestId"]),
      decision:(confirmed?"approve":"deny"),
      duration:"once" as const,
      validUntilMs:confirmed?now+10*60*1000:null,
      signedAtMs:now,nonce:randomUUID(),
    };
    const signedMessage=buildApprovalMessage(
      r as Parameters<typeof buildApprovalMessage>[0],unsigned,
    );
    const decision={
      ...unsigned,
      signatureBase64:agent.signExactV3Receipt(canonicalJson(signedMessage)),
    };
    const response=await post("/v3/agent/s02e-decision",{session:session(),decision});
    if(response.status!==202)throw Error("physical Windows S02E consent response uncertain");
    return"s02e";
  }
  if(s02e.status!==204)throw Error("physical Windows S02E endpoint denied");
  const local=await post("/v3/agent/consent-claim",{session:session()});
  if(local.status===200){
    const outer=local.json as {schema?:string;prompt?:Record<string,unknown>};
    const r=outer.prompt;
    if(!r||r["targetDeviceId"]!=="windows-main")
      throw Error("physical Windows exact local consent mismatch");
    const confirmed=await gui.confirm({
      requestId:String(r["requestId"]),operationSha256:String(r["operationSha256"]),
      sourceDeviceId:"macbook-main",targetDeviceId:"windows-main",
      subject:String(r["subject"]),capability:String(r["capability"]),
      inputSha256:String(r["inputSha256"]),
      resourceDescription:String(r["resourceDescription"]),
      issuedAtMs:Number(r["issuedAtMs"]),expiresAtMs:Number(r["expiresAtMs"]),
    });
    if(!confirmed){
      const result=await post("/v3/agent/consent-deny",{
        session:session(),requestId:String(r["requestId"]),
      });
      if(result.status!==202)throw Error("physical Windows local consent denial uncertain");
      return"consent";
    }
    const now=Date.now();
    const approval={
      schema:"radlina.v3.i01.recipient-approval/v1" as const,
      operationSha256:String(r["operationSha256"]),
      sourceDeviceId:"macbook-main",
      targetDeviceId:"windows-main",
      subject:String(r["subject"]),localUserApproved:true as const,
      nonce:randomUUID(),issuedAtMs:now,
      expiresAtMs:Math.min(now+60000,Number(r["expiresAtMs"])),
    };
    const signed={
      approval,
      deviceSignatureBase64:agent.signExactV3Receipt(canonicalJson(approval)),
    };
    const localGrants=new I01PhysicalLocalGrantAndAudit(
      "E:\\radlina-v3-oauth-standalone\\windows-owner-agent\\target-approval-audit.sqlite3",
      "windows-main",
    );
    try{
      localGrants.record({approval:signed,request:{
        requestId:String(r["requestId"]),
        operationSha256:String(r["operationSha256"]),
        sourceDeviceId:"macbook-main",targetDeviceId:"windows-main",
        subject:String(r["subject"]),capability:String(r["capability"]),
        inputSha256:String(r["inputSha256"]),
        resourceDescription:String(r["resourceDescription"]),
        issuedAtMs:Number(r["issuedAtMs"]),expiresAtMs:Number(r["expiresAtMs"]),
      }});
    }finally{localGrants.close();}
    const result=await post("/v3/agent/consent-submit",{
      session:session(),signed,
    });
    if(result.status!==202)throw Error("Windows target signed approval uncertain");
    return"consent";
  }
  if(local.status!==204)throw Error("physical Windows local consent endpoint denied");
  const leased=await post("/v3/agent/claim",{session:session()});
  if(leased.status===204)return"idle";
  if(leased.status!==200)throw Error("physical Windows command polling denied");
  const exact=operation.parse(leased.json);
  const target=path.join("E:\\radlina-v3-oauth-standalone","windows-owner-agent");
  const grants=new I01PhysicalLocalGrantAndAudit(
    path.join(target,"target-approval-audit.sqlite3"),"windows-main",
  );
  const replay=new I01TargetReplayLedger(
    path.join(target,"target-once-operations.sqlite3"),
  );
  const native=new I01SafeNativeTextCapabilities(
    "windows-main","C:\\Users\\Radlina\\OneDrive\\Desktop\\RadlinaV3",
  );
  const recipient=new I01RecipientExecutionAgent({
    deviceId:"windows-main",agentInstanceId:identity.agentInstanceId,
    publicKeyPem:identity.publicKeyPem,publicKeyFingerprint:identity.fingerprint,
    verifiedSignedHeartbeatFresh:true,installedCapabilities:native.capabilities,
  },ownerPublicKeyPem,ownerKeyPin,{
    physicallyVerifiedController:async()=>observeLiveMacTailnetPeer()===macTailnetPin,
  },grants,native,{
    signCanonical:async(payload)=>agent.signExactV3Receipt(payload),
  },grants,replay);
  try{
    replay.recordLease(exact.envelope.operation.requestId,exact.leaseId);
    const reply=i01SignedDeviceResponseSchema.parse(
      await recipient.receive(exact.envelope),
    );
    const result=await post("/v3/agent/report",{
      session:session(),leaseId:exact.leaseId,response:reply,
    });
    if(result.status!==202)
      throw Error("physical Windows mutation may have completed; receipt uncertain");
    replay.markReported(reply.requestId);
    return"execution";
  }finally{grants.close();replay.close();}
}
