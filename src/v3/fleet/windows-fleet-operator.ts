/**
 * Physical Windows F01 recipient, separate interactive elevated owner process.
 * Only RadlinaV3OAuthBeta can switch. Never modifies V2 or its service.
 */
import { createPublicKey, randomUUID } from "node:crypto";
import { mkdir } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { canonicalJson, sha256 } from "../../utils/json.js";
import { WindowsProtectedDeviceIdentity } from "../device/windows-protected-identity.js";
import { V3LiveTailnetNodeObserver } from "../integration/i01-tailnet-observer.js";
import { i01AgentSessionSchema } from "../integration/i01-physical-session.js";
import { I01WindowsPhysicalApprovalDialog } from "../integration/i01-local-recipient-ports.js";
import { F01PhysicalRecipientAgent, F01LocalReplayStore } from "./local-release-agent.js";
import { WindowsV3NativeReleaseHost } from "./native-v3-release-host.js";
import { F01PhysicalLocalAuditChain } from "./f01-local-audit.js";
import { f01SignedCommandSchema } from "./physical-adapters.js";
import * as z from "zod/v4";

const gateway="https://v3-mcp.radlina.com";
const windowsPin="fafcea842b3d0142b9cb24ff05455a09da409d44e7d08a483b39bb0596a7f5a0";
const ownerPin="6259d21211f73fc9d2d7cc0174d9bfdc36424cd456878671ab5683468ca0fe93";
const signedFleet=z.object({
  schema:z.literal("radlina.v3.f01.leased-fleet-command/v1"),
  leaseId:z.string().uuid(),
  command:f01SignedCommandSchema,
}).strict();
const fleetPrompt=z.object({
  schema:z.literal("radlina.v3.f01.release-approval-prompt/v1"),
  prompt:z.object({
    requestId:z.string().uuid(),
    deviceId:z.literal("windows-main"),
    planId:z.string().uuid(),
    operation:z.enum(["fleet.preflight","fleet.activate","fleet.verify","fleet.rollback"]),
    targetManifestSha256:z.string().regex(/^[a-f0-9]{64}$/u),
    previousManifestSha256:z.string().regex(/^[a-f0-9]{64}$/u),
    expiresAtMs:z.number().int().positive(),
  }).strict(),
}).strict();
async function request(route:string,body:unknown):Promise<{status:number;data:unknown}>{
  const message=canonicalJson(body);
  if(Buffer.byteLength(message,"utf8")>256*1024)throw Error("V3 bounded signed fleet message required");
  const response=await fetch(gateway+route,{
    method:"POST",redirect:"error",headers:{
      "content-type":"application/json","accept":"application/json",
    },body:message,signal:AbortSignal.timeout(20000),
  });
  if(response.status===204)return{status:204,data:null};
  const bytes=Buffer.from(await response.arrayBuffer());
  if(bytes.length>262144)throw Error("oversized F01 signed fleet response");
  return{status:response.status,data:JSON.parse(bytes.toString("utf8")) as unknown};
}
export async function runPhysicalWindowsFleetOnce(config:{
  ownerPublicKeyPem:string;
  macTailnetNodeHash:string;
}):Promise<"idle"|"fleet-approval"|"fleet-receipt-delivered">{
  if(process.platform!=="win32"||os.hostname().toLowerCase()!=="laptop-13qineif"||
    os.userInfo().username.toLowerCase()!=="radlina"||
    process.env["RADLINA_V3_FLEET_SUPERVISOR"]!=="1"||
    process.env["RADLINA_V3_PUBLIC_URL"]){
    throw Error("dedicated interactive Windows V3 fleet supervisor required");
  }
  if(sha256(createPublicKey(config.ownerPublicKeyPem).export({type:"spki",format:"der"}))!==ownerPin||
    !/^[a-f0-9]{64}$/u.test(config.macTailnetNodeHash)){
    throw Error("owner P03 public key and real Mac Tailnet pin required");
  }
  const observer=new V3LiveTailnetNodeObserver();
  if(observer.observeExactTailnetNodeHash("macbook-main")!==config.macTailnetNodeHash)
    throw Error("physical Mac peer unavailable for Windows F01");
  const device=await WindowsProtectedDeviceIdentity.open(
    "E:\\radlina-v3-runtime\\windows-device-identity");
  const identity=device.publicIdentity();
  if(identity.deviceId!=="windows-main"||identity.fingerprint!==windowsPin)
    throw Error("protected Windows P03 identity mismatch");
  const session=()=>{
    const payload=i01AgentSessionSchema.parse({
      schema:"radlina.v3.i01.device-session/v1",
      deviceId:"windows-main",nonce:randomUUID(),signedAtMs:Date.now(),
    });
    return {
      deviceId:payload.deviceId,nonce:payload.nonce,signedAtMs:payload.signedAtMs,
      signatureBase64:device.signExactV3Receipt(canonicalJson(payload)),
    };
  };
  const local=new I01WindowsPhysicalApprovalDialog();
  const consent=await request("/v3/fleet/consent-claim",{session:session()});
  if(consent.status===200){
    const {prompt}=fleetPrompt.parse(consent.data);
    if(prompt.expiresAtMs<=Date.now())
      throw Error("physical Windows F01 approval already expired");
    const approved=await local.confirm({
      requestId:prompt.requestId,
      operationSha256:sha256(canonicalJson(prompt)),
      sourceDeviceId:"macbook-main",
      targetDeviceId:"windows-main",
      subject:"Physical V3 fleet release",
      capability:prompt.operation,
      inputSha256:prompt.targetManifestSha256,
      resourceDescription:"Target "+prompt.targetManifestSha256+
        " / rollback "+prompt.previousManifestSha256,
      issuedAtMs:Date.now(),
      expiresAtMs:prompt.expiresAtMs,
    });
    if(!approved)return"idle";
    const issuedAtMs=Date.now();
    const receipt={
      schema:"radlina.v3.f01.recipient-release-consent/v1" as const,
      requestId:prompt.requestId,deviceId:"windows-main" as const,
      planId:prompt.planId,operation:prompt.operation,
      targetManifestSha256:prompt.targetManifestSha256,
      previousManifestSha256:prompt.previousManifestSha256,
      localUserApproved:true as const,
      nonce:randomUUID(),issuedAtMs,
      expiresAtMs:Math.min(prompt.expiresAtMs,issuedAtMs+60000),
    };
    if(receipt.expiresAtMs<=issuedAtMs)
      throw Error("F01 Windows physical consent expired during local UI");
    const signed={
      approval:receipt,
      deviceSignatureBase64:device.signExactV3Receipt(canonicalJson(receipt)),
    };
    const done=await request("/v3/fleet/consent-decision",{session:session(),signed});
    if(done.status!==202)throw Error("F01 recipient consent receipt uncertain");
    return"fleet-approval";
  }
  if(consent.status!==204)throw Error("F01 Windows recipient consent endpoint unavailable");
  const polled=await request("/v3/fleet/claim",{session:session()});
  if(polled.status===204)return"idle";
  if(polled.status!==200)throw Error("F01 physical command claim denied");
  const {command,leaseId}=signedFleet.parse(polled.data);
  if(command.command.deviceId!=="windows-main")
    throw Error("physical Windows received a foreign target");
  const folder="E:\\radlina-v3-oauth-standalone\\windows-owner-agent\\fleet";
  await mkdir(folder,{recursive:true});
  const journal=new F01LocalReplayStore(path.join(folder,"fleet-once.sqlite3"));
  const audit=new F01PhysicalLocalAuditChain(path.join(folder,"fleet-audit.sqlite3"),"windows-main");
  try{
    const ownerDecision={
      check:async(exact:typeof command.command)=>{
        if(exact.deviceId!=="windows-main"||
          observer.observeExactTailnetNodeHash("macbook-main")!==config.macTailnetNodeHash)return false;
        return await local.confirm({
          requestId:exact.operationId,
          operationSha256:sha256(canonicalJson(exact)),
          sourceDeviceId:"macbook-main",
          targetDeviceId:"windows-main",
          subject:"Owner-signed V3 physical release",
          capability:exact.action,
          inputSha256:exact.targetManifestSha256,
          resourceDescription:"Manifest "+exact.targetManifestSha256+
            " / Previous "+exact.previousManifestSha256,
          issuedAtMs:exact.issuedAtMs,
          expiresAtMs:exact.expiresAtMs,
        });
      },
    };
    const agent=new F01PhysicalRecipientAgent(new WindowsV3NativeReleaseHost(),{
      deviceId:"windows-main",
      agentInstanceId:identity.agentInstanceId,
      publicKeyFingerprint:identity.fingerprint,
      liveP03KeyAndHeartbeat:async()=>
        observer.observeExactTailnetNodeHash("macbook-main")===config.macTailnetNodeHash,
      signReceipt:async(payload:string)=>device.signExactV3Receipt(payload),
    },config.ownerPublicKeyPem,ownerPin,ownerDecision,audit,journal);
    const signed=await agent.execute(command);
    const delivered=await request("/v3/fleet/report",{
      session:session(),leaseId,response:signed,
    });
    if(delivered.status!==202)
      throw Error("physical Windows release may have completed; manual reconciliation required");
    return"fleet-receipt-delivered";
  }finally{audit.close();journal.close();}
}
