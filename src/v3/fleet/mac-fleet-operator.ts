/**
 * Physical macOS F01 target. Runs only in a dedicated user-level fleet
 * supervisor (different LaunchAgent from V3 operator and heartbeat sender).
 */
import { execFile as execCallback } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import * as z from "zod/v4";
import { canonicalJson, sha256 } from "../../utils/json.js";
import { ExistingPhysicalMacP03Signer } from "../device/macos-p03-signer.js";
import { MacV3NativeReleaseHost } from "./native-v3-release-host.js";
import { F01PhysicalRecipientAgent,F01LocalReplayStore } from "./local-release-agent.js";
import { F01PhysicalLocalAuditChain } from "./f01-local-audit.js";
import { f01SignedCommandSchema } from "./physical-adapters.js";
import { I01MacPhysicalApprovalDialog } from "../integration/i01-local-recipient-ports.js";
import { i01AgentSessionSchema } from "../integration/i01-physical-session.js";

const run=promisify(execCallback);
const endpoint="https://v3-mcp.radlina.com";
const label="com.radlina.remote-mcp.v3.mac-fleet-agent";
const allowedCommands=new Set(["fleet.preflight","fleet.activate","fleet.verify","fleet.rollback"]);
const fleetLeaseSchema=z.object({
  schema:z.literal("radlina.v3.f01.leased-fleet-command/v1"),
  leaseId:z.string().uuid(),
  command:f01SignedCommandSchema,
}).strict();
const expectedOwnerFingerprint="6259d21211f73fc9d2d7cc0174d9bfdc36424cd456878671ab5683468ca0fe93";
const expectedWindowsTailnetHash="b7bfc7b8c91c6085911f5de9cf079db4433f0b7a4e8e3df0438f0ab58925a6";
// Expected exact Windows Tailnet hash MUST come from the owner-signed F01 rollout
// configuration; the constant above must never be used as an identity fallback.
async function observeWindowsPeer():Promise<string|undefined>{
  for(const binary of ["/usr/local/bin/tailscale","/Applications/Tailscale.app/Contents/MacOS/Tailscale"]){
    try{
      const{stdout}=await run(binary,["status","--json"],{timeout:12000,maxBuffer:4*1024*1024});
      const status=JSON.parse(stdout) as {
        BackendState?:string;CurrentTailnet?:{Name?:string};
        Peer?:Record<string,{ID?:string;OS?:string;Online?:boolean;DNSName?:string}>};
      if(status.BackendState!=="Running"||status.CurrentTailnet?.Name!=="rezanory.github")continue;
      const peers=Object.values(status.Peer??{}).filter(p=>
        p.OS==="windows"&&p.Online===true&&
        p.DNSName?.replace(/\.$/u,"").toLowerCase()==="laptop-13qineif.taile17c9e.ts.net");
      if(peers.length===1&&peers[0]?.ID)return sha256(peers[0].ID);
    }catch{/* alternate installed tailnet app; never change VPN */}
  }
  return undefined;
}
async function post(pathname:string,body:unknown):Promise<{status:number;data:unknown}>{
  const bodyJson=canonicalJson(body);
  if(Buffer.byteLength(bodyJson,"utf8")>256*1024)throw Error("fleet target envelope too large");
  const response=await fetch(endpoint+pathname,{method:"POST",redirect:"error",
    headers:{"content-type":"application/json","accept":"application/json"},
    body:bodyJson,signal:AbortSignal.timeout(20000)});
  if(response.status===204)return{status:204,data:null};
  const bytes=Buffer.from(await response.arrayBuffer());
  if(bytes.length>262144)throw Error("fleet server reply exceeds bounded size");
  return{status:response.status,data:JSON.parse(bytes.toString("utf8"))};
}
export async function runV3MacFleetOnce(config:{
  ownerPublicKeyPem:string;ownerFingerprint:string;
  windowsTailnetNodeHash:string;
}):Promise<"idle"|"fleet-approval"|"fleet-receipt-delivered">{
  if(process.platform!=="darwin"||process.arch!=="x64"||
    os.hostname()!=="amirs-MacBook-Pro.local"||
    os.userInfo().username!=="amirsheikhzadeh"||
    process.env["RADLINA_V3_FLEET_SUPERVISOR"]!=="1"||
    process.env["RADLINA_V3_PUBLIC_URL"]){
    throw Error("dedicated physical Mac V3 fleet supervisor is required");
  }
  if(config.ownerFingerprint!==expectedOwnerFingerprint||
    !/^[a-f0-9]{64}$/u.test(config.windowsTailnetNodeHash)||
    await observeWindowsPeer()!==config.windowsTailnetNodeHash){
    throw Error("owner and live Windows Tailnet public identity are not pinned");
  }
  const signer=await ExistingPhysicalMacP03Signer.open();
  const identity=signer.publicIdentity();
  const session=()=>{
    const claim=i01AgentSessionSchema.parse({
      schema:"radlina.v3.i01.device-session/v1",
      deviceId:"macbook-main",nonce:randomUUID(),signedAtMs:Date.now(),
    });
    return{
      deviceId:claim.deviceId,nonce:claim.nonce,signedAtMs:claim.signedAtMs,
      signatureBase64:signer.signCanonical(canonicalJson(claim)),
    };
  };
  const approvalCall=await post("/v3/fleet/consent-claim",{session:session()});
  if(approvalCall.status===200){
    const parsed=approvalCall.data as {schema?:string;prompt?:Record<string,unknown>};
    const prompt=parsed.prompt;
    if(parsed.schema!=="radlina.v3.f01.release-approval-prompt/v1"||
      !prompt||prompt["deviceId"]!=="macbook-main"){
      throw Error("physical Mac fleet approval prompt malformed");
    }
    const requestId=String(prompt["requestId"]);
    const planId=String(prompt["planId"]);
    const operation=String(prompt["operation"]);
    const targetManifestSha256=String(prompt["targetManifestSha256"]);
    const previousManifestSha256=String(prompt["previousManifestSha256"]);
    const expiresAtMs=Number(prompt["expiresAtMs"]);
    if(!allowedCommands.has(operation)||expiresAtMs<=Date.now()||
      !/^[0-9a-f]{64}$/u.test(targetManifestSha256)||
      !/^[0-9a-f]{64}$/u.test(previousManifestSha256)){
      throw Error("physical F01 release permission outside signed bounds");
    }
    const confirmed=await new I01MacPhysicalApprovalDialog().confirm({
      requestId,operationSha256:sha256(canonicalJson(prompt)),
      sourceDeviceId:"windows-main",targetDeviceId:"macbook-main",
      subject:"Exact F01 V3 physical release",
      capability:operation,inputSha256:targetManifestSha256,
      resourceDescription:"Next: "+targetManifestSha256+" Previous: "+previousManifestSha256,
      issuedAtMs:Date.now(),expiresAtMs,
    });
    if(!confirmed)return"idle";
    const now=Date.now();
    const releaseConsent={
      schema:"radlina.v3.f01.recipient-release-consent/v1" as const,
      requestId,deviceId:"macbook-main" as const,planId,
      operation:operation as "fleet.preflight"|"fleet.activate"|"fleet.verify"|"fleet.rollback",
      targetManifestSha256,previousManifestSha256,localUserApproved:true as const,
      nonce:randomUUID(),issuedAtMs:now,expiresAtMs:Math.min(expiresAtMs,now+60000),
    };
    const deliveredConsent=await post("/v3/fleet/consent-decision",{
      session:session(),
      signed:{
        approval:releaseConsent,
        deviceSignatureBase64:signer.signCanonical(canonicalJson(releaseConsent)),
      },
    });
    if(deliveredConsent.status!==202)
      throw Error("physical F01 target signed approval not accepted");
    return"fleet-approval";
  }
  if(approvalCall.status!==204)throw Error("physical F01 approval query failed");
  const received=await post("/v3/fleet/claim",{session:session()});
  if(received.status===204)return"idle";
  if(received.status!==200)throw Error("Mac F01 target polling failed closed: HTTP_"+received.status);
  const leased=fleetLeaseSchema.parse(received.data);
  const command=leased.command.command;
  if(command.deviceId!=="macbook-main"||!allowedCommands.has(command.action))
    throw Error("fleet target or operation not assigned to physical Mac");
  const dir=path.join(os.homedir(),".local","share","radlina","v3-beta","macbook-main-agent","fleet");
  await mkdir(dir,{recursive:true,mode:0o700});
  const journal=new F01LocalReplayStore(path.join(dir,"physical-release-replay.sqlite3"));
  const audit=new F01PhysicalLocalAuditChain(path.join(dir,"physical-release-audit.sqlite3"),"macbook-main");
  const host=new MacV3NativeReleaseHost();
  const approval={
    check:async(op:typeof command)=>{
      if(op.deviceId!=="macbook-main")return false;
      const hash=sha256(canonicalJson(op));
      return await new I01MacPhysicalApprovalDialog().confirm({
        requestId:op.operationId,operationSha256:hash,
        sourceDeviceId:"windows-main",targetDeviceId:"macbook-main",
        subject:"Owner-authorized V3 release operation",
        capability:op.action,
        inputSha256:op.targetManifestSha256,
        resourceDescription:"Target "+op.targetManifestSha256+
          " / Previous "+op.previousManifestSha256,
        issuedAtMs:op.issuedAtMs,expiresAtMs:op.expiresAtMs,
      });
    },
  };
  const agent=new F01PhysicalRecipientAgent(host,{
    deviceId:"macbook-main",agentInstanceId:identity.agentInstanceId,
    publicKeyFingerprint:identity.publicKeyFingerprint,
    liveP03KeyAndHeartbeat:async()=>{
      return await observeWindowsPeer()===config.windowsTailnetNodeHash;
    },
    signReceipt:async(message:string)=>signer.signCanonical(message),
  },config.ownerPublicKeyPem,config.ownerFingerprint,approval,audit,journal);
  try{
    const reply=await agent.execute(leased.command);
    const acknowledgement=await post("/v3/fleet/report",{
      session:session(),leaseId:leased.leaseId,response:reply,
    });
    if(acknowledgement.status!==202){
      throw Error("Mac F01 physical execution may have completed; receipt delivery unknown");
    }
    return"fleet-receipt-delivered";
  }finally{audit.close();journal.close();}
}
