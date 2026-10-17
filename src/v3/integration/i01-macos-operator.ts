/**
 * I01 physical Mac operations loop, launched as its own per-user LaunchAgent.
 * Outbound HTTPS only. Keychain never exports P03 private keys.
 * A task can run ONLY after independently signed owner command + local Mac UI
 * approval + live pinned Windows peer observation.
 */
import { execFile as execCallback } from "node:child_process";
import { createPublicKey, randomUUID, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import * as z from "zod/v4";
import { canonicalJson, sha256 } from "../../utils/json.js";
import { ExistingPhysicalMacP03Signer } from "../device/macos-p03-signer.js";
import { requireOwnerApprovedMacOperatorPolicy } from "../device/p08-mac-operator-policy.js";
import { I01RecipientExecutionAgent, I01TargetReplayLedger } from "./i01-recipient-agent.js";
import { I01MacPhysicalApprovalDialog, I01PhysicalLocalGrantAndAudit } from "./i01-local-recipient-ports.js";
import { I01SafeNativeTextCapabilities } from "./i01-native-files.js";
import { i01SignedOwnerEnvelopeSchema, i01SignedDeviceResponseSchema } from "./i01-secured-dispatch.js";
import { i01AgentSessionSchema } from "./i01-physical-session.js";
import { buildApprovalMessage } from "../security/consent-contracts.js";

const execFile=promisify(execCallback);
const host="amirs-MacBook-Pro.local";
const endpoint="https://v3-mcp.radlina.com";
const ownerPin="6259d21211f73fc9d2d7cc0174d9bfdc36424cd456878671ab5683468ca0fe93";
const macKey="f2c2e93ff120fbc5122cbb6b5a0b461a072f54bd8d226368c858fd0bd17037ea";
const leaseSchema=z.object({
  schema:z.literal("radlina.v3.i01.leased-exact-command/v1"),
  leaseId:z.string().uuid(),
  targetDeviceId:z.literal("macbook-main"),
  envelope:i01SignedOwnerEnvelopeSchema,
}).strict();
const consentRequestSchema=z.object({
  schema:z.literal("radlina.v3.i01.local-approval-request/v1"),
  prompt:z.object({
    requestId:z.string().uuid(),
    operationSha256:z.string().regex(/^[0-9a-f]{64}$/u),
    sourceDeviceId:z.literal("windows-main"),
    targetDeviceId:z.literal("macbook-main"),
    subject:z.string().min(1).max(200),
    capability:z.string().min(1).max(128),
    inputSha256:z.string().regex(/^[0-9a-f]{64}$/u),
    resourceDescription:z.string().min(1).max(200),
    issuedAtMs:z.number().int().positive(),
    expiresAtMs:z.number().int().positive(),
  }).strict(),
}).strict();

async function liveWindowsTailnet():Promise<string|undefined>{
  const paths=["/usr/local/bin/tailscale","/Applications/Tailscale.app/Contents/MacOS/Tailscale"];
  for(const binary of paths){
    try{
      const {stdout}=await execFile(binary,["status","--json"],{timeout:12000,maxBuffer:4*1024*1024});
      const s=JSON.parse(stdout) as {
        BackendState?:string;CurrentTailnet?:{Name?:string};
        Peer?:Record<string,{ID?:string;OS?:string;Online?:boolean;DNSName?:string}>;
      };
      if(s.BackendState!=="Running"||s.CurrentTailnet?.Name!=="rezanory.github")continue;
      const peers=Object.values(s.Peer??{}).filter(p=>
        p.OS==="windows"&&p.Online===true&&
        p.DNSName?.replace(/\.$/u,"").toLowerCase()==="laptop-13qineif.taile17c9e.ts.net");
      if(peers.length===1&&peers[0]?.ID)return sha256(peers[0].ID);
    }catch{/* Try alternate existing Tailscale binary; do not reconfigure VPN. */}
  }
  return undefined;
}
async function boundedPost(url:string,body:unknown):Promise<{status:number;json?:unknown}> {
  const payload=canonicalJson(body);
  if(Buffer.byteLength(payload,"utf8")>128*1024)throw Error("bounded physical envelope exceeded");
  const response=await fetch(url,{
    method:"POST",headers:{"content-type":"application/json","accept":"application/json"},
    body:payload,redirect:"error",signal:AbortSignal.timeout(20000),
  });
  if(response.status===204)return{status:204};
  const bytes=Buffer.from(await response.arrayBuffer());
  if(bytes.length>128*1024)throw Error("oversized authenticated relay response");
  return{status:response.status,json:JSON.parse(bytes.toString("utf8"))};
}
async function requirePolicy(file:string) {
  const bytes=await readFile(file);
  if(bytes.length>8192)throw Error("owner signed Mac operator policy size limit");
  return requireOwnerApprovedMacOperatorPolicy(JSON.parse(bytes.toString("utf8")));
}
function signedSession(signer:ExistingPhysicalMacP03Signer) {
  const payload=i01AgentSessionSchema.parse({
    schema:"radlina.v3.i01.device-session/v1",
    deviceId:"macbook-main",nonce:randomUUID(),signedAtMs:Date.now(),
  });
  return {
    deviceId:payload.deviceId,nonce:payload.nonce,signedAtMs:payload.signedAtMs,
    signatureBase64:signer.signCanonical(canonicalJson(payload)),
  };
}
async function lastAcknowledgedMacHeartbeat(state:string,publicKeyPem:string,
  agentInstanceId:string):Promise<boolean>{
  try{
    const bytes=await readFile(path.join(state,"heartbeat-latest-ack.json"));
    if(bytes.length>8192)return false;
    const record=JSON.parse(bytes.toString("utf8")) as Record<string,unknown>;
    if(record["schema"]!=="radlina.v3.p08.durable-heartbeat-ack/v1"||
      !record["envelope"]||typeof record["envelope"]!=="object"||
      !record["gatewayReceipt"]||typeof record["gatewayReceipt"]!=="object")return false;
    const envelope=record["envelope"] as Record<string,unknown>;
    const receipt=record["gatewayReceipt"] as Record<string,unknown>;
    if(envelope["schema"]!=="radlina.v3.p03.heartbeat-evidence/v1"||
      !envelope["heartbeat"]||typeof envelope["heartbeat"]!=="object")return false;
    const heartbeat=envelope["heartbeat"] as Record<string,unknown>;
    const timestamp=heartbeat["signedAtMs"];
    const proofBase64=envelope["deviceSignatureBase64"];
    if(heartbeat["schema"]!=="radlina.v3.p03.signed-heartbeat/v1"||
      heartbeat["deviceId"]!=="macbook-main"||
      heartbeat["agentInstanceId"]!==agentInstanceId||
      heartbeat["agentVersion"]!=="3.0.0-alpha.1"||
      heartbeat["health"]!=="healthy"||heartbeat["status"]!=="online"||
      JSON.stringify(heartbeat["capabilities"])!=='["device.health"]'||
      typeof timestamp!=="number"||!Number.isSafeInteger(timestamp)||
      Date.now()<timestamp||Date.now()-timestamp>120000||
      receipt["acceptance"]!=="V3_P08_REAL_MAC_SIGNED_HEARTBEAT_ACCEPTED"||
      receipt["deviceId"]!=="macbook-main"||receipt["trustState"]!=="trusted"||
      receipt["crossDeviceExecutionEnabled"]!==false||
      typeof proofBase64!=="string")return false;
    const sig=Buffer.from(proofBase64,"base64");
    return sig.length===64&&sig.toString("base64")===proofBase64&&
      verify(null,Buffer.from(canonicalJson(heartbeat)),createPublicKey(publicKeyPem),sig);
  }catch{return false;}
}
export async function runPhysicalMacOperatorOnce(policyFile:string):Promise<{
  status:"consent"|"command"|"idle";
  executionEnabled:boolean;
}>{
  if(process.platform!=="darwin"||process.arch!=="x64"||
    os.hostname()!==host||process.argv.length>3){
    throw Error("only the enrolled physical Mac V3 user agent can run");
  }
  const policy=await requirePolicy(policyFile);
  if(await liveWindowsTailnet()!==policy.windowsTailnetNodeHash) {
    throw Error("trusted Windows owner device is not physically visible on Tailnet");
  }
  const agentState=path.join(os.homedir(),".local","share","radlina","v3-beta","macbook-main-agent");
  const signer=await ExistingPhysicalMacP03Signer.open();
  const identity=signer.publicIdentity();
  if(identity.publicKeyFingerprint!==macKey)throw Error("Mac enrolled Keychain key changed");
  if(!await lastAcknowledgedMacHeartbeat(agentState,identity.publicKeyPem,identity.agentInstanceId)) {
    throw Error("macOS P03 signed heartbeat evidence not freshly acknowledged or verifiable");
  }
  const signedHeartbeat={
    schema:"radlina.v3.p03.signed-heartbeat/v1",
    deviceId:"macbook-main",
    agentInstanceId:identity.agentInstanceId,
    signedAtMs:Date.now(),nonce:randomUUID(),
    agentVersion:"3.0.0-alpha.1",
    status:"online",health:"healthy",
    capabilities:policy.allowedCapabilities,
  };
  const verifiedHeartbeat=await boundedPost(endpoint+"/v3/agent/heartbeat",{
    schema:"radlina.v3.p03.heartbeat-evidence/v1",
    heartbeat:signedHeartbeat,
    deviceSignatureBase64:signer.signCanonical(canonicalJson(signedHeartbeat)),
  });
  if(verifiedHeartbeat.status!==200){
    throw Error("signed physical Mac execution capabilities not accepted by P03 gateway");
  }
  const journalDir=path.join(agentState,"operator");
  const grants=new I01PhysicalLocalGrantAndAudit(
    path.join(journalDir,"local-consent-audit.sqlite3"),"macbook-main");
  const replays=new I01TargetReplayLedger(path.join(journalDir,"local-operations.sqlite3"));
  const native=new I01SafeNativeTextCapabilities("macbook-main",
    path.join(os.homedir(),"Desktop","RadlinaV3"));
  const allowed:ReadonlySet<string>=new Set<string>(policy.allowedCapabilities.filter(x=>native.capabilities.has(x)));
  const agent=new I01RecipientExecutionAgent({
      deviceId:"macbook-main",agentInstanceId:identity.agentInstanceId,
      publicKeyPem:identity.publicKeyPem,
      publicKeyFingerprint:identity.publicKeyFingerprint,
      verifiedSignedHeartbeatFresh:true,installedCapabilities:allowed,
    },policy.ownerPublicKeyPem,ownerPin,{
      physicallyVerifiedController:async()=>
        await liveWindowsTailnet()===policy.windowsTailnetNodeHash,
    },grants,native,{
      signCanonical:async(message)=>signer.signCanonical(message),
    },grants,replays);
  try{
    const pending=replays.nextUndelivered();
    if(pending){
      const recovered=await boundedPost(endpoint+"/v3/agent/report",{
        session:signedSession(signer),leaseId:pending.leaseId,response:pending.reply,
      });
      if(recovered.status!==202)
        throw Error("previous signed Mac receipt remains uncertain; native command not retried");
      replays.markReported(pending.requestId);
      return{status:"command",executionEnabled:false};
    }
    const s02e=await boundedPost(endpoint+"/v3/agent/s02e-claim",{
      session:signedSession(signer),
    });
    if(s02e.status===200){
      const outer=s02e.json as {schema?:string;request?:Record<string,unknown>};
      const prompt=outer.request;
      if(outer.schema!=="radlina.v3.i01.s02e-owner-scoped-consent-request/v1"||
        !prompt||prompt["targetDeviceId"]!=="macbook-main"||
        prompt["sourceDeviceId"]!=="windows-main"){
        throw Error("signed S02E consent request does not bind to Mac");
      }
      const localPrompt={
        requestId:String(prompt["requestId"]),
        operationSha256:String(prompt["requestHash"]),
        sourceDeviceId:"windows-main" as const,
        targetDeviceId:"macbook-main" as const,
        subject:String(prompt["subject"]),
        capability:String(prompt["capability"]),
        inputSha256:String(prompt["inputSha256"]),
        resourceDescription:String(prompt["resourceKey"]),
        issuedAtMs:Number(prompt["requestedAtMs"]),
        expiresAtMs:Number(prompt["requestExpiresAtMs"]),
      };
      const confirmed=await new I01MacPhysicalApprovalDialog().confirm(localPrompt);
      const issuedAtMs=Date.now();
      const duration="once" as const;
      const validUntilMs=confirmed
        ?Math.min(issuedAtMs+10*60*1000,Number(prompt["requestExpiresAtMs"])+9*60*1000)
        :null;
      const unsigned:Parameters<typeof buildApprovalMessage>[1]={
        requestId:String(prompt["requestId"]),
        decision:(confirmed?"approve":"deny"),
        duration,validUntilMs,signedAtMs:issuedAtMs,nonce:randomUUID(),
      };
      const signedMessage=buildApprovalMessage(prompt as Parameters<typeof buildApprovalMessage>[0],unsigned);
      const decision={
        ...unsigned,signatureBase64:signer.signCanonical(canonicalJson(signedMessage)),
      };
      const received=await boundedPost(endpoint+"/v3/agent/s02e-decision",{
        session:signedSession(signer),decision,
      });
      if(received.status!==202)throw Error("physical S02E grant decision not accepted");
      return{status:"consent",executionEnabled:false};
    }
    if(s02e.status!==204)throw Error("physical S02E consent query HTTP_"+s02e.status);
    const consent=await boundedPost(endpoint+"/v3/agent/consent-claim",{
      session:signedSession(signer),
    });
    if(consent.status===200){
      const {prompt}=consentRequestSchema.parse(consent.json);
      const confirmed=await new I01MacPhysicalApprovalDialog().confirm(prompt);
      if(!confirmed){
        const denied=await boundedPost(endpoint+"/v3/agent/consent-deny",{
          session:signedSession(signer),requestId:prompt.requestId,
        });
        if(denied.status!==202)throw Error("recipient denial not durably acknowledged");
        return{status:"consent",executionEnabled:false};
      }
      const issuedAtMs=Date.now();
      const approval={
        schema:"radlina.v3.i01.recipient-approval/v1" as const,
        operationSha256:prompt.operationSha256,
        sourceDeviceId:prompt.sourceDeviceId,
        targetDeviceId:prompt.targetDeviceId,
        subject:prompt.subject,localUserApproved:true as const,
        nonce:randomUUID(),issuedAtMs,
        expiresAtMs:Math.min(prompt.expiresAtMs,issuedAtMs+60000),
      };
      const signed={approval,deviceSignatureBase64:signer.signCanonical(canonicalJson(approval))};
      grants.record({approval:signed,request:prompt});
      const acknowledged=await boundedPost(endpoint+"/v3/agent/consent-submit",{
        session:signedSession(signer),signed,
      });
      if(acknowledged.status!==202) {
        throw Error("local consent signed but target receipt delivery outcome uncertain");
      }
      return{status:"consent",executionEnabled:true};
    }
    if(consent.status!==204)throw Error("recipient consent inbox returned HTTP_"+consent.status);

    const polled=await boundedPost(endpoint+"/v3/agent/claim",{
      session:signedSession(signer),
    });
    if(polled.status===204)return{status:"idle",executionEnabled:false};
    if(polled.status!==200)throw Error("physical operation poll HTTP_"+polled.status);
    const leased=leaseSchema.parse(polled.json);
    if(!allowed.has(leased.envelope.operation.capability)) {
      throw Error("physical target did not install requested capability");
    }
    replays.recordLease(leased.envelope.operation.requestId,leased.leaseId);
    const response=i01SignedDeviceResponseSchema.parse(await agent.receive(leased.envelope));
    const delivered=await boundedPost(endpoint+"/v3/agent/report",{
      session:signedSession(signer),
      leaseId:leased.leaseId,response,
    });
    if(delivered.status!==202)throw Error("physical operation receipt delivery uncertain");
    replays.markReported(response.requestId);
    return{status:"command",executionEnabled:true};
  }finally{
    grants.close();
    replays.close();
  }
}
