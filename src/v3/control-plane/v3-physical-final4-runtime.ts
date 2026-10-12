/**
 * V3-only physical final-four composition. Instantiated only when the
 * independent V3 bootstrap requests it with owner-provided public pins.
 *
 * No generic shell fallback, fabricated signatures, synthetic reviewer,
 * duplicate actions or V2 service/credential modifications.
 */
import { createPublicKey } from "node:crypto";
import { readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { AppConfig } from "../../config/schema.js";
import type { Store } from "../../persistence/store.js";
import type { AuthService } from "../../auth/service.js";
import { unprotectBytes } from "../../auth/dpapi.js";
import { sha256 } from "../../utils/json.js";
import { HmacDistributedAuditSigner } from "../audit/distributed.js";
import { S03IndependentMacAuditAnchor, S03HttpsAuditTransport } from "../audit/s03-remote-anchor.js";
import { V3IndependentPhysicalAcceptanceLedger } from "../acceptance/ac01-final-gates.js";
import { V3ExplicitFleetOwner } from "../fleet/physical-adapters.js";
import { V3PhysicalFleetOrchestrator } from "../fleet/physical-composition.js";
import { SqliteFleetStore } from "../fleet/store.js";
import { F01SealedFleetTransport } from "../fleet/f01-sealed-transport.js";
import { F01SignedReleaseConsentMailbox } from "../fleet/f01-release-consent.js";
import { V3OwnerProtectedSigningBroker } from "../security/windows-owner-broker.js";
import { SqliteCrossDeviceConsentAuthority } from "../security/device-consent.js";
import { I01P03ConsentTrust, I01S02EConsentController } from "../integration/i01-s02e-consent.js";
import { I01ActualP03SessionAuthority, I01WindowsDpapiSealer } from "../integration/i01-physical-session.js";
import { I01DurableSealedOutbox } from "../integration/i01-sealed-outbox.js";
import { I01SqliteTargetLocalConsentMailbox } from "../integration/i01-local-consent-mailbox.js";
import { I01ConsentAndAuditDispatcher, I01DurableDispatchJournal } from "../integration/i01-secured-dispatch.js";
import { V3PhysicalP03Reader, PinnedNativeV3OwnerBinder } from "../integration/i01-owner-bindings.js";
import { V3LiveTailnetNodeObserver } from "../integration/i01-tailnet-observer.js";
import type { V3MacOperatorPolicy } from "../device/p08-mac-operator-policy.js";
import type { SqliteDeviceRegistry } from "../device/registry.js";
import type { V3FinalFourMcpPorts } from "./final4-mcp-surface.js";
import type { I01PhysicalRelayPorts } from "../integration/i01-agent-relay-http.js";

const SHA=/^[0-9a-f]{64}$/u;
export type V3FinalFourFactoryContext={
  registry:SqliteDeviceRegistry;
  store:Store;
  config:AppConfig;
  auth:AuthService;
  stateRoot:string;
};
export type V3ComposedPhysicalFinalFour={
  finalFour:V3FinalFourMcpPorts;
  physicalRelay:I01PhysicalRelayPorts;
  close():Promise<void>;
};
export interface V3FinalFourIndependentPins {
  /** Explicit signed owner capability policy already approved on physical Windows. */
  signedMacOperatorPolicy:V3MacOperatorPolicy;
  nativeClientOwnerBindingFile:string;
  nativeClientOwnerBindingSha256:string;
  /** Separately protected local V3 HMAC key for internal S03 record construction. */
  internalAuditHmacDpapiFile:string;
  /** Independently deployed, Mac-held external witness P03 public identity. */
  externalAuditWitnessPublicKeyFile:string;
  externalAuditWitnessFingerprint:string;
  /** Reviewer public key is controlled by an independent reviewer, not by owner. */
  independentReviewerPublicKeyFile:string;
  independentReviewerFingerprint:string;
}
async function publicKeyFromPinnedFile(file:string,expected:string):Promise<string>{
  if(!path.isAbsolute(file)||!SHA.test(expected)||file.toLowerCase().includes("\\v2\\"))
    throw Error("dedicated V3 external public key pin required");
  const bytes=await readFile(file);
  if(bytes.byteLength>4096)throw Error("public key exceeded allowed input size");
  const pub=bytes.toString("utf8");
  if(sha256(createPublicKey(pub).export({type:"spki",format:"der"}))!==expected)
    throw Error("independently pinned public key mismatch");
  return pub;
}
async function localS03Hmac(file:string):Promise<Buffer>{
  if(process.platform!=="win32"||!path.win32.isAbsolute(file)||
    file.toLowerCase().includes("\\v2\\")){
    throw Error("isolated physical Windows DPAPI HMAC secret required");
  }
  const bytes=await readFile(file);
  if(bytes.byteLength>4096||bytes.byteLength<32)
    throw Error("bounded DPAPI-protected audit secret missing");
  const value=await unprotectBytes(bytes.toString("utf8").trim());
  if(value.byteLength<32||value.byteLength>128){
    value.fill(0);
    throw Error("protected audit HMAC key strength invalid");
  }
  return value;
}
function safeState(root:string,child:string){
  if(!path.win32.isAbsolute(root)||root.toLowerCase().includes("\\v2\\")||
    !root.toLowerCase().includes("v3")) {
    throw Error("isolated Windows V3 state root required");
  }
  return path.win32.join(root,"final4",child);
}
export async function composePhysicalV3FinalFour(
  ctx:V3FinalFourFactoryContext,pins:V3FinalFourIndependentPins,
):Promise<V3ComposedPhysicalFinalFour>{
  if(process.platform!=="win32"||os.hostname().toLowerCase()!=="laptop-13qineif"||
    ctx.config.server.host!=="127.0.0.1"||
    !pins.signedMacOperatorPolicy ||
    !SHA.test(pins.nativeClientOwnerBindingSha256)){
    throw Error("V3 final-four composition requires real local Windows and owner public pins");
  }
  const resources:Array<{close:()=>void|Promise<void>}>=[];
  const track=<T extends{close:()=>void|Promise<void>}>(resource:T):T=>{
    resources.push(resource);return resource;
  };
  try{
    const physical=new V3LiveTailnetNodeObserver();
    const reader=new V3PhysicalP03Reader(
      ctx.registry,physical,
      "fafcea842b3d0142b9cb24ff05455a09da409d44e7d08a483b39bb0596a7f5a0",
      "f2c2e93ff120fbc5122cbb6b5a0b461a072f54bd8d226368c858fd0bd17037ea",
      pins.signedMacOperatorPolicy,
    );
    const owner=track(new PinnedNativeV3OwnerBinder(
      pins.nativeClientOwnerBindingFile,reader,pins.nativeClientOwnerBindingSha256,
      safeState(ctx.stateRoot,"native-chatgpt-owner.sqlite3"),
    ));
    const sessions=track(new I01ActualP03SessionAuthority(
      ctx.registry,safeState(ctx.stateRoot,"p03-sessions.sqlite3"),physical,
    ));
    const crypt=new I01WindowsDpapiSealer();
    const outbox=track(new I01DurableSealedOutbox(
      safeState(ctx.stateRoot,"i01-sealed-outbox.sqlite3"),crypt,sessions,
    ));
    const localConsent=track(new I01SqliteTargetLocalConsentMailbox(
      safeState(ctx.stateRoot,"i01-target-consent.sqlite3"),sessions,reader,
    ));
    const consentAuthority=track(new SqliteCrossDeviceConsentAuthority(
      safeState(ctx.stateRoot,"s02e-consent.sqlite3"),
      new I01P03ConsentTrust(ctx.registry),
    ));
    const s02e=new I01S02EConsentController(consentAuthority,sessions,reader,owner);
    const broker=track(new V3OwnerProtectedSigningBroker(
      safeState(ctx.stateRoot,"owner-signing.sqlite3"),
    ));
    const ownerRecord=await readFile(pins.nativeClientOwnerBindingFile,"utf8");
    if(sha256(ownerRecord)!==pins.nativeClientOwnerBindingSha256)
      throw Error("native ChatGPT owner pin mutated during composition");
    const ownerPublicKeyPem=(JSON.parse(ownerRecord) as{ownerPublicKeyPem?:string})
      .ownerPublicKeyPem;
    if(!ownerPublicKeyPem)throw Error("native owner key identity missing");
    const witness=await publicKeyFromPinnedFile(
      pins.externalAuditWitnessPublicKeyFile,pins.externalAuditWitnessFingerprint,
    );
    const externalAudit=new S03IndependentMacAuditAnchor(
      new S03HttpsAuditTransport("https://v3-audit.radlina.com/v1/anchor"),
      witness,pins.externalAuditWitnessFingerprint,
    );
    const hmac=await localS03Hmac(pins.internalAuditHmacDpapiFile);
    const auditSigner=new HmacDistributedAuditSigner(hmac);
    hmac.fill(0);
    const journal=track(new I01DurableDispatchJournal(
      safeState(ctx.stateRoot,"i01-exact-intents.sqlite3"),
    ));
    const execution=new I01ConsentAndAuditDispatcher(
      journal,reader,owner,owner,consentAuthority,localConsent,
      broker,outbox,auditSigner,externalAudit,
    );
    const fleetOutbox=track(new F01SealedFleetTransport(
      safeState(ctx.stateRoot,"f01-sealed-queue.sqlite3"),crypt,sessions,
    ));
    const fleetConsent=track(new F01SignedReleaseConsentMailbox(
      safeState(ctx.stateRoot,"f01-local-approval.sqlite3"),sessions,reader,
    ));
    const fleetStore=track(new SqliteFleetStore(
      safeState(ctx.stateRoot,"f01-fleet-plans.sqlite3"),
    ));
    const fleet=new V3PhysicalFleetOrchestrator({
      registry:ctx.registry,store:fleetStore,
      owner:new V3ExplicitFleetOwner({
        verifyAuthenticatedOwner:async(subject)=>owner.isAuthorizedOwnerSubject(subject),
      }),
      consent:fleetConsent,
      recipientLocal:fleetConsent,
      identities:{
        requireFreshTrusted:(deviceId:string)=>{
          const record=reader.resolve(deviceId,"device.health");
          return {
            deviceId:record.deviceId,agentInstanceId:record.agentInstanceId,
            publicKeyPem:record.devicePublicKeyPem,
            signedHeartbeatFresh:true as const,
          };
        },
      },
      protectedSigner:broker,
      physicalTransport:fleetOutbox,
      externalAudit,
      isolatedStateRoot:safeState(ctx.stateRoot,"fleet-operations"),
    });
    const reviewer=await publicKeyFromPinnedFile(
      pins.independentReviewerPublicKeyFile,pins.independentReviewerFingerprint,
    );
    const acceptance=track(new V3IndependentPhysicalAcceptanceLedger(
      safeState(ctx.stateRoot,"final-acceptance.sqlite3"),ownerPublicKeyPem,reviewer,
    ));
    return{
      finalFour:{
        authenticatedPlugin:owner,execution,fleet,acceptance,s02e,
      },
      physicalRelay:{
        outbox,consent:localConsent,s02e,
        fleet:fleetOutbox,fleetApprovals:fleetConsent,
      },
      close:async()=>{
        for(const resource of resources.reverse())await resource.close();
      },
    };
  }catch(error){
    for(const resource of resources.reverse()){
      try{await resource.close();}catch{/* Preserve first failure; never initialize partial runtime. */}
    }
    throw error;
  }
}
