/**
 * Exact, opt-in V3 final-four composition. No synthetic physical ports.
 * This module is inert until a protected owner-reviewed config and independent
 * S03 writer credentials are explicitly injected into the V3-only process.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import * as z from "zod/v4";
import { sha256 } from "../../utils/json.js";
import { SqliteDeviceRegistry } from "../device/registry.js";
import { observeLiveMacTailnetPeer } from "../device/mac-heartbeat-ingress.js";
import type { V3MacOperatorPolicy } from "../device/p08-mac-operator-policy.js";
import { I01ActualP03SessionAuthority,I01WindowsDpapiSealer } from "./i01-physical-session.js";
import { V3PhysicalP03Reader,PinnedNativeV3OwnerBinder } from "./i01-owner-bindings.js";
import { I01DurableSealedOutbox } from "./i01-sealed-outbox.js";
import { I01SqliteTargetLocalConsentMailbox } from "./i01-local-consent-mailbox.js";
import { I01S02EConsentController,I01P03ConsentTrust } from "./i01-s02e-consent.js";
import { I01ConsentAndAuditDispatcher,I01DurableDispatchJournal } from "./i01-secured-dispatch.js";
import { V3OwnerProtectedSigningBroker } from "../security/windows-owner-broker.js";
import { SqliteCrossDeviceConsentAuthority } from "../security/device-consent.js";
import { S03ExternalAuditClient } from "../audit/s03-independent-witness.js";
import { HmacDistributedAuditSigner } from "../audit/distributed.js";
import { SqliteFleetStore } from "../fleet/store.js";
import { F01SealedFleetTransport } from "../fleet/f01-sealed-transport.js";
import { F01SignedReleaseConsentMailbox } from "../fleet/f01-release-consent.js";
import { V3PhysicalFleetOrchestrator } from "../fleet/physical-composition.js";
import { V3IndependentPhysicalAcceptanceLedger } from "../acceptance/ac01-final-gates.js";
import type { V3FinalFourMcpPorts } from "../control-plane/final4-mcp-surface.js";
import type { I01PhysicalRelayPorts } from "./i01-agent-relay-http.js";

const digest=z.string().regex(/^[a-f0-9]{64}$/u);
const configSchema=z.object({
  schema:z.literal("radlina.v3.final-four-production-binding/v1"),
  ownerOAuthClientPolicyPath:z.string().min(10).max(4096),
  ownerOAuthClientPolicyHash:digest,
  windowsDeviceFingerprint:digest,
  macDeviceFingerprint:digest,
  macTailnetNodeHash:digest,
  windowsTailnetNodeHash:digest,
  ownerPublicKeyPem:z.string().includes("BEGIN PUBLIC KEY").max(4096),
  independentReviewerPublicKeyPem:z.string().includes("BEGIN PUBLIC KEY").max(4096),
  s03:z.object({
    endpoint:z.literal("https://v3-audit.radlina.com/api/v1/anchor"),
    witnessPublicKeyPem:z.string().includes("BEGIN PUBLIC KEY").max(4096),
    witnessFingerprint:digest,
  }).strict(),
}).strict();
export type V3FinalFourBindingConfig=z.infer<typeof configSchema>;
export class V3PhysicalPortsNotConfigured extends Error{
  constructor(msg:string){super(msg);this.name="V3PhysicalPortsNotConfigured";}
}
function windowsNodeHash():string|undefined {
  if(process.platform!=="win32"||os.hostname().toLowerCase()!=="laptop-13qineif")
    return undefined;
  try{
    const s=JSON.parse(execFileSync("C:\\Program Files\\Tailscale\\tailscale.exe",["status","--json"],{
      encoding:"utf8",timeout:12000,maxBuffer:4*1024*1024,windowsHide:true,
    })) as {
      BackendState?:string;CurrentTailnet?:{Name?:string};Self?:{ID?:string;Online?:boolean};
    };
    return s.BackendState==="Running"&&s.CurrentTailnet?.Name==="rezanory.github"&&
      s.Self?.Online===true&&s.Self.ID?sha256(s.Self.ID):undefined;
  }catch{return undefined;}
}
export type V3PhysicalComposition={
  finalFour:V3FinalFourMcpPorts;
  relay:I01PhysicalRelayPorts;
  close():void;
};
export function createV3FinalFourPhysicalComposition(input:{
  configPath:string;
  configFileSha256:string;
  stateDirectory:string;
  signedMacPolicy?:V3MacOperatorPolicy;
  s03WriterToken:string;
  s03HmacKeyBase64:string;
}):V3PhysicalComposition {
  if(process.platform!=="win32"||os.hostname().toLowerCase()!=="laptop-13qineif"||
    !path.win32.isAbsolute(input.stateDirectory)||
    !path.win32.isAbsolute(input.configPath)||
    !input.stateDirectory.toLowerCase().startsWith("e:\\")||
    input.stateDirectory.toLowerCase().includes("\\v2\\")){
    throw new V3PhysicalPortsNotConfigured("exact physical V3 Windows and E: private state required");
  }
  const raw=readFileSync(input.configPath);
  if(raw.byteLength>32768||sha256(raw)!==input.configFileSha256){
    throw new V3PhysicalPortsNotConfigured("owner-approved immutable V3 binding configuration missing");
  }
  const config=configSchema.parse(JSON.parse(raw.toString("utf8")));
  const hmacKey=Buffer.from(input.s03HmacKeyBase64,"base64");
  if(hmacKey.length<32||input.s03WriterToken.length<32)
    throw new V3PhysicalPortsNotConfigured("independently provisioned S03 secrets required");
  const state=input.stateDirectory;
  const registry=new SqliteDeviceRegistry(path.join(state,"v3-devices.sqlite3"));
  const peer={
    observeExactTailnetNodeHash:(deviceId:"windows-main"|"macbook-main")=>
      deviceId==="macbook-main"?observeLiveMacTailnetPeer():windowsNodeHash(),
  };
  const physical=new V3PhysicalP03Reader(
    registry,peer,config.windowsDeviceFingerprint,config.macDeviceFingerprint,
    input.signedMacPolicy,
  );
  const origins=new PinnedNativeV3OwnerBinder(
    config.ownerOAuthClientPolicyPath,physical,config.ownerOAuthClientPolicyHash,
    path.join(state,"final4","owner-origins.sqlite3"),
  );
  const physicalSession=new I01ActualP03SessionAuthority(
    registry,path.join(state,"final4","p03-sessions.sqlite3"),peer,
  );
  const crypt=new I01WindowsDpapiSealer();
  const consent=new SqliteCrossDeviceConsentAuthority(
    path.join(state,"final4","s02e-consent.sqlite3"),new I01P03ConsentTrust(registry),
  );
  const s02e=new I01S02EConsentController(consent,physicalSession,physical,origins);
  const outbox=new I01DurableSealedOutbox(
    path.join(state,"final4","i01-relay.sqlite3"),crypt,physicalSession,
  );
  const mailbox=new I01SqliteTargetLocalConsentMailbox(
    path.join(state,"final4","target-local-consent.sqlite3"),
    physicalSession,physical,
  );
  const fleetTransport=new F01SealedFleetTransport(
    path.join(state,"final4","fleet-relay.sqlite3"),crypt,physicalSession,
  );
  const fleetApprovals=new F01SignedReleaseConsentMailbox(
    path.join(state,"final4","fleet-recipient-consent.sqlite3"),physicalSession,physical,
  );
  const ownerSigner=new V3OwnerProtectedSigningBroker(
    path.join(state,"final4","owner-signing.sqlite3"),
  );
  const external=new S03ExternalAuditClient(
    config.s03.endpoint,input.s03WriterToken,hmacKey,
    config.s03.witnessPublicKeyPem,config.s03.witnessFingerprint,
  );
  const dispatch=new I01ConsentAndAuditDispatcher(
    new I01DurableDispatchJournal(path.join(state,"final4","i01-intents.sqlite3")),
    physical,origins,origins,consent,mailbox,ownerSigner,outbox,
    new HmacDistributedAuditSigner(hmacKey),external,
  );
  const fleetStore=new SqliteFleetStore(path.join(state,"final4","fleet-plans.sqlite3"));
  const fleet=new V3PhysicalFleetOrchestrator({
    registry,store:fleetStore,
    owner:{
      assertOwner:async(subject)=>{
        if(!subject||!origins.requireNativeV3Client)throw Error("physical fleet owner unbound");
        // Fleet plan ownership is checked independently by native MCP OAuth binder.
        if(subject!==JSON.parse(readFileSync(config.ownerOAuthClientPolicyPath,"utf8")).ownerSubject)
          throw Error("physical V3 owner subject mismatch");
      },
    },
    consent:fleetApprovals,
    recipientLocal:fleetApprovals,
    identities:{
      requireFreshTrusted:(id:string)=>{
        const d=physical.resolve(id,"device.health");
        return {
          deviceId:d.deviceId,agentInstanceId:d.agentInstanceId,
          publicKeyPem:d.devicePublicKeyPem,signedHeartbeatFresh:true as const,
        };
      },
    },
    protectedSigner:ownerSigner,
    physicalTransport:fleetTransport,
    externalAudit:external,
    isolatedStateRoot:path.join(state,"final4"),
  });
  const acceptance=new V3IndependentPhysicalAcceptanceLedger(
    path.join(state,"final4","acceptance.sqlite3"),
    config.ownerPublicKeyPem,config.independentReviewerPublicKeyPem,
  );
  const objects=[
    registry,origins,physicalSession,consent,outbox,mailbox,
    fleetTransport,fleetApprovals,ownerSigner,fleetStore,acceptance,
  ];
  return{
    finalFour:{
      authenticatedPlugin:origins,
      execution:dispatch,
      fleet,
      acceptance,
      s02e,
    },
    relay:{outbox,consent:mailbox,s02e,fleet:fleetTransport,fleetApprovals},
    close:()=>{
      for(const object of [...objects].reverse()){
        try{object.close();}catch{/* Continue closing isolated resources. */}
      }
      hmacKey.fill(0);
    },
  };
}
