/**
 * Exact native ChatGPT OAuth owner binding and physical P03 source records.
 * A caller-selected source is accepted ONLY when the independently approved
 * owner policy pins it and its physical P03 identity is freshly verified.
 */
import { readFileSync, mkdirSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import * as z from "zod/v4";
import type { AuthInfo } from "@modelcontextprotocol/server";
import { sha256 } from "../../utils/json.js";
import { ed25519PublicKeyFingerprint } from "../device/owner-pinned-enrollment.js";
import type { V3MacOperatorPolicy } from "../device/p08-mac-operator-policy.js";
import type { SqliteDeviceRegistry } from "../device/registry.js";
import type { VerifiedDevicePrincipal } from "../security/consent-contracts.js";
import type { VerifiedWorkflowOriginPort } from "../security/consent-dispatch.js";
import type { V3NativePluginAuthenticator } from "../control-plane/final4-mcp-surface.js";
import type { I01TrustedDeviceResolver, I01OwnerScopeAuthority } from "./i01-secured-dispatch.js";
import type { ObservedP03Peer } from "./i01-physical-session.js";

const sha=z.string().regex(/^[a-f0-9]{64}$/u);
const deviceId=z.enum(["windows-main","macbook-main"]);
const ownerPolicySchema=z.object({
  schema:z.literal("radlina.v3.native-chatgpt-owner-binding/v1"),
  authorizedClientIds:z.array(z.string().min(12).max(200)).min(1).max(10),
  ownerSubject:z.string().min(1).max(200),
  ownerKeyFingerprint:sha,
  ownerPublicKeyPem:z.string().includes("BEGIN PUBLIC KEY").max(4096),
  windowsDeviceKeyFingerprint:sha,
  macDeviceKeyFingerprint:sha,
  authorizedSourceDeviceIds:z.array(deviceId).min(1).max(2),
  allowedCapabilities:z.array(z.string().regex(/^[a-z][a-z0-9.-]{0,127}$/u)).min(1).max(100),
  ownerApprovedAt:z.string().datetime({offset:true}),
}).strict();
type OwnerPolicy=z.infer<typeof ownerPolicySchema>;

export class V3OwnerBindingDenied extends Error {
  constructor(msg:string){super(msg);this.name="V3OwnerBindingDenied";}
}
/** Signed heartbeat certifies liveness; signed owner capability policy certifies scope. */
export class V3PhysicalP03Reader implements I01TrustedDeviceResolver {
  constructor(
    private readonly registry:SqliteDeviceRegistry,
    private readonly peer:ObservedP03Peer,
    private readonly windowsFingerprint:string,
    private readonly macFingerprint:string,
    private readonly macPolicy?:V3MacOperatorPolicy,
    private readonly windowsCapabilities:ReadonlySet<string>=new Set([
      "device.health","filesystem.read","filesystem.write",
    ]),
    private readonly now:()=>number=()=>Date.now(),
  ){}
  resolve(deviceId:string,capability:string){
    const id=deviceIdSchema(deviceId);
    const record=this.registry.require(id);
    const age=this.now()-Date.parse(record.lastSeen);
    if(record.trustState!=="trusted"||record.status!=="online"||
      !Number.isFinite(age)||age<0||age>120000||
      record.health==="unhealthy"||record.health==="unknown"||
      !record.capabilities.includes("device.health")){
      throw new V3OwnerBindingDenied("physical device P03 signed heartbeat or trust not fresh");
    }
    const row=this.registry.db.prepare(
      "SELECT identity_json,device_public_key_pem,tailscale_node_hash "+
      "FROM v3_p03_trusted_identities WHERE device_id=?"
    ).get(id) as {
      identity_json:string;device_public_key_pem:string;tailscale_node_hash:string;
    }|undefined;
    if(!row)throw new V3OwnerBindingDenied("signed device enrollment missing");
    const identity=z.object({
      deviceId:z.literal(id),
      agentInstanceId:z.string().uuid(),
      publicKeyFingerprint:sha,
    }).passthrough().parse(JSON.parse(row.identity_json));
    const expected=id==="macbook-main"?this.macFingerprint:this.windowsFingerprint;
    if(identity.publicKeyFingerprint!==expected||
      ed25519PublicKeyFingerprint(row.device_public_key_pem)!==expected||
      row.tailscale_node_hash!==this.peer.observeExactTailnetNodeHash(id)){
      throw new V3OwnerBindingDenied("physical key or live independently observed Tailnet peer changed");
    }
    if(capability!=="device.health"){
      if(id==="macbook-main"){
        if(!this.macPolicy ||
          Date.parse(this.macPolicy.expiresAt)<=this.now() ||
          !this.macPolicy.allowedCapabilities.includes(
            capability as typeof this.macPolicy.allowedCapabilities[number]
          )){
          throw new V3OwnerBindingDenied("signed owner Mac capability policy absent or expired");
        }
      }else if(!this.windowsCapabilities.has(capability)){
        throw new V3OwnerBindingDenied("Windows native capability is not installed or allowlisted");
      }
    }
    return {
      deviceId:id,
      agentInstanceId:identity.agentInstanceId,
      devicePublicKeyPem:row.device_public_key_pem,
      devicePublicKeyFingerprint:identity.publicKeyFingerprint,
      heartbeatFresh:true as const,
    };
  }
}
function deviceIdSchema(raw:string):"windows-main"|"macbook-main"{
  return deviceId.parse(raw);
}

/** Authenticated workflow origins survive server restart without caller overrides. */
export class PinnedNativeV3OwnerBinder
  implements V3NativePluginAuthenticator,I01OwnerScopeAuthority,VerifiedWorkflowOriginPort {
  private readonly policy:OwnerPolicy;
  private readonly db:DatabaseSync;
  constructor(
    file:string,
    private readonly devices:V3PhysicalP03Reader,
    private readonly allowListFingerprint:string,
    ownershipDatabase:string,
  ){
    if(!path.isAbsolute(file)||file.toLowerCase().includes("\\v2\\")||
      !path.isAbsolute(ownershipDatabase)||ownershipDatabase.toLowerCase().includes("\\v2\\")){
      throw new V3OwnerBindingDenied("independent absolute V3 owner/OAuth binding storage required");
    }
    const bytes=readFileSync(file);
    if(bytes.byteLength>16384)throw new V3OwnerBindingDenied("bounded native client owner pin required");
    this.policy=ownerPolicySchema.parse(JSON.parse(bytes.toString("utf8")));
    if(sha256(bytes)!==allowListFingerprint ||
      ed25519PublicKeyFingerprint(this.policy.ownerPublicKeyPem)!==
        this.policy.ownerKeyFingerprint){
      throw new V3OwnerBindingDenied("owner policy hash/key does not match independent pin");
    }
    if(new Set(this.policy.authorizedClientIds).size!==this.policy.authorizedClientIds.length ||
      new Set(this.policy.authorizedSourceDeviceIds).size!==this.policy.authorizedSourceDeviceIds.length){
      throw new V3OwnerBindingDenied("owner policy contains duplicate client/source identities");
    }
    mkdirSync(path.dirname(ownershipDatabase),{recursive:true});
    this.db=new DatabaseSync(ownershipDatabase,{enableForeignKeyConstraints:true});
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS v3_native_workflow_origins("+
      "workflow_execution_id TEXT PRIMARY KEY,subject TEXT NOT NULL,"+
      "client_id TEXT NOT NULL,source_device_id TEXT NOT NULL, bound_at_ms INTEGER NOT NULL);"
    );
  }
  isAuthorizedOwnerSubject(subject:string):boolean {
    return subject===this.policy.ownerSubject;
  }
  requireNativeV3Client(clientId:string):boolean{
    return this.policy.authorizedClientIds.includes(clientId);
  }
  async bindOwner(input:{
    auth:AuthInfo;workflowExecutionId:string;requestedSourceDeviceId?:string;
  }):Promise<{subject:string;sourceDeviceId:string;attested:true}>{
    const {auth}=input;
    const sub=auth.extra?.["sub"];
    if(!this.requireNativeV3Client(auth.clientId)||
      sub!==this.policy.ownerSubject||!auth.scopes.includes("device:read")||
      !z.string().uuid().safeParse(input.workflowExecutionId).success){
      throw new V3OwnerBindingDenied("OAuth subject, verified client or operation ID not pinned");
    }
    const source=deviceIdSchema(input.requestedSourceDeviceId??"windows-main");
    if(!this.policy.authorizedSourceDeviceIds.includes(source))
      throw new V3OwnerBindingDenied("selected physical source not independently owner-approved");
    this.devices.resolve(source,"device.health");
    const existing=this.db.prepare(
      "SELECT subject,client_id,source_device_id FROM v3_native_workflow_origins "+
      "WHERE workflow_execution_id=?"
    ).get(input.workflowExecutionId) as {
      subject:string;client_id:string;source_device_id:string;
    }|undefined;
    if(existing && (existing.subject!==this.policy.ownerSubject||
      existing.client_id!==auth.clientId||existing.source_device_id!==source)){
      throw new V3OwnerBindingDenied("immutable physical workflow source conflict");
    }
    if(!existing){
      this.db.prepare(
        "INSERT INTO v3_native_workflow_origins(workflow_execution_id,subject,client_id,"+
        "source_device_id,bound_at_ms) VALUES(?,?,?,?,?)"
      ).run(input.workflowExecutionId,this.policy.ownerSubject,auth.clientId,source,Date.now());
    }
    return{subject:this.policy.ownerSubject,sourceDeviceId:source,attested:true};
  }
  resolve(input:{workflowExecutionId:string;subject:string}):VerifiedDevicePrincipal|undefined {
    const row=this.db.prepare(
      "SELECT subject,source_device_id FROM v3_native_workflow_origins "+
      "WHERE workflow_execution_id=?"
    ).get(input.workflowExecutionId) as {subject:string;source_device_id:string}|undefined;
    if(!row||row.subject!==input.subject ||
      !this.policy.authorizedSourceDeviceIds.includes(deviceIdSchema(row.source_device_id)))return undefined;
    try {this.devices.resolve(row.source_device_id,"device.health");}
    catch {return undefined;}
    return {subject:row.subject,deviceId:row.source_device_id,attested:true};
  }
  async authorize(origin:VerifiedDevicePrincipal,capability:string,targetId:string):Promise<void>{
    if(!origin.attested||origin.subject!==this.policy.ownerSubject||
      !this.policy.authorizedSourceDeviceIds.includes(deviceIdSchema(origin.deviceId))||
      targetId===origin.deviceId||!this.policy.allowedCapabilities.includes(capability)){
      throw new V3OwnerBindingDenied("owner-approved physical source/target or capability missing");
    }
    this.devices.resolve(origin.deviceId,"device.health");
    this.devices.resolve(targetId,capability);
  }
  close():void{this.db.close();}
}
