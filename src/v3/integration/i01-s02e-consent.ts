/**
 * Existing S02E cross-device consent authority bound to real P03 key registry.
 * No caller controls approvalPublicKeyPem or the independently trusted devices.
 */
import { SqliteCrossDeviceConsentAuthority } from "../security/device-consent.js";
import { buildApprovalMessage, consentDecisionSchema,
  type ConsentDeviceTrustPort,type SignedConsentDecision,
  type VerifiedDevicePrincipal } from "../security/consent-contracts.js";
import type { SqliteDeviceRegistry } from "../device/registry.js";
import type { I01PhysicalDeviceSession,I01SignedPull } from "./i01-sealed-outbox.js";
import type { VerifiedWorkflowOriginPort } from "../security/consent-dispatch.js";
import type { I01TrustedDeviceResolver } from "./i01-secured-dispatch.js";

export class I01P03ConsentTrust implements ConsentDeviceTrustPort {
  constructor(private readonly registry:SqliteDeviceRegistry){}
  get(deviceId:string){
    if(deviceId!=="macbook-main"&&deviceId!=="windows-main")return undefined;
    const record=this.registry.get(deviceId);
    if(record?.trustState!=="trusted")return undefined;
    const pinned=this.registry.db.prepare(
      "SELECT device_public_key_pem,identity_json FROM v3_p03_trusted_identities WHERE device_id=?"
    ).get(deviceId) as {device_public_key_pem:string;identity_json:string}|undefined;
    if(!pinned)return undefined;
    const id=JSON.parse(pinned.identity_json) as {publicKeyFingerprint:string};
    return{
      deviceId,trustState:"trusted" as const,
      approvalPublicKeyPem:pinned.device_public_key_pem,
      approvalKeyFingerprint:id.publicKeyFingerprint,
    };
  }
}
export class I01S02EConsentController {
  constructor(
    readonly authority:SqliteCrossDeviceConsentAuthority,
    readonly sessions:I01PhysicalDeviceSession,
    readonly trusted:I01TrustedDeviceResolver,
    readonly origins:VerifiedWorkflowOriginPort,
  ){
    // A target's approval applies to exactly the pinned OAuth workflow,
    // not a different operation with similar device/capability/input data.
    this.authority.db.exec(
      "CREATE TABLE IF NOT EXISTS v3_i01_consent_workflow_bindings("+
      "request_id TEXT PRIMARY KEY REFERENCES v3_consent_requests(request_id),"+
      "workflow_execution_id TEXT NOT NULL,subject TEXT NOT NULL,"+
      "source_device_id TEXT NOT NULL,target_device_id TEXT NOT NULL,"+
      "capability TEXT NOT NULL,input_sha256 TEXT NOT NULL);"
    );
  }
  async create(input:{
    executionId:string;subject:string;targetDeviceId:string;capability:string;
    resourceKey:string;inputSha256:string;idempotencyKey:string;
  }){
    const source=this.origins.resolve({
      workflowExecutionId:input.executionId,subject:input.subject,
    });
    if(!source?.attested)
      throw Error("S02E requires server-bound OAuth owner/device origin");
    this.trusted.resolve(source.deviceId,"device.health");
    this.trusted.resolve(input.targetDeviceId,"device.health");
    const request=this.authority.request({
      sourceDeviceId:source.deviceId,targetDeviceId:input.targetDeviceId,
      subject:input.subject,capability:input.capability,
      resourceKey:input.resourceKey,inputSha256:input.inputSha256,
      purpose:"exact physical I01 operation",
    },source,input.idempotencyKey);
    this.authority.db.prepare(
      "INSERT OR IGNORE INTO v3_i01_consent_workflow_bindings("+
      "request_id,workflow_execution_id,subject,source_device_id,target_device_id,"+
      "capability,input_sha256) VALUES(?,?,?,?,?,?,?)",
    ).run(request.requestId,input.executionId,input.subject,source.deviceId,
      input.targetDeviceId,input.capability,input.inputSha256);
    this.requireExact(request.requestId,input.executionId,input.subject,source.deviceId,
      input.targetDeviceId,input.capability,input.inputSha256,false);
    return request;
  }
  /** An OAuth owner may consume only a previously bound recipient approval. */
  requireExact(requestId:string,executionId:string,subject:string,sourceId:string,
    targetId:string,capability:string,inputSha256:string,requireApproved=true):void{
    const row=this.authority.db.prepare(
      "SELECT workflow_execution_id,subject,source_device_id,target_device_id,"+
      "capability,input_sha256 FROM v3_i01_consent_workflow_bindings WHERE request_id=?",
    ).get(requestId) as {
      workflow_execution_id:string;subject:string;source_device_id:string;
      target_device_id:string;capability:string;input_sha256:string;
    }|undefined;
    const request=this.authority.getRequest(requestId);
    if(!row||!request||row.workflow_execution_id!==executionId||
      row.subject!==subject||row.source_device_id!==sourceId||
      row.target_device_id!==targetId||row.capability!==capability||
      row.input_sha256!==inputSha256||
      request.subject!==subject||request.sourceDeviceId!==sourceId||
      request.targetDeviceId!==targetId||request.capability!==capability||
      request.inputSha256!==inputSha256||
      (requireApproved&&request.state!=="approved")){
      throw Error("S02E recipient consent not approved for this exact OAuth workflow");
    }
  }
  status(requestId:string,subject:string,executionId?:string){
    if(executionId){
      const bound=this.authority.db.prepare(
        "SELECT workflow_execution_id FROM v3_i01_consent_workflow_bindings WHERE request_id=?",
      ).get(requestId) as {workflow_execution_id:string}|undefined;
      if(bound?.workflow_execution_id!==executionId)
        throw Error("S02E request not owned by this OAuth workflow");
    }
    const request=this.authority.getRequest(requestId);
    if(!request||request.subject!==subject)throw Error("owner scoped consent not found");
    return{
      requestId:request.requestId,state:request.state,
      targetDeviceId:request.targetDeviceId,capability:request.capability,
      requestHash:request.requestHash,
      pendingDecisionUntil:request.requestExpiresAtMs,
    };
  }
  async claimForTarget(session:I01SignedPull){
    await this.sessions.assertPhysicalAgent(session);
    this.trusted.resolve(session.deviceId,"device.health");
    const principal:VerifiedDevicePrincipal={
      subject:"recipient-device",deviceId:session.deviceId,attested:true,
    };
    return this.authority.pendingForTarget(principal)[0]??null;
  }
  async decideFromTarget(session:I01SignedPull,raw:SignedConsentDecision){
    await this.sessions.assertPhysicalAgent(session);
    this.trusted.resolve(session.deviceId,"device.health");
    const decision=consentDecisionSchema.parse(raw);
    const request=this.authority.getRequest(decision.requestId);
    if(!request||request.targetDeviceId!==session.deviceId)
      throw Error("physical S02E consent target mismatch");
    const principal:VerifiedDevicePrincipal={
      deviceId:session.deviceId,subject:request.subject,
      attested:true,localUserApproved:true,
    };
    return this.authority.decide(decision,principal);
  }
}
