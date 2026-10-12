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
  ){}
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
    return this.authority.request({
      sourceDeviceId:source.deviceId,targetDeviceId:input.targetDeviceId,
      subject:input.subject,capability:input.capability,
      resourceKey:input.resourceKey,inputSha256:input.inputSha256,
      purpose:"exact physical I01 operation",
    },source,input.idempotencyKey);
  }
  status(requestId:string,subject:string){
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
