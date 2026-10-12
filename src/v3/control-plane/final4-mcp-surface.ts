/**
 * V3 final-four MCP surface, deliberately DISABLED unless real authorized
 * physical ports have been composed and injected by the V3-only bootstrap.
 *
 * It does not permit a caller to self-assert ChatGPT provenance, owner identity,
 * source device identity, review decisions or recipient-local consent.
 */
import { randomUUID } from "node:crypto";
import { McpServer, type AuthInfo } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import type { I01ConsentAndAuditDispatcher } from "../integration/i01-secured-dispatch.js";
import type { V3FleetControlPort } from "../fleet/physical-composition.js";
import type { I01S02EConsentController } from "../integration/i01-s02e-consent.js";
import { canonicalJson, sha256 } from "../../utils/json.js";
import { fleetPlanSchema } from "../fleet/contracts.js";
import type { V3IndependentPhysicalAcceptanceLedger } from "../acceptance/ac01-final-gates.js";
import { workflowNodeSchema } from "../workflow/contracts.js";

export interface V3NativePluginAuthenticator {
  /** Verify OAuth client_id from server-side allowed connector registry. */
  requireNativeV3Client(clientId: string): boolean;
  /** Subject and source device MUST originate from an immutable owner binding. */
  bindOwner(input:{
    auth: AuthInfo;
    workflowExecutionId: string;
    requestedSourceDeviceId?: string;
  }): Promise<{subject: string; sourceDeviceId: string; attested: true}>;
}
export interface V3FinalFourMcpPorts {
  authenticatedPlugin: V3NativePluginAuthenticator;
  execution: I01ConsentAndAuditDispatcher;
  fleet: V3FleetControlPort;
  acceptance: V3IndependentPhysicalAcceptanceLedger;
  s02e: I01S02EConsentController;
}
const WRITE={readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:false};
const READ={readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:false};
function ownerAuth(context: {http?:{authInfo?:AuthInfo}},scope:string,
  ports:V3FinalFourMcpPorts):AuthInfo{
  const auth=context.http?.authInfo;
  if(!auth||!auth.scopes.includes(scope)||!auth.scopes.includes("device:read")||
    !ports.authenticatedPlugin.requireNativeV3Client(auth.clientId)){
    throw new Error("native V3 OAuth client/required owner scope is unavailable");
  }
  return auth;
}
function ok(result:unknown){
  return {
    content:[{type:"text" as const,text:JSON.stringify({result})}],
    structuredContent:{result},
  };
}
function denied(error:unknown){
  // Client receives an opaque rejection; server audit owns all internals.
  void error;
  return {
    isError:true,
    content:[{type:"text" as const,text:JSON.stringify({error:"V3_POLICY_OR_ACCEPTANCE_DENIED"})}],
  };
}
export function registerV3FinalFourTools(server:McpServer,ports:V3FinalFourMcpPorts):void{
  server.registerTool("v3_consent_request",{
    description:"Request bounded once-only, recipient-signed S02E consent for a specified V3 device, capability and exact input.",
    inputSchema:z.object({
      workflowExecutionId:z.string().uuid(),
      targetDeviceId:z.enum(["macbook-main","windows-main"]),
      sourceDeviceId:z.enum(["macbook-main","windows-main"]),
      capability:z.string().regex(/^[a-z][a-z0-9.-]{0,127}$/u),
      input:z.record(z.string(),z.unknown()),
      idempotencyKey:z.string().uuid(),
    }).strict(),
    annotations:WRITE,
  },async(input,context)=>{
    try{
      const auth=ownerAuth(context,"device:execute",ports);
      const bound=await ports.authenticatedPlugin.bindOwner({
        auth,workflowExecutionId:input.workflowExecutionId,
        requestedSourceDeviceId:input.sourceDeviceId,
      });
      if(bound.sourceDeviceId!==input.sourceDeviceId||bound.sourceDeviceId===input.targetDeviceId)
        throw Error("cross-device S02E source and target must differ");
      const inputSha256=sha256(canonicalJson(input.input));
      const record=await ports.s02e.create({
        executionId:input.workflowExecutionId,
        subject:bound.subject,targetDeviceId:input.targetDeviceId,
        capability:input.capability,
        resourceKey:"exact-input:"+inputSha256,inputSha256,
        idempotencyKey:input.idempotencyKey,
      });
      return ok({
        requestId:record.requestId,targetDeviceId:record.targetDeviceId,
        state:record.state,expiresAtMs:record.requestExpiresAtMs,
        exactInputSha256:inputSha256,
      });
    }catch(e){return denied(e);}
  });
  server.registerTool("v3_consent_status",{
    description:"Read exact owner S02E recipient-consent decision without exposing device private keys.",
    inputSchema:z.object({requestId:z.string().uuid(),workflowExecutionId:z.string().uuid(),
      sourceDeviceId:z.enum(["macbook-main","windows-main"])}).strict(),
    annotations:READ,
  },async(input,context)=>{
    try{
      const auth=ownerAuth(context,"device:read",ports);
      const owner=await ports.authenticatedPlugin.bindOwner({
        auth,workflowExecutionId:input.workflowExecutionId,
        requestedSourceDeviceId:input.sourceDeviceId,
      });
      return ok(ports.s02e.status(input.requestId,owner.subject));
    }catch(e){return denied(e);}
  });
  server.registerTool("v3_exact_device_execute",{
    description:"Execute a bounded exact-device V3 capability after live P03 trust, owner OAuth, independent recipient-local consent and S03 audit.",
    inputSchema:z.object({
      targetDeviceId:z.enum(["macbook-main","windows-main"]),
      sourceDeviceId:z.enum(["macbook-main","windows-main"]),
      capability:z.string().min(1).max(128),
      input:z.record(z.string(),z.unknown()).default({}),
      idempotencyKey:z.string().uuid(),
      timeoutMs:z.number().int().min(1000).max(120000).default(30000),
    }).strict(),
    annotations:WRITE,
  },async(input,context)=>{
    try{
      const auth=ownerAuth(context,"device:execute",ports);
      const bound=await ports.authenticatedPlugin.bindOwner({
        auth,workflowExecutionId:input.idempotencyKey,
        requestedSourceDeviceId:input.sourceDeviceId,
      });
      if(!bound.attested||bound.sourceDeviceId!==input.sourceDeviceId||bound.sourceDeviceId===input.targetDeviceId)
        throw new Error("exact remote source must be verified and distinct");
      const node=workflowNodeSchema.parse({
        id:"direct",
        capability:input.capability,
        input:input.input,
        dependsOn:[],
        target:{deviceId:input.targetDeviceId},
        maxAttempts:1,
        timeoutMs:input.timeoutMs,
        executionPolicy:{
          failureMode:"fail-workflow",allowDynamicReroute:false,
          unknownOutcome:"manual-resume",
        },
        expectedOutput:{
          contractId:"v3.exact-device-receipt/v1",
          artifactMode:"inline",
          maxBytes:65536,
        },
      });
      const result=await ports.execution.execute({
        workflowExecutionId:input.idempotencyKey,
        subject:bound.subject,node,attempt:1,
      });
      return ok(result);
    }catch(error){return denied(error);}
  });
  server.registerTool("v3_fleet_plan",{
    description:"Create a two-physical-device F01 release plan without activating any release.",
    inputSchema:z.object({
      targetManifestSha256:z.string().regex(/^[0-9a-f]{64}$/u),
      rollbackManifestSha256:z.string().regex(/^[0-9a-f]{64}$/u),
      canaryDeviceId:z.enum(["macbook-main","windows-main"]),
      idempotencyKey:z.string().uuid(),
    }).strict(),
    annotations:WRITE,
  },async(input,context)=>{
    try{
      const auth=ownerAuth(context,"fleet:control",ports);
      const bound=await ports.authenticatedPlugin.bindOwner({
        auth,workflowExecutionId:input.idempotencyKey,
      });
      const plan=fleetPlanSchema.parse({
        planId:randomUUID(),idempotencyKey:input.idempotencyKey,
        ownerSubject:bound.subject,
        targetManifestSha256:input.targetManifestSha256,
        rollbackManifestSha256:input.rollbackManifestSha256,
        targetDeviceIds:["windows-main","macbook-main"],
        canaryDeviceId:input.canaryDeviceId,
        createdAtMs:Date.now(),
      });
      return ok(await ports.fleet.plan(plan));
    }catch(error){return denied(error);}
  });
  server.registerTool("v3_fleet_run",{
    description:"Start an explicitly owner-approved F01 two-device canary/rollback plan with target-local signed consent.",
    inputSchema:z.object({
      planId:z.string().uuid(),
      operationId:z.string().uuid(),
    }).strict(),
    annotations:WRITE,
  },async(input,context)=>{
    try{
      const auth=ownerAuth(context,"fleet:control",ports);
      const bound=await ports.authenticatedPlugin.bindOwner({
        auth,workflowExecutionId:input.operationId,
      });
      return ok(await ports.fleet.run(input.planId,bound.subject));
    }catch(error){return denied(error);}
  });
  server.registerTool("v3_release_acceptance_status",{
    description:"Read four independent P08/I01/F01/AC01 gates. Code and test counts never imply acceptance.",
    inputSchema:z.object({}),
    annotations:READ,
  },async(_input,context)=>{
    try{
      ownerAuth(context,"device:read",ports);
      return ok(ports.acceptance.readiness());
    }catch(error){return denied(error);}
  });
}
