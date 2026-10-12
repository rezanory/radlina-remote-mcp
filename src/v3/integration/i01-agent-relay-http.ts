/**
 * V3 agent-only HTTPS relay ingress. No shell endpoint; all paths bind to
 * P03 Ed25519 physical device sessions with fresh nonces and Tailnet pins.
 */
import express, { type Express } from "express";
import * as z from "zod/v4";
import { i01SignedDeviceResponseSchema, i01RecipientApprovalSchema } from "./i01-secured-dispatch.js";
import type { I01SqliteTargetLocalConsentMailbox } from "./i01-local-consent-mailbox.js";
import type { I01S02EConsentController } from "./i01-s02e-consent.js";
import type { F01SealedFleetTransport } from "../fleet/f01-sealed-transport.js";
import type { F01SignedReleaseConsentMailbox } from "../fleet/f01-release-consent.js";
import { consentDecisionSchema } from "../security/consent-contracts.js";
import type { I01DurableSealedOutbox } from "./i01-sealed-outbox.js";

export type I01PhysicalRelayPorts = {
  outbox: I01DurableSealedOutbox;
  consent: I01SqliteTargetLocalConsentMailbox;
  s02e: I01S02EConsentController;
  fleet: F01SealedFleetTransport;
  fleetApprovals: F01SignedReleaseConsentMailbox;
};
const physicalSession = z.object({
  deviceId: z.enum(["macbook-main", "windows-main"]),
  nonce: z.string().uuid(),
  signedAtMs: z.number().int().positive(),
  signatureBase64: z.string().min(80).max(200),
}).strict();
const claim = z.object({session:physicalSession}).strict();
const consentReply = z.object({
  session:physicalSession,
  signed:z.object({
    approval:i01RecipientApprovalSchema,
    deviceSignatureBase64:z.string().min(80).max(200),
  }).strict(),
}).strict();
const consentDeny = z.object({
  session:physicalSession,
  requestId:z.string().uuid(),
}).strict();
const s02eDecision = z.object({
  session:physicalSession,
  decision:consentDecisionSchema,
}).strict();
const fleetApproval=z.object({
  session:physicalSession,
  signed:z.object({
    approval:z.object({
      schema:z.literal("radlina.v3.f01.recipient-release-consent/v1"),
      requestId:z.string().uuid(),deviceId:z.enum(["macbook-main","windows-main"]),
      planId:z.string().uuid(),
      operation:z.enum(["fleet.preflight","fleet.activate","fleet.verify","fleet.rollback"]),
      targetManifestSha256:z.string().regex(/^[0-9a-f]{64}$/u),
      previousManifestSha256:z.string().regex(/^[0-9a-f]{64}$/u),
      localUserApproved:z.literal(true),
      nonce:z.string().uuid(),issuedAtMs:z.number().int().positive(),
      expiresAtMs:z.number().int().positive(),
    }).strict(),
    deviceSignatureBase64:z.string().min(80).max(200),
  }).strict(),
}).strict();
const fleetReport=z.object({
  session:physicalSession,
  leaseId:z.string().uuid(),
  response:z.object({
    schema:z.literal("radlina.v3.f01.signed-fleet-reply/v1"),
    operationId:z.string().uuid(),
    deviceId:z.enum(["macbook-main","windows-main"]),
    agentInstanceId:z.string().uuid(),
    payload:z.unknown(),
    deviceSignatureBase64:z.string().min(80).max(200),
  }).strict(),
}).strict();
const report = z.object({
  session:physicalSession,
  leaseId:z.string().uuid(),
  response:i01SignedDeviceResponseSchema,
}).strict();

export function installV3PhysicalAgentRelayRoutes(
  app:Express,
  ports:I01PhysicalRelayPorts,
):void{
  const json=express.json({limit:"256kb",strict:true,type:"application/json"});
  app.post("/v3/agent/claim",json,async(req,res)=>{
    res.setHeader("cache-control","no-store");
    try{
      const request=claim.parse(req.body);
      const work=await ports.outbox.claimNext(request.session);
      if(work===null) {
        res.status(204).end();
        return;
      }
      res.status(200).json({
        schema:"radlina.v3.i01.leased-exact-command/v1",
        leaseId:work.leaseId,
        targetDeviceId:work.targetDeviceId,
        envelope:work.envelope,
      });
    }catch{
      res.status(403).json({error:"physical_agent_signature_required"});
    }
  });
  app.post("/v3/agent/consent-claim",json,async(req,res)=>{
    res.setHeader("cache-control","no-store");
    try{
      const parsed=claim.parse(req.body);
      const prompt=await ports.consent.pollTarget(parsed.session);
      if(!prompt){res.status(204).end();return;}
      res.status(200).json({schema:"radlina.v3.i01.local-approval-request/v1",prompt});
    }catch{
      res.status(403).json({error:"physical_recipient_session_denied"});
    }
  });
  app.post("/v3/agent/consent-submit",json,async(req,res)=>{
    res.setHeader("cache-control","no-store");
    try{
      const parsed=consentReply.parse(req.body);
      await ports.consent.submitTarget(parsed.session,parsed.signed);
      res.status(202).json({accepted:true});
    }catch{
      res.status(403).json({error:"physical_recipient_approval_denied"});
    }
  });
  app.post("/v3/agent/consent-deny",json,async(req,res)=>{
    res.setHeader("cache-control","no-store");
    try{
      const parsed=consentDeny.parse(req.body);
      await ports.consent.denyTarget(parsed.session,parsed.requestId);
      res.status(202).json({accepted:true});
    }catch{
      res.status(403).json({error:"physical_recipient_denial_failed"});
    }
  });
  app.post("/v3/agent/s02e-claim",json,async(req,res)=>{
    res.setHeader("cache-control","no-store");
    try {
      const request=claim.parse(req.body);
      const prompt=await ports.s02e.claimForTarget(request.session);
      if(!prompt){res.status(204).end();return;}
      res.status(200).json({
        schema:"radlina.v3.i01.s02e-owner-scoped-consent-request/v1",
        request:prompt,
      });
    }catch{
      res.status(403).json({error:"physical_s02e_session_denied"});
    }
  });
  app.post("/v3/agent/s02e-decision",json,async(req,res)=>{
    res.setHeader("cache-control","no-store");
    try{
      const parsed=s02eDecision.parse(req.body);
      const accepted=await ports.s02e.decideFromTarget(parsed.session,parsed.decision);
      res.status(202).json({requestId:accepted.request.requestId,state:accepted.request.state});
    }catch{
      res.status(403).json({error:"physical_s02e_decision_denied"});
    }
  });
  app.post("/v3/fleet/consent-claim",json,async(req,res)=>{
    res.setHeader("cache-control","no-store");
    try{
      const parsed=claim.parse(req.body);
      const prompt=await ports.fleetApprovals.poll(parsed.session);
      if(!prompt){res.status(204).end();return;}
      res.status(200).json({
        schema:"radlina.v3.f01.release-approval-prompt/v1",
        prompt,
      });
    }catch{res.status(403).json({error:"physical_fleet_consent_claim_denied"});}
  });
  app.post("/v3/fleet/consent-decision",json,async(req,res)=>{
    res.setHeader("cache-control","no-store");
    try{
      const parsed=fleetApproval.parse(req.body);
      await ports.fleetApprovals.decide(parsed.session,parsed.signed);
      res.status(202).json({accepted:true});
    }catch{res.status(403).json({error:"physical_fleet_consent_decision_denied"});}
  });
  app.post("/v3/fleet/claim",json,async(req,res)=>{
    res.setHeader("cache-control","no-store");
    try{
      const parsed=claim.parse(req.body);
      const operation=await ports.fleet.claim(parsed.session);
      if(!operation){res.status(204).end();return;}
      res.status(200).json({
        schema:"radlina.v3.f01.leased-fleet-command/v1",
        leaseId:operation.leaseId,
        command:operation.command,
      });
    }catch{
      res.status(403).json({error:"physical_fleet_session_denied"});
    }
  });
  app.post("/v3/fleet/report",json,async(req,res)=>{
    res.setHeader("cache-control","no-store");
    try{
      const parsed=fleetReport.parse(req.body);
      await ports.fleet.report(parsed.session,parsed.leaseId,parsed.response);
      res.status(202).json({accepted:true});
    }catch{
      res.status(403).json({error:"physical_fleet_receipt_denied"});
    }
  });
  app.post("/v3/agent/report",json,async(req,res)=>{
    res.setHeader("cache-control","no-store");
    try{
      const request=report.parse(req.body);
      await ports.outbox.deliverSignedResult(
        request.session,
        request.leaseId,
        request.response,
      );
      res.status(202).json({accepted:true});
    }catch{
      res.status(403).json({error:"physical_agent_receipt_denied"});
    }
  });
}
