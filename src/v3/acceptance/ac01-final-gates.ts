/**
 * AC01 final acceptance ledger. Source only: never declares Production Ready
 * from compiler output, unit tests, local mocks or historical signatures.
 *
 * Each gate requires independent cryptographic owner AND reviewer decisions,
 * traceable input/runtime/execution/output receipts, immutable durable journal
 * and the correct physical devices. No synthetic acceptance fallback exists.
 */
import { createPublicKey, verify } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import * as z from "zod/v4";
import { canonicalJson, sha256 } from "../../utils/json.js";
import { missingV3PhysicalAcceptancePrerequisites } from "./final4-physical-dependencies.js";

export const V3_FINAL_GATES = ["P08", "I01", "F01", "AC01"] as const;
export type V3FinalGateId = typeof V3_FINAL_GATES[number];
const digest = z.string().regex(/^[0-9a-f]{64}$/u);
const device = z.enum(["windows-main","macbook-main"]);
const stringId = z.string().min(1).max(200);
const sourceReceipt = z.object({
  artifactUrl: z.string().url().max(2048),
  artifactSha256: digest,
  signedAt: z.string().datetime({offset:true}),
}).strict();
export const actualGateEvidenceSchema = z.object({
  schema: z.literal("radlina.v3.ac01.physical-gate-acceptance/v1"),
  gate: z.enum(V3_FINAL_GATES),
  ownerSubject: stringId,
  submittedAt: z.string().datetime({offset:true}),
  source: z.array(sourceReceipt).min(2).max(40),
  input: z.object({
    requestSha256: digest,
    requestedOperation: stringId,
    ownerApprovalId: stringId,
  }).strict(),
  runtime: z.object({
    generation: z.literal("v3"),
    v2IsolationObserved: z.literal(true),
    windowsDeviceId: z.literal("windows-main"),
    macDeviceId: z.literal("macbook-main"),
    v3PublicIssuer: z.literal("https://v3-mcp.radlina.com"),
    activeV3ReleaseSha256: digest,
    windowsP03KeyFingerprint: digest,
    macP03KeyFingerprint: digest,
  }).strict(),
  execution: z.object({
    executionId: stringId,
    actualDeviceIds: z.array(device).min(1).max(2),
    authenticatedLiveExecution: z.literal(true),
    source: z.enum(["physical-mac", "physical-windows", "cross-host-v3", "native-chatgpt-v3"]),
    startedAt: z.string().datetime({offset:true}),
    endedAt: z.string().datetime({offset:true}),
    correlationId: stringId,
    /** Required for AC01 only, reported by the ChatGPT V3 native plugin. */
    nativeChatGPTToolName: stringId.nullable(),
    nativeChatGPTCallId: stringId.nullable(),
  }).strict(),
  output: z.object({
    deviceSignedReceiptSha256: digest,
    externalAuditAnchorSha256: digest,
    recipientConsentEvidenceSha256: digest,
    outputReadbackSha256: digest,
    canaryAndRollbackEvidenceSha256: digest.nullable(),
    noUnauthorizedChanges: z.literal(true),
  }).strict(),
  acceptance: z.object({
    decision: z.literal("PASS"),
    independentReviewerId: stringId,
    reviewerIsDifferentFromOwner: z.literal(true),
    physicalArtifactsInspected: z.literal(true),
    signedDecisionAt: z.string().datetime({offset:true}),
  }).strict(),
}).strict();
export type V3PhysicalGateEvidence = z.infer<typeof actualGateEvidenceSchema>;

export type V3DualSignedGateSubmission = {
  evidence: V3PhysicalGateEvidence;
  ownerSignatureBase64: string;
  independentReviewerSignatureBase64: string;
};
export interface V3AcceptedGate {
  gate: V3FinalGateId;
  evidenceHash: string;
  ownerSignatureHash: string;
  reviewerSignatureHash: string;
  acceptedAt: string;
}
export class V3FinalAcceptanceDenied extends Error {
  constructor(message:string){super(message);this.name="V3FinalAcceptanceDenied";}
}
function verifySigner(pem:string,value:unknown,base64:string):boolean {
  try {
    const signature=Buffer.from(base64,"base64");
    return signature.length===64&&signature.toString("base64")===base64&&
      verify(null,Buffer.from(canonicalJson(value)),createPublicKey(pem),signature);
  }catch{return false;}
}
function keyFingerprint(pem:string):string {
  return sha256(createPublicKey(pem).export({type:"spki",format:"der"}));
}
export class V3IndependentPhysicalAcceptanceLedger {
  readonly db:DatabaseSync;
  private readonly ownerFingerprint:string;
  private readonly reviewerFingerprint:string;
  constructor(
    file:string,
    private readonly ownerPublicKeyPem:string,
    private readonly reviewerPublicKeyPem:string,
    private readonly now:()=>number=()=>Date.now(),
  ){
    if(!path.isAbsolute(file)||file.toLowerCase().includes("\\v2\\"))
      throw new V3FinalAcceptanceDenied("independent V3 acceptance journal path required");
    this.ownerFingerprint=keyFingerprint(ownerPublicKeyPem);
    this.reviewerFingerprint=keyFingerprint(reviewerPublicKeyPem);
    if(this.ownerFingerprint===this.reviewerFingerprint)
      throw new V3FinalAcceptanceDenied("an independently controlled reviewer key is required");
    mkdirSync(path.dirname(file),{recursive:true});
    this.db=new DatabaseSync(file,{enableForeignKeyConstraints:true});
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS v3_final_gate_decisions ("+
      "gate TEXT PRIMARY KEY, evidence_json TEXT NOT NULL, evidence_hash TEXT NOT NULL UNIQUE,"+
      "owner_signature_hash TEXT NOT NULL, reviewer_signature_hash TEXT NOT NULL,"+
      "accepted_at_ms INTEGER NOT NULL);"
    );
  }
  get(gate:V3FinalGateId):V3AcceptedGate|undefined{
    const record=this.db.prepare(
      "SELECT evidence_hash,owner_signature_hash,reviewer_signature_hash,accepted_at_ms "+
      "FROM v3_final_gate_decisions WHERE gate=?"
    ).get(gate) as {
      evidence_hash:string;owner_signature_hash:string;
      reviewer_signature_hash:string;accepted_at_ms:number;
    }|undefined;
    if(!record)return undefined;
    return {
      gate,evidenceHash:record.evidence_hash,
      ownerSignatureHash:record.owner_signature_hash,
      reviewerSignatureHash:record.reviewer_signature_hash,
      acceptedAt:new Date(record.accepted_at_ms).toISOString(),
    };
  }
  accept(submission:V3DualSignedGateSubmission):V3AcceptedGate{
    const evidence=actualGateEvidenceSchema.parse(submission.evidence);
    const timestamp=Date.parse(evidence.acceptance.signedDecisionAt);
    const current=this.now();
    if(timestamp>current||current-timestamp>24*60*60*1000||
      Date.parse(evidence.submittedAt)>current||
      Date.parse(evidence.execution.endedAt)<Date.parse(evidence.execution.startedAt)||
      Date.parse(evidence.execution.endedAt)>current||
      evidence.ownerSubject===evidence.acceptance.independentReviewerId) {
      throw new V3FinalAcceptanceDenied("owner/reviewer or physical timestamps are invalid");
    }
    if(!verifySigner(this.ownerPublicKeyPem,evidence,submission.ownerSignatureBase64)||
      !verifySigner(this.reviewerPublicKeyPem,evidence,submission.independentReviewerSignatureBase64)){
      throw new V3FinalAcceptanceDenied("independent owner AND reviewer Ed25519 signatures required");
    }
    const actualDevices=new Set(evidence.execution.actualDeviceIds);
    if(evidence.gate==="P08"&&(!actualDevices.has("macbook-main")||
       evidence.execution.source!=="physical-mac")) {
      throw new V3FinalAcceptanceDenied("P08 requires persistent real Mac evidence");
    }
    if(evidence.gate==="I01"&&(!actualDevices.has("macbook-main")||
       !actualDevices.has("windows-main")||
       evidence.execution.source!=="cross-host-v3")) {
      throw new V3FinalAcceptanceDenied("I01 requires actual two-host signed execution");
    }
    if(evidence.gate==="F01"&&(!actualDevices.has("macbook-main")||
       !actualDevices.has("windows-main")||
       evidence.output.canaryAndRollbackEvidenceSha256===null)) {
      throw new V3FinalAcceptanceDenied("F01 requires real Windows/Mac canary AND rollback receipts");
    }
    if(evidence.gate==="AC01"&&(!actualDevices.has("macbook-main")||
       !actualDevices.has("windows-main")||
       evidence.execution.source!=="native-chatgpt-v3"||
       evidence.execution.nativeChatGPTCallId===null||
       evidence.execution.nativeChatGPTToolName===null||
       evidence.execution.nativeChatGPTToolName==="get_capabilities"||
       evidence.execution.nativeChatGPTToolName==="list_devices"||
       evidence.execution.nativeChatGPTToolName==="v3_admin_status")) {
      throw new V3FinalAcceptanceDenied("AC01 requires native ChatGPT V3 write/execute call and both hosts");
    }
    // Development of F01/AC01 may begin early; acceptance remains strictly
    // sequential and always requires genuine physical prerequisite entries.
    const missing=missingV3PhysicalAcceptancePrerequisites(
      evidence.gate,gate=>Boolean(this.get(gate)),
    );
    if(missing.length){
      throw new V3FinalAcceptanceDenied("independent prerequisite gate missing: "+missing[0]);
    }
    const evidenceHash=sha256(canonicalJson(evidence));
    this.db.prepare(
      "INSERT INTO v3_final_gate_decisions(gate,evidence_json,evidence_hash,owner_signature_hash,reviewer_signature_hash,accepted_at_ms) "+
      "VALUES(?,?,?,?,?,?)"
    ).run(
      evidence.gate,canonicalJson(evidence),evidenceHash,
      sha256(submission.ownerSignatureBase64),
      sha256(submission.independentReviewerSignatureBase64),current
    );
    const result=this.get(evidence.gate);
    if(!result)throw new V3FinalAcceptanceDenied("acceptance journal did not commit");
    return result;
  }
  readiness():{
    officialBaselineAccepted:number;
    total:number;
    gates:Record<V3FinalGateId,boolean>;
    productionReady:boolean;
    missing:V3FinalGateId[];
  }{
    const gates={
      P08:Boolean(this.get("P08")),I01:Boolean(this.get("I01")),
      F01:Boolean(this.get("F01")),AC01:Boolean(this.get("AC01")),
    };
    return {
      officialBaselineAccepted:24,total:28,gates,
      productionReady:Object.values(gates).every(Boolean),
      missing:V3_FINAL_GATES.filter(x=>!gates[x]),
    };
  }
  close():void{this.db.close();}
}
