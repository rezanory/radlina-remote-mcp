/**
 * F01 physical Windows+macOS canary/rollback adapter for V3FleetController.
 * Code only. Actual fleet actions require a signed recipient-local port.
 *
 * NEVER switch V2, and never consider a successful command exit an acceptance
 * receipt; verify exact target P03 signature plus S03 remote audit anchoring.
 */
import { createPublicKey, randomUUID, verify } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import * as z from "zod/v4";

import { canonicalJson, sha256 } from "../../utils/json.js";
import type {
  FleetAttestation, FleetDeviceAgentPort, FleetDeviceReader,
  FleetOwnershipAuthority, FleetPlan, FleetReceiptVerifierPort,
  FleetRecipientConsentPort, FleetSwitchReceipt, FleetVerifyReceipt,
  FleetOperation,
} from "./contracts.js";
import { assertManifestHash } from "./contracts.js";
import { effectiveTrustedDeviceHeartbeat } from "../device/mac-heartbeat-ingress.js";
import type { SqliteDeviceRegistry } from "../device/registry.js";

const hash = z.string().regex(/^[0-9a-f]{64}$/u);
export const f01ExactFleetCommandSchema = z.object({
  schema: z.literal("radlina.v3.f01.exact-fleet-operation/v1"),
  operationId: z.string().uuid(),
  planId: z.string().uuid(),
  deviceId: z.enum(["windows-main", "macbook-main"]),
  action: z.enum(["fleet.preflight","fleet.activate","fleet.verify","fleet.rollback"]),
  targetManifestSha256: hash,
  previousManifestSha256: hash,
  issuedAtMs: z.number().int().positive(),
  expiresAtMs: z.number().int().positive(),
  nonce: z.string().uuid(),
}).strict();
export type F01PhysicalCommand = z.infer<typeof f01ExactFleetCommandSchema>;
export const f01SignedCommandSchema = z.object({
  command: f01ExactFleetCommandSchema,
  ownerSignatureBase64: z.string().min(80).max(200),
}).strict();
export interface F01SignedCommand {
  command: F01PhysicalCommand;
  ownerSignatureBase64: string;
}
export interface F01SignedReply<T> {
  schema: "radlina.v3.f01.signed-fleet-reply/v1";
  operationId: string;
  deviceId: string;
  agentInstanceId: string;
  payload: T;
  deviceSignatureBase64: string;
}
export interface F01DeviceIdentityPort {
  requireFreshTrusted(id: string): {
    deviceId: string;
    agentInstanceId: string;
    publicKeyPem: string;
    signedHeartbeatFresh: true;
  };
}
export interface F01OwnerProtectedSigner {
  signCanonical(payload: string): Promise<string>;
}
export interface F01RecipientLocalReleaseConsent {
  /** Exact operation and version hashes must be locally approved on the target. */
  assertSignedLocalApproval(planId: string, deviceId: string,
    action: FleetOperation, target: string, previous: string): Promise<void>;
}
export interface F01PhysicalTransport {
  /**
   * Physical target verifies controller key, local consent and manifests,
   * and must atomically switch its own V3 release, not the controller's files.
   */
  perform<T>(message: F01SignedCommand): Promise<F01SignedReply<T>>;
}
export interface F01IndependentAuditPort {
  anchorPhysicalReceipt(input: {
    planId: string;
    deviceId: string;
    commandHash: string;
    deviceReceiptHash: string;
    devicePublicKeyPem: string;
    ownerSignedCommand: F01SignedCommand;
    signedReply: F01SignedReply<unknown>;
  }): Promise<{durable:true; anchorId:string}>;
}
export class F01PhysicalBlocked extends Error {
  constructor(reason:string) { super(reason);this.name="F01PhysicalBlocked"; }
}
export class V3ExactFleetDeviceReader implements FleetDeviceReader {
  constructor(private readonly registry: SqliteDeviceRegistry) {}
  get(deviceId: string) {
    if (deviceId !== "windows-main" && deviceId !== "macbook-main") return undefined;
    const record = this.registry.get(deviceId);
    if (!record) return undefined;
    const fresh = effectiveTrustedDeviceHeartbeat(record);
    return {
      deviceId: fresh.deviceId,
      trustState: fresh.trustState,
      status: fresh.heartbeatFresh ? fresh.status : "unknown",
      health: fresh.heartbeatFresh ? fresh.health : "unknown",
    };
  }
}
export class V3ExplicitFleetOwner implements FleetOwnershipAuthority {
  constructor(private readonly authority: {
    verifyAuthenticatedOwner(subject:string, operation: FleetOperation | "fleet.plan"): Promise<boolean>
  }) {}
  async assertOwner(subject:string, operation:FleetOperation|"fleet.plan"):Promise<void> {
    if (!subject.trim() || !await this.authority.verifyAuthenticatedOwner(subject,operation))
      throw new F01PhysicalBlocked("fleet action requires independently verified owner principal");
  }
}
export class V3ExactFleetRecipientConsent implements FleetRecipientConsentPort {
  constructor(private readonly grants: {
    requireTargetLocalSignedGrant(deviceId:string, operation:FleetOperation, planId:string):Promise<boolean>;
  }) {}
  async require(deviceId:string,operation:FleetOperation,planId:string):Promise<void> {
    if (!await this.grants.requireTargetLocalSignedGrant(deviceId,operation,planId)) {
      throw new F01PhysicalBlocked("target-local signed recipient fleet approval unavailable");
    }
  }
}
function signedReplyMatches<T extends {deviceId:string}>(
  reply: F01SignedReply<T>,
  operation:F01PhysicalCommand,
  identity:{agentInstanceId:string;publicKeyPem:string},
):boolean {
  if (reply.schema!=="radlina.v3.f01.signed-fleet-reply/v1" ||
    reply.operationId!==operation.operationId ||
    reply.deviceId!==operation.deviceId ||
    reply.agentInstanceId!==identity.agentInstanceId ||
    reply.payload.deviceId!==operation.deviceId) return false;
  const bound = {
    schema:reply.schema,operationId:reply.operationId,
    deviceId:reply.deviceId,agentInstanceId:reply.agentInstanceId,
    payload:reply.payload,
  };
  try {
    const proof=Buffer.from(reply.deviceSignatureBase64,"base64");
    return proof.length===64 && proof.toString("base64")===reply.deviceSignatureBase64 &&
      verify(null,Buffer.from(canonicalJson(bound)),createPublicKey(identity.publicKeyPem),proof);
  }catch{return false;}
}

/** Persistent unknown-outcome guard: crash cannot trigger a second switch. */
export class F01PhysicalDispatchJournal {
  readonly db:DatabaseSync;
  constructor(file:string) {
    if(!path.isAbsolute(file)||file.toLowerCase().includes("\\v2\\"))
      throw new F01PhysicalBlocked("isolated V3 F01 journal path mandatory");
    mkdirSync(path.dirname(file),{recursive:true});
    this.db=new DatabaseSync(file,{enableForeignKeyConstraints:true});
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS v3_f01_physical_dispatches(" +
      "operation_key TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE, plan_id TEXT NOT NULL, " +
      "device_id TEXT NOT NULL, action TEXT NOT NULL, command_hash TEXT NOT NULL, " +
      "state TEXT NOT NULL CHECK(state IN ('pending','anchored','uncertain')), " +
      "anchor_id TEXT, created_at_ms INTEGER NOT NULL);"
    );
  }
  reserve(key:string,id:string,plan:string,device:string,action:string,hashValue:string):void {
    const exists=this.db.prepare(
      "SELECT command_hash FROM v3_f01_physical_dispatches WHERE operation_key=?"
    ).get(key) as {command_hash:string}|undefined;
    if(exists)throw new F01PhysicalBlocked(
      exists.command_hash===hashValue ? "existing fleet outcome requires manual reconciliation" :
        "fleet idempotency conflict"
    );
    this.db.prepare(
      "INSERT INTO v3_f01_physical_dispatches(operation_key,operation_id,plan_id,device_id,action,command_hash,state,created_at_ms) " +
      "VALUES(?,?,?,?,?,?,'pending',?)"
    ).run(key,id,plan,device,action,hashValue,Date.now());
  }
  anchor(key:string,anchorId:string):void {
    const change=this.db.prepare(
      "UPDATE v3_f01_physical_dispatches SET state='anchored',anchor_id=? WHERE operation_key=? AND state='pending'"
    ).run(anchorId,key);
    if(Number(change.changes)!==1)throw new F01PhysicalBlocked("fleet receipt anchor CAS failed");
  }
  uncertain(key:string):void {
    this.db.prepare(
      "UPDATE v3_f01_physical_dispatches SET state='uncertain' WHERE operation_key=? AND state='pending'"
    ).run(key);
  }
  close():void{this.db.close();}
}

/**
 * Bound to one explicit two-device plan; do not reuse between fleet plans.
 * V3FleetController maintains the canary phase, rollback order and manual stop.
 */
export class V3PhysicalSignedFleetAgent implements FleetDeviceAgentPort, FleetReceiptVerifierPort {
  private readonly staged=new Map<string,{target:string;previous:string}>();
  private readonly signedReceipts=new Set<string>();
  constructor(
    private readonly plan:FleetPlan,
    private readonly identity:F01DeviceIdentityPort,
    private readonly signer:F01OwnerProtectedSigner,
    private readonly recipient:F01RecipientLocalReleaseConsent,
    private readonly transport:F01PhysicalTransport,
    private readonly audit:F01IndependentAuditPort,
    private readonly journal:F01PhysicalDispatchJournal,
    private readonly now:()=>number=()=>Date.now(),
  ){
    if(plan.targetDeviceIds.length!==2||
      !plan.targetDeviceIds.includes("windows-main")||
      !plan.targetDeviceIds.includes("macbook-main")||
      !plan.targetDeviceIds.includes(plan.canaryDeviceId)){
      throw new F01PhysicalBlocked("F01 physical rollout must select exact Windows and Mac devices");
    }
    assertManifestHash(plan.targetManifestSha256);
    assertManifestHash(plan.rollbackManifestSha256);
    if(plan.targetManifestSha256===plan.rollbackManifestSha256)
      throw new F01PhysicalBlocked("target and rollback manifest cannot match");
  }
  private async operation<T extends {deviceId:string}>(
    id:string,action:FleetOperation,target:string,previous:string,
  ):Promise<T>{
    if(id!=="windows-main"&&id!=="macbook-main")
      throw new F01PhysicalBlocked("unknown physical target");
    assertManifestHash(target);assertManifestHash(previous);
    const identity=this.identity.requireFreshTrusted(id);
    if(identity.deviceId!==id||!identity.signedHeartbeatFresh)
      throw new F01PhysicalBlocked("physical device P03 signed heartbeat not fresh");
    await this.recipient.assertSignedLocalApproval(this.plan.planId,id,action,target,previous);
    const now=this.now();
    const command=f01ExactFleetCommandSchema.parse({
      schema:"radlina.v3.f01.exact-fleet-operation/v1",
      operationId:randomUUID(),planId:this.plan.planId,deviceId:id,action,
      targetManifestSha256:target,previousManifestSha256:previous,
      issuedAtMs:now,expiresAtMs:now+90000,nonce:randomUUID(),
    });
    const canonical=canonicalJson(command);
    const signature=await this.signer.signCanonical(canonical);
    if(Buffer.from(signature,"base64").length!==64)
      throw new F01PhysicalBlocked("protected owner release-signing key is unavailable");
    const key=sha256(canonicalJson({
      planId:this.plan.planId,deviceId:id,action,target,previous,
    }));
    this.journal.reserve(key,command.operationId,this.plan.planId,id,action,sha256(canonical));
    try{
      const signedCommand:F01SignedCommand={command,ownerSignatureBase64:signature};
      const received=await this.transport.perform<T>(signedCommand);
      if(!signedReplyMatches(received,command,identity))
        throw new F01PhysicalBlocked("P03 signed physical switch receipt invalid");
      const receiptHash=sha256(canonicalJson(received.payload));
      const anchored=await this.audit.anchorPhysicalReceipt({
        planId:this.plan.planId,deviceId:id,commandHash:sha256(canonical),
        deviceReceiptHash:receiptHash,
        devicePublicKeyPem:identity.publicKeyPem,
        ownerSignedCommand:signedCommand,
        signedReply:received,
      });
      if(!anchored.durable||!anchored.anchorId)
        throw new F01PhysicalBlocked("missing independently persisted S03 fleet audit");
      this.journal.anchor(key,anchored.anchorId);
      this.signedReceipts.add(receiptHash);
      return received.payload;
    }catch(e){this.journal.uncertain(key);throw e;}
  }
  async preflight(deviceId:string,target:string,previous:string):Promise<FleetAttestation>{
    const result=await this.operation<FleetAttestation>(deviceId,"fleet.preflight",target,previous);
    if(result.identityVerified&&result.stagedTargetVerified&&result.stagedRollbackVerified) {
      this.staged.set(deviceId,{target,previous});
    }
    return result;
  }
  async activate(deviceId:string,target:string):Promise<FleetSwitchReceipt>{
    const stages=this.staged.get(deviceId);
    if(!stages||stages.target!==target)
      throw new F01PhysicalBlocked("both signed release manifests must be physically preflighted");
    return await this.operation<FleetSwitchReceipt>(deviceId,"fleet.activate",target,stages.previous);
  }
  async verify(deviceId:string,expected:string):Promise<FleetVerifyReceipt>{
    const stages=this.staged.get(deviceId);
    if(!stages||(expected!==stages.target&&expected!==stages.previous))
      throw new F01PhysicalBlocked("expected manifest not covered by signed preflight");
    return await this.operation<FleetVerifyReceipt>(
      deviceId,"fleet.verify",expected,
      expected===stages.target?stages.previous:stages.target
    );
  }
  async rollback(deviceId:string,previous:string):Promise<FleetSwitchReceipt>{
    const stages=this.staged.get(deviceId);
    if(!stages||previous!==stages.previous)
      throw new F01PhysicalBlocked("rollback manifest not staged and signed by target");
    return await this.operation<FleetSwitchReceipt>(deviceId,"fleet.rollback",previous,stages.target);
  }
  async verifyPreflight(receipt:FleetAttestation):Promise<boolean>{
    return this.signedReceipts.has(sha256(canonicalJson(receipt)));
  }
  async verifySwitch(receipt:FleetSwitchReceipt):Promise<boolean>{
    return this.signedReceipts.has(sha256(canonicalJson(receipt)));
  }
  async verifyHealth(receipt:FleetVerifyReceipt):Promise<boolean>{
    return this.signedReceipts.has(sha256(canonicalJson(receipt)));
  }
}
