/**
 * F01 bounded physical controller composition.
 *
 * Each real plan receives a separate signed native agent, release hash pair
 * and persistent operation journal. Nothing here starts a canary on import.
 */
import path from "node:path";

import { fleetPlanSchema, type FleetPlan, type FleetOwnershipAuthority,
  type FleetRecipientConsentPort } from "./contracts.js";
import { V3FleetController } from "./controller.js";
import type { SqliteFleetStore, FleetPlanSnapshot } from "./store.js";
import type { SqliteDeviceRegistry } from "../device/registry.js";
import {
  F01PhysicalDispatchJournal,
  V3ExactFleetDeviceReader,
  V3PhysicalSignedFleetAgent,
  type F01DeviceIdentityPort,
  type F01OwnerProtectedSigner,
  type F01RecipientLocalReleaseConsent,
  type F01PhysicalTransport,
  type F01IndependentAuditPort,
} from "./physical-adapters.js";

export interface V3FleetControlPort {
  plan(raw: FleetPlan): Promise<{snapshot:FleetPlanSnapshot;replayed:boolean}>;
  run(planId:string, ownerSubject:string): Promise<FleetPlanSnapshot>;
}
export interface V3PhysicalFleetComposition {
  registry: SqliteDeviceRegistry;
  store: SqliteFleetStore;
  owner: FleetOwnershipAuthority;
  consent: FleetRecipientConsentPort;
  recipientLocal: F01RecipientLocalReleaseConsent;
  identities: F01DeviceIdentityPort;
  protectedSigner: F01OwnerProtectedSigner;
  physicalTransport: F01PhysicalTransport;
  externalAudit: F01IndependentAuditPort;
  isolatedStateRoot: string;
}
export class V3PhysicalFleetOrchestrator implements V3FleetControlPort {
  constructor(private readonly config:V3PhysicalFleetComposition) {
    if (!path.isAbsolute(config.isolatedStateRoot) ||
      config.isolatedStateRoot.toLowerCase().includes("\\v2\\")) {
      throw new Error("F01 requires a dedicated V3 absolute persistent state root");
    }
  }
  private controller(plan:FleetPlan) {
    const journal=new F01PhysicalDispatchJournal(path.join(
      this.config.isolatedStateRoot,"fleet","ops-"+plan.planId+".sqlite3"));
    const agent=new V3PhysicalSignedFleetAgent(
      plan,this.config.identities,this.config.protectedSigner,
      this.config.recipientLocal,this.config.physicalTransport,
      this.config.externalAudit,journal,
    );
    return {
      controller:new V3FleetController(
        this.config.store,
        new V3ExactFleetDeviceReader(this.config.registry),
        agent,this.config.owner,this.config.consent,agent,
      ),
      journal,
    };
  }
  async plan(raw:FleetPlan):Promise<{snapshot:FleetPlanSnapshot;replayed:boolean}> {
    const plan=fleetPlanSchema.parse(raw);
    const bound=this.controller(plan);
    try {
      return await bound.controller.plan(plan);
    } finally { bound.journal.close(); }
  }
  async run(planId:string,ownerSubject:string):Promise<FleetPlanSnapshot> {
    const snapshot=this.config.store.require(planId);
    const bound=this.controller(snapshot.plan);
    try{
      return await bound.controller.run(planId,ownerSubject);
    } finally {bound.journal.close();}
  }
}
