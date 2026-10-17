/**
 * V3 physical acceptance dependency graph, shared by I01, F01 and AC01.
 *
 * Source development and isolated tests may proceed on later gates before
 * acceptance of earlier gates. Physical acceptance CANNOT: it still requires
 * every prerequisite and its own independently authenticated evidence.
 *
 * Never mistake this planning metadata for signed physical acceptance.
 */
export const V3_PHYSICAL_ACCEPTANCE_ORDER=[
  "P08","I01","F01","AC01",
] as const;
export type V3PhysicalAcceptanceGate=typeof V3_PHYSICAL_ACCEPTANCE_ORDER[number];

export const V3_PHYSICAL_ACCEPTANCE_PREREQUISITES:{
  readonly [G in V3PhysicalAcceptanceGate]:readonly V3PhysicalAcceptanceGate[];
}=Object.freeze({
  P08:Object.freeze([] as const),
  I01:Object.freeze(["P08"] as const),
  F01:Object.freeze(["P08","I01"] as const),
  AC01:Object.freeze(["P08","I01","F01"] as const),
});

export function missingV3PhysicalAcceptancePrerequisites(
  gate:V3PhysicalAcceptanceGate,
  isAccepted:(gate:V3PhysicalAcceptanceGate)=>boolean,
):V3PhysicalAcceptanceGate[]{
  return V3_PHYSICAL_ACCEPTANCE_PREREQUISITES[gate].filter(
    prerequisite=>!isAccepted(prerequisite),
  );
}

/**
 * Plan parallel development without bypassing sequential acceptance.
 * prerequisiteEvidenceComplete means ONLY that earlier physical gates were
 * accepted; it never verifies this gate's own live execution, S02E, S03 or
 * cryptographic owner/reviewer decision.
 */
export function v3PhysicalDevelopmentRoadmap(
  isAccepted:(gate:V3PhysicalAcceptanceGate)=>boolean,
):Array<{
  gate:V3PhysicalAcceptanceGate;
  developmentMayProceed:true;
  alreadyAccepted:boolean;
  missingAcceptancePrerequisites:V3PhysicalAcceptanceGate[];
  prerequisiteEvidenceComplete:boolean;
}>{
  return V3_PHYSICAL_ACCEPTANCE_ORDER.map(gate=>{
    const missingAcceptancePrerequisites=missingV3PhysicalAcceptancePrerequisites(
      gate,isAccepted,
    );
    return {
      gate,developmentMayProceed:true,alreadyAccepted:isAccepted(gate),
      missingAcceptancePrerequisites,
      prerequisiteEvidenceComplete:missingAcceptancePrerequisites.length===0,
    };
  });
}
