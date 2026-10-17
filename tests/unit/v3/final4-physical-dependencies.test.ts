import { describe, expect, it } from "vitest";
import {
  V3_PHYSICAL_ACCEPTANCE_ORDER,
  V3_PHYSICAL_ACCEPTANCE_PREREQUISITES,
  missingV3PhysicalAcceptancePrerequisites,
  v3PhysicalDevelopmentRoadmap,
} from "../../../src/v3/acceptance/final4-physical-dependencies.js";
import { V3_FINAL_GATES } from "../../../src/v3/acceptance/ac01-final-gates.js";

describe("V3 physical gate dependency separation: build ahead, accept in order",()=>{
  it("shares the same exact four gates as the AC01 physical ledger",()=>{
    expect(V3_PHYSICAL_ACCEPTANCE_ORDER).toEqual(V3_FINAL_GATES);
    expect(V3_PHYSICAL_ACCEPTANCE_PREREQUISITES).toEqual({
      P08:[],
      I01:["P08"],
      F01:["P08","I01"],
      AC01:["P08","I01","F01"],
    });
  });

  it("I01 can be accepted after P08 without requiring F01 or AC01",()=>{
    const accepted=new Set(["P08"]);
    const missing=missingV3PhysicalAcceptancePrerequisites(
      "I01",gate=>accepted.has(gate),
    );
    expect(missing).toEqual([]);
    expect(missingV3PhysicalAcceptancePrerequisites(
      "F01",gate=>accepted.has(gate),
    )).toEqual(["I01"]);
    expect(missingV3PhysicalAcceptancePrerequisites(
      "AC01",gate=>accepted.has(gate),
    )).toEqual(["I01","F01"]);
  });

  it("permits F01 and AC01 source development even when I01 is incomplete",()=>{
    const accepted=new Set(["P08"]);
    expect(v3PhysicalDevelopmentRoadmap(gate=>accepted.has(gate))).toEqual([
      {gate:"P08",developmentMayProceed:true,alreadyAccepted:true,
        missingAcceptancePrerequisites:[],prerequisiteEvidenceComplete:true},
      {gate:"I01",developmentMayProceed:true,alreadyAccepted:false,
        missingAcceptancePrerequisites:[],prerequisiteEvidenceComplete:true},
      {gate:"F01",developmentMayProceed:true,alreadyAccepted:false,
        missingAcceptancePrerequisites:["I01"],prerequisiteEvidenceComplete:false},
      {gate:"AC01",developmentMayProceed:true,alreadyAccepted:false,
        missingAcceptancePrerequisites:["I01","F01"],prerequisiteEvidenceComplete:false},
    ]);
  });

  it("requires P08 for I01 and never treats completed code as accepted P08",()=>{
    const none=()=>false;
    expect(missingV3PhysicalAcceptancePrerequisites("I01",none)).toEqual(["P08"]);
    expect(v3PhysicalDevelopmentRoadmap(none).every(x=>x.developmentMayProceed)).toBe(true);
    expect(v3PhysicalDevelopmentRoadmap(none).find(x=>x.gate==="I01")!
      .prerequisiteEvidenceComplete).toBe(false);
  });

  it("F01 must have I01; AC01 must have F01 in physical acceptance",()=>{
    const accepted=new Set(["P08","I01"]);
    expect(missingV3PhysicalAcceptancePrerequisites("F01",gate=>accepted.has(gate)))
      .toEqual([]);
    expect(missingV3PhysicalAcceptancePrerequisites("AC01",gate=>accepted.has(gate)))
      .toEqual(["F01"]);
  });

  it("completed prerequisites alone never mark the target gate accepted",()=>{
    const accepted=new Set(["P08","I01","F01"]);
    const planned=v3PhysicalDevelopmentRoadmap(gate=>accepted.has(gate));
    expect(planned.find(x=>x.gate==="AC01")).toEqual({
      gate:"AC01",developmentMayProceed:true,alreadyAccepted:false,
      missingAcceptancePrerequisites:[],prerequisiteEvidenceComplete:true,
    });
  });

  it("does not mutate or implicitly write accepted gate state",()=>{
    const accepted=new Set(["P08"]);
    const before=[...accepted];
    const roadmap=v3PhysicalDevelopmentRoadmap(gate=>accepted.has(gate));
    expect([...accepted]).toEqual(before);
    expect(roadmap.filter(x=>x.alreadyAccepted).map(x=>x.gate)).toEqual(["P08"]);
    expect(roadmap).toHaveLength(4);
  });
});
