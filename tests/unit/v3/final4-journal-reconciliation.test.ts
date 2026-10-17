import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { I01DurableDispatchJournal } from "../../../src/v3/integration/i01-secured-dispatch.js";
import { F01PhysicalDispatchJournal } from "../../../src/v3/fleet/physical-adapters.js";

const temporary:string[]=[];
const connections:Array<{close():void}>=[];
async function journalFile(name:string):Promise<string>{
  const root=await mkdtemp(path.join(tmpdir(),"radlina-v3-final4-journal-"));
  temporary.push(root);
  return path.join(root,name);
}
afterEach(async()=>{
  for(const db of connections.splice(0))db.close();
  for(const root of temporary.splice(0))await rm(root,{recursive:true,force:true});
});

describe("V3 I01 and F01 persistent unknown-outcome journals (test-only)",()=>{
  it("I01 reserves once and rejects all repeated native requests, even when marked unknown",async()=>{
    const db=new I01DurableDispatchJournal(await journalFile("i01.sqlite3"));
    connections.push(db);
    const key="a".repeat(64),hash="b".repeat(64),id=randomUUID();
    db.reserve(key,hash,"macbook-main",id);
    expect(db.getForManualReconciliation(key)).toMatchObject({requestId:id,state:"pending"});
    expect(()=>db.reserve(key,hash,"macbook-main",randomUUID())).toThrow(/no automatic remote retry/u);
    db.uncertain(key);
    expect(db.getForManualReconciliation(key)?.state).toBe("uncertain");
    expect(()=>db.reserve(key,hash,"macbook-main",randomUUID())).toThrow(/no automatic remote retry/u);
    expect(()=>db.reserve(key,"f".repeat(64),"macbook-main",randomUUID())).toThrow(/collides/u);
  });

  it("I01 requires a durable unknown outcome before one signed-evidence reconciliation",async()=>{
    const db=new I01DurableDispatchJournal(await journalFile("i01.sqlite3"));
    connections.push(db);
    const key="a".repeat(64);
    db.reserve(key,"b".repeat(64),"windows-main",randomUUID());
    expect(()=>db.completeManually(key,"c".repeat(64),"anchor-1")).toThrow(/cannot be reconciled twice/u);
    db.uncertain(key);
    expect(()=>db.completeManually(key,"bad","anchor-1")).toThrow(/signed I01 recovery evidence/u);
    db.completeManually(key,"c".repeat(64),"anchor-1");
    expect(db.getForManualReconciliation(key)?.state).toBe("completed");
    expect(()=>db.completeManually(key,"c".repeat(64),"anchor-1")).toThrow(/cannot be reconciled twice/u);
    expect(()=>db.reserve(key,"b".repeat(64),"windows-main",randomUUID())).toThrow(/no automatic remote retry/u);
  });

  it("F01 preserves signed fleet operation identity and blocks native switch replay",async()=>{
    const db=new F01PhysicalDispatchJournal(await journalFile("f01.sqlite3"));
    connections.push(db);
    const key="1".repeat(64),id=randomUUID(),planId=randomUUID(),commandHash="2".repeat(64);
    db.reserve(key,id,planId,"windows-main","fleet.activate",commandHash);
    expect(db.unresolved(id)).toMatchObject({
      operationKey:key,commandHash,planId,deviceId:"windows-main",action:"fleet.activate",state:"pending",
    });
    expect(()=>db.reserve(key,randomUUID(),planId,"windows-main","fleet.activate",commandHash)).toThrow(/manual reconciliation/u);
    db.uncertain(key);
    expect(db.unresolved(id)?.state).toBe("uncertain");
    expect(()=>db.reserve(key,randomUUID(),planId,"windows-main","fleet.activate",commandHash)).toThrow(/manual reconciliation/u);
  });

  it("F01 manually anchors only once after unknown outcome without restarting the rollout",async()=>{
    const db=new F01PhysicalDispatchJournal(await journalFile("f01.sqlite3"));
    connections.push(db);
    const key="1".repeat(64),id=randomUUID(),planId=randomUUID();
    db.reserve(key,id,planId,"macbook-main","fleet.rollback","2".repeat(64));
    expect(()=>db.anchorManual(key,"anchor-1")).toThrow(/manual anchor CAS failed/u);
    db.uncertain(key);
    expect(()=>db.anchorManual(key,"")).toThrow(/signed S03 fleet ACK required/u);
    db.anchorManual(key,"anchor-1");
    expect(db.unresolved(id)?.state).toBe("anchored");
    expect(()=>db.anchorManual(key,"anchor-1")).toThrow(/manual anchor CAS failed/u);
  });
});
