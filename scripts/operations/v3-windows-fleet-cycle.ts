/**
 * Physical Windows V3-only reversible fleet supervisor cycle.
 * Owner-approved configuration file and a physical local user token required.
 */
import { readFile } from "node:fs/promises";
import { createPublicKey } from "node:crypto";
import { sha256 } from "../../src/utils/json.js";
import { runPhysicalWindowsFleetOnce } from "../../src/v3/fleet/windows-fleet-operator.js";

const file=process.env["RADLINA_V3_FINAL4_CONFIG_PATH"];
const expected=process.env["RADLINA_V3_FINAL4_CONFIG_SHA256"];
if(!file||!/^[a-f0-9]{64}$/u.test(expected??"")||process.argv.length!==2||
  process.env["RADLINA_V3_FLEET_SUPERVISOR"]!=="1"){
  throw Error("owner-authorized V3 Windows final-four fleet configuration required");
}
const bytes=await readFile(file);
if(bytes.length>32768||sha256(bytes)!==expected)
  throw Error("Windows physical fleet config has changed since owner approval");
const record=JSON.parse(bytes.toString("utf8")) as {
  ownerPublicKeyPem:string;macTailnetNodeHash:string;
};
if(!record.ownerPublicKeyPem?.includes("BEGIN PUBLIC KEY")||
  !/^[a-f0-9]{64}$/u.test(record.macTailnetNodeHash)){
  throw Error("exact physical V3 owner/Mac fleet pins required");
}
const result=await runPhysicalWindowsFleetOnce({
  ownerPublicKeyPem:record.ownerPublicKeyPem,
  macTailnetNodeHash:record.macTailnetNodeHash,
});
process.stdout.write(JSON.stringify({
  schema:"radlina.v3.windows-fleet-cycle/v1",result,
  v2Untouched:true,
})+"\n");
