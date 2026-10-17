/**
 * One physical macOS F01 owner-signed, recipient-local approved fleet step.
 * No automatic switch, retry or rollback is performed unless a real command
 * has already passed exact P03 verification in runV3MacFleetOnce.
 */
import { readFile } from "node:fs/promises";
import { createPublicKey } from "node:crypto";
import { sha256 } from "../../src/utils/json.js";
import { requireOwnerApprovedMacOperatorPolicy } from "../../src/v3/device/p08-mac-operator-policy.js";
import { runV3MacFleetOnce } from "../../src/v3/fleet/mac-fleet-operator.js";

const policyPath=process.env["RADLINA_V3_MAC_OPERATOR_POLICY_PATH"];
if(!policyPath||process.argv.length!==2 ||
  process.env["RADLINA_V3_FLEET_SUPERVISOR"]!=="1"){
  throw Error("F01 must run in its own owner-authorized Mac supervisor");
}
const bytes=await readFile(policyPath);
if(bytes.length>8192)throw Error("signed Mac V3 policy exceeds hard bound");
const policy=requireOwnerApprovedMacOperatorPolicy(JSON.parse(bytes.toString("utf8")));
const fingerprint=sha256(createPublicKey(policy.ownerPublicKeyPem).export({
  type:"spki",format:"der",
}));
const result=await runV3MacFleetOnce({
  ownerPublicKeyPem:policy.ownerPublicKeyPem,
  ownerFingerprint:fingerprint,
  windowsTailnetNodeHash:policy.windowsTailnetNodeHash,
});
process.stdout.write(JSON.stringify({
  schema:"radlina.v3.mac-fleet-cycle/v1",
  result,generatedAt:new Date().toISOString(),
  v2Untouched:true,
})+"\n");
