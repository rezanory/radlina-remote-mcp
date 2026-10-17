/**
 * Pinned per-user physical Mac V3 I01 cycle.
 * launchd owns recurrence; this process handles exactly one bounded cycle.
 */
import { runPhysicalMacOperatorOnce } from "../../src/v3/integration/i01-macos-operator.js";

const policy=process.env["RADLINA_V3_MAC_OPERATOR_POLICY_PATH"];
if(!policy||process.argv.length!==2)
  throw Error("physical Mac V3 operator requires explicitly configured signed policy");
const result=await runPhysicalMacOperatorOnce(policy);
process.stdout.write(JSON.stringify({
  schema:"radlina.v3.mac-operator-cycle/v1",
  result,generatedAt:new Date().toISOString(),
  v2Untouched:true,
})+"\n");
