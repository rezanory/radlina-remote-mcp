/**
 * Interactive Windows owner operation cycle; no shell or cross-device fallback.
 */
import { readFile } from "node:fs/promises";
import { runWindowsI01RecipientOnce } from "../../src/v3/integration/i01-windows-operator.js";
const pin="C:\\Users\\Radlina\\AppData\\Local\\Radlina\\V3\\owner-signing\\owner-public-pin.json";
if(process.argv.length!==2||process.env["RADLINA_V3_WINDOWS_OWNER_OPERATOR"]!=="1")
  throw Error("physical interactive V3 Windows recipient task required");
const owner=JSON.parse(await readFile(pin,"utf8")) as {
  ownerPrincipal:string;publicKeyPem:string;fingerprint:string;
};
if(owner.ownerPrincipal.toLowerCase()!=="laptop-13qineif\\radlina"||
  owner.fingerprint!=="6259d21211f73fc9d2d7cc0174d9bfdc36424cd456878671ab5683468ca0fe93"){
  throw Error("exact V3 owner key public pin required");
}
const outcome=await runWindowsI01RecipientOnce(owner.publicKeyPem);
process.stdout.write(JSON.stringify({
  schema:"radlina.v3.windows-operator-cycle/v1",outcome,
  v2Untouched:true,
})+"\n");
