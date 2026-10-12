/**
 * OWNER-INITIATED ONLY: reconcile a specific previously uncertain F01 native
 * release switch. This is NOT installation, rollout, rollback or acceptance.
 * No service may be started/stopped; two already-signed independent human
 * observations and live healthy V3 release inspection are mandatory.
 *
 * Code-only: do not execute until a later authorized owner maintenance gate.
 */
import { createPublicKey } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import * as z from "zod/v4";
import { sha256 } from "../../src/utils/json.js";
import { V3NativeSwitchJournal } from "../../src/v3/fleet/native-switch-journal.js";
import {
  WindowsV3NativeReleaseHost,MacV3NativeReleaseHost,
} from "../../src/v3/fleet/native-v3-release-host.js";

const digest=z.string().regex(/^[a-f0-9]{64}$/u);
const evidence=z.object({
  schema:z.literal("radlina.v3.f01.native-switch-reconciliation/v1"),
  switchId:z.string().uuid(),deviceId:z.enum(["windows-main","macbook-main"]),
  beforeManifestSha256:digest,afterManifestSha256:digest,
  observedManifestSha256:digest,observedHealth:z.literal("healthy"),
  observedAtMs:z.number().int().positive(),nonce:z.string().uuid(),
  codeExecutionPerformed:z.literal(false),
}).strict();
const signed=z.object({
  evidence,
  ownerSignatureBase64:z.string().min(86).max(90),
  reviewerSignatureBase64:z.string().min(86).max(90),
}).strict();
const pins=z.object({
  schema:z.literal("radlina.v3.final-four-production-binding/v1"),
  ownerPublicKeyPem:z.string().includes("BEGIN PUBLIC KEY").max(4096),
  independentReviewerPublicKeyPem:z.string().includes("BEGIN PUBLIC KEY").max(4096),
}).passthrough();
if(process.argv.length!==4||process.argv[2]!=="--reconcile")
  throw Error("explicit --reconcile signed-proofs-file required");
const windows=process.platform==="win32";
const mac=process.platform==="darwin";
if(!windows&&!mac)throw Error("exact native Windows/Mac V3 operator required");
if((windows&&(
  os.hostname().toLowerCase()!=="laptop-13qineif"||
  os.userInfo().username.toLowerCase()!=="radlina"))||
  (mac&&(os.hostname()!=="amirs-MacBook-Pro.local"||
  os.userInfo().username!=="amirsheikhzadeh"))||
  process.env["RADLINA_V3_FLEET_SUPERVISOR"]!=="1")
  throw Error("only physically signed-in V3 owner fleet supervisor permitted");
const configFile=process.env["RADLINA_V3_FINAL4_CONFIG_PATH"];
const configSha=process.env["RADLINA_V3_FINAL4_CONFIG_SHA256"];
if(!configFile||!path.isAbsolute(configFile)||!configSha||!digest.safeParse(configSha).success)
  throw Error("independently approved exact V3 owner binding required");
async function exactPrivate(file:string,max:number):Promise<Buffer>{
  if(!path.isAbsolute(file)||file.toLowerCase().includes("v2"))
    throw Error("isolated native V3-only file required");
  const info=await stat(file);
  if(!info.isFile()||info.isSymbolicLink()||info.size>max||info.size<32||
    (mac&&(info.mode&0o077)!==0))
    throw Error("dedicated private V3 signed file missing");
  return readFile(file);
}
const configBytes=await exactPrivate(configFile,16384);
if(sha256(configBytes)!==configSha)
  throw Error("owner-approved immutable V3 binding digest changed");
const policy=pins.parse(JSON.parse(configBytes.toString("utf8")));
const provided=signed.parse(JSON.parse(
  (await exactPrivate(process.argv[3]!,16384)).toString("utf8"),
));
const deviceId=windows?"windows-main":"macbook-main";
if(provided.evidence.deviceId!==deviceId)
  throw Error("reconciliation cannot be applied to another physical device");
const host=windows?new WindowsV3NativeReleaseHost():new MacV3NativeReleaseHost();
const expected=await host.currentManifest();
if(provided.evidence.observedManifestSha256!==expected)
  throw Error("live native V3 release is different from independently signed observation");
const result=await host.verifyActiveRelease(expected);
if(result.health!=="healthy")
  throw Error("native V3 service not independently healthy; unresolved switch remains blocked");
const root=windows?"E:\\radlina-v3-runtime\\supervisor\\native-switch.sqlite3":
  path.join(os.homedir(),".local","share","radlina","v3-beta",
    "macbook-main-agent","fleet","native-switch.sqlite3");
const fingerprint=(pem:string)=>sha256(createPublicKey(pem).export({type:"spki",format:"der"}));
const journal=new V3NativeSwitchJournal(root,deviceId);
try{
  journal.reconcileUnknown({
    evidence:provided.evidence,
    ownerSignatureBase64:provided.ownerSignatureBase64,
    reviewerSignatureBase64:provided.reviewerSignatureBase64,
    pins:{
      ownerPublicKeyPem:policy.ownerPublicKeyPem,
      reviewerPublicKeyPem:policy.independentReviewerPublicKeyPem,
      ownerKeyFingerprint:fingerprint(policy.ownerPublicKeyPem),
      reviewerKeyFingerprint:fingerprint(policy.independentReviewerPublicKeyPem),
    },
  });
  if(await host.currentManifest()!==expected)
    throw Error("native service changed after reconciliation; manual review required");
  process.stdout.write(JSON.stringify({
    schema:"radlina.v3.f01.manual-reconciliation-recorded/v1",
    switchId:provided.evidence.switchId,deviceId,observedManifestSha256:expected,
    nativeServiceHealth:"healthy",v2Untouched:true,
    isOperationalAcceptance:false,automaticRollbackPerformed:false,
  })+"\n");
}finally{journal.close();}
