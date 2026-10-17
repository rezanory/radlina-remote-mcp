/**
 * V3 interactive owner-only final-four public-policy preparation.
 *
 * Never generates OAuth client registrations, reviewer keys or S03 witness
 * keys. Requires those REAL public identities as inputs. Mac operator policy
 * is signed with the existing Windows CurrentUser DPAPI Ed25519 owner key.
 * Outputs are public-key policy files only. Not executed in coding-only turns.
 */
import { createPublicKey } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import * as z from "zod/v4";

import { canonicalJson, sha256 } from "../../src/utils/json.js";
import { SqliteDeviceRegistry } from "../../src/v3/device/registry.js";
import { V3WindowsProtectedOwnerSigner } from "../../src/v3/security/windows-owner-signer.js";
import { resolveFinalFourProvisionMode } from "../../src/v3/integration/final4-development-gating.js";

const HASH=z.string().regex(/^[a-f0-9]{64}$/u);
const inputSchema=z.object({
  schema:z.literal("radlina.v3.final-four-owner-provision/v1"),
  authorizedChatGPTClientIds:z.array(z.string().min(12).max(200)).min(1).max(10),
  ownerSubject:z.string().min(1).max(200),
  approvedSourceDeviceIds:z.array(z.enum(["windows-main","macbook-main"])).min(1).max(2),
  allowedCapabilities:z.array(z.enum([
    "device.health","filesystem.read","filesystem.write",
  ])).min(1).max(3),
  independentReviewerPublicKeyFile:z.string().min(5).max(4096).optional(),
  s03WitnessPublicKeyFile:z.string().min(5).max(4096),
  expiresAt:z.string().datetime({offset:true}),
}).strict();
const ROOT="E:\\radlina-v3-oauth-standalone";
const OUT=path.win32.join(ROOT,"final4","owner-policies");
const DEV_OUT=path.win32.join(ROOT,"final4","development-only-owner-policies");
const I01_OUT=path.win32.join(ROOT,"final4","i01-only-owner-policies");

function publicKey(text:string):{pem:string;fingerprint:string}{
  if(Buffer.byteLength(text,"utf8")>4096)throw Error("bounded public key material only");
  const parsed=createPublicKey(text);
  if(parsed.asymmetricKeyType!=="ed25519")throw Error("independent owner/reviewer/witness Ed25519 public key required");
  return{
    pem:parsed.export({type:"spki",format:"pem"}).toString(),
    fingerprint:sha256(parsed.export({type:"spki",format:"der"})),
  };
}
function requireFile(filename:string):string{
  if(!path.win32.isAbsolute(filename)||filename.toLowerCase().includes("\\v2\\")||
    filename.includes(".."))throw Error("owner-selected absolute public-key path required");
  return filename;
}
type P03TrustedRow={identity_json:string;device_public_key_pem:string;tailscale_node_hash:string};
function trusted(registry:SqliteDeviceRegistry,id:"macbook-main"|"windows-main"){
  const descriptor=registry.require(id);
  if(descriptor.trustState!=="trusted")throw Error("real device is not P03 owner-attested: "+id);
  const row=registry.db.prepare(
    "SELECT identity_json,device_public_key_pem,tailscale_node_hash "+
    "FROM v3_p03_trusted_identities WHERE device_id=?"
  ).get(id) as P03TrustedRow|undefined;
  if(!row||!HASH.safeParse(row.tailscale_node_hash).success)
    throw Error("physical P03 device public-key/tailnet binding missing: "+id);
  const identity=z.object({
    deviceId:z.literal(id),
    agentInstanceId:z.string().uuid(),
    publicKeyFingerprint:HASH,
  }).passthrough().parse(JSON.parse(row.identity_json));
  if(publicKey(row.device_public_key_pem).fingerprint!==identity.publicKeyFingerprint)
    throw Error("physical dual-signed P03 device key changed: "+id);
  return {identity,tailnet:row.tailscale_node_hash,descriptor};
}

if(process.platform!=="win32"||os.hostname().toLowerCase()!=="laptop-13qineif"||
  os.userInfo().username.toLowerCase()!=="radlina"||
  process.argv.length!==4||!["--prepare","--prepare-i01","--prepare-development"].includes(process.argv[2]??"")||
  !path.win32.isAbsolute(process.argv[3]??"")){
  throw Error("manual interactive Windows V3 owner --prepare, --prepare-i01 or --prepare-development <absolute-input.json> required");
}
const inputFile=requireFile(process.argv[3]!);
const bytes=await readFile(inputFile);
if(bytes.byteLength>16384)throw Error("bounded V3 owner input document required");
const input=inputSchema.parse(JSON.parse(bytes.toString("utf8")));
const mode=resolveFinalFourProvisionMode(process.argv[2]!,input.independentReviewerPublicKeyFile);
const outputRoot=mode.name==="i01"?I01_OUT:mode.deployable?OUT:DEV_OUT;
if(input.allowedCapabilities[0]!=="device.health"||
  new Set(input.allowedCapabilities).size!==input.allowedCapabilities.length||
  new Set(input.authorizedChatGPTClientIds).size!==input.authorizedChatGPTClientIds.length||
  new Set(input.approvedSourceDeviceIds).size!==input.approvedSourceDeviceIds.length){
  throw Error("owner signed Mac and ChatGPT source capability scope must be explicit and unique");
}
const now=Date.now(),expires=Date.parse(input.expiresAt);
if(expires<=now||expires-now>30*24*60*60*1000){
  throw Error("V3 signed owner capability policy must expire within 30 days");
}
const signer=await V3WindowsProtectedOwnerSigner.open();
const owner=publicKey(signer.publicKeyPem);
const reviewer=mode.name==="production"
  ? publicKey(await readFile(requireFile(input.independentReviewerPublicKeyFile!),"utf8"))
  : undefined;
const witness=publicKey(await readFile(requireFile(input.s03WitnessPublicKeyFile),"utf8"));
if(owner.fingerprint===witness.fingerprint||
  (reviewer!==undefined&&(owner.fingerprint===reviewer.fingerprint||
    witness.fingerprint===reviewer.fingerprint))){
  throw Error("P03 owner, final reviewer and physical Mac S03 witness keys must differ");
}
const registry=new SqliteDeviceRegistry(path.win32.join(ROOT,"v3-devices.sqlite3"));
let windows,mac;
try{
  windows=trusted(registry,"windows-main");
  mac=trusted(registry,"macbook-main");
}finally{registry.close();}
const capabilityPolicy={
  schema:"radlina.v3.i01.macos-physical-operator-policy/v1" as const,
  macDeviceId:"macbook-main" as const,
  controllerDeviceId:"windows-main" as const,
  macPublicKeyFingerprint:mac.identity.publicKeyFingerprint,
  ownerPublicKeyPem:owner.pem,
  windowsTailnetNodeHash:windows.tailnet,
  allowedCapabilities:input.allowedCapabilities,
  createdAt:new Date(now).toISOString(),
  expiresAt:input.expiresAt,
  approvalMode:"interactive-target-local" as const,
};
const signature=signer.signCanonical(canonicalJson(capabilityPolicy));
const signedMacPolicy={policy:capabilityPolicy,ownerSignatureBase64:signature};
const chatGPTPolicy={
  schema:"radlina.v3.native-chatgpt-owner-binding/v1",
  authorizedClientIds:input.authorizedChatGPTClientIds,
  ownerSubject:input.ownerSubject,
  ownerKeyFingerprint:owner.fingerprint,
  ownerPublicKeyPem:owner.pem,
  windowsDeviceKeyFingerprint:windows.identity.publicKeyFingerprint,
  macDeviceKeyFingerprint:mac.identity.publicKeyFingerprint,
  authorizedSourceDeviceIds:input.approvedSourceDeviceIds,
  allowedCapabilities:input.allowedCapabilities,
  ownerApprovedAt:new Date(now).toISOString(),
};
const chatPolicyPath=path.win32.join(outputRoot,"native-chatgpt-owner.json");
const macPolicyPath=path.win32.join(outputRoot,"mac-operator-signed.json");
const physicalConfigPath=path.win32.join(outputRoot,"final4-binding.json");
const macWitnessPolicyPath=path.win32.join(outputRoot,"mac-s03-witness-policy.json");
const macWitnessPolicy={
  schema:"radlina.v3.s03.witness-pins/v1" as const,
  ownerPublicKeyPem:owner.pem,
  ownerKeyFingerprint:owner.fingerprint,
  physicalDevices:{
    "windows-main":{
      publicKeyFingerprint:windows.identity.publicKeyFingerprint,
      agentInstanceId:windows.identity.agentInstanceId,
    },
    "macbook-main":{
      publicKeyFingerprint:mac.identity.publicKeyFingerprint,
      agentInstanceId:mac.identity.agentInstanceId,
    },
  },
};
const chatJSON=canonicalJson(chatGPTPolicy);
const config={
  schema:mode.schema,
  ownerOAuthClientPolicyPath:chatPolicyPath,
  ownerOAuthClientPolicyHash:sha256(chatJSON+"\n"),
  windowsDeviceFingerprint:windows.identity.publicKeyFingerprint,
  macDeviceFingerprint:mac.identity.publicKeyFingerprint,
  macTailnetNodeHash:mac.tailnet,
  windowsTailnetNodeHash:windows.tailnet,
  ownerPublicKeyPem:owner.pem,
  ...(reviewer?{independentReviewerPublicKeyPem:reviewer.pem}:
    mode.name==="i01"?{i01Only:true as const}:{
      developmentOnly:true as const,
      productionActivationPermitted:false as const,
      gateAcceptancePermitted:false as const,
    }),
  s03:{
    endpoint:"https://v3-audit.radlina.com/api/v1/anchor" as const,
    witnessPublicKeyPem:witness.pem,
    witnessFingerprint:witness.fingerprint,
  },
};
await mkdir(outputRoot,{recursive:true});
for(const [file,data] of [
  [chatPolicyPath,chatJSON],
  [macPolicyPath,canonicalJson(signedMacPolicy)],
  [physicalConfigPath,canonicalJson(config)],
  [macWitnessPolicyPath,canonicalJson(macWitnessPolicy)],
] as const){
  await writeFile(file,data+"\n",{flag:"wx",encoding:"utf8"});
}
process.stdout.write(JSON.stringify({
  result:mode.name==="i01"
    ?"V3_I01_ONLY_REAL_OWNER_PUBLIC_PIN_POLICIES_PREPARED"
    :mode.deployable
      ?"V3_FINAL4_REAL_OWNER_PUBLIC_PIN_POLICIES_PREPARED"
      :"V3_FINAL4_DEVELOPMENT_ONLY_PUBLIC_POLICIES_PREPARED_NOT_DEPLOYABLE",
  mode:mode.name,
  productionDeploymentAllowed:mode.deployable,
  paths:{
    nativeChatGPT:chatPolicyPath,
    macOperator:macPolicyPath,
    finalFourConfig:physicalConfigPath,
    macIndependentWitness:macWitnessPolicyPath,
  },
  sha256:{
    nativeChatGPT:sha256(chatJSON+"\n"),
    macOperator:sha256(canonicalJson(signedMacPolicy)+"\n"),
    finalFourConfig:sha256(canonicalJson(config)+"\n"),
    macIndependentWitness:sha256(canonicalJson(macWitnessPolicy)+"\n"),
  },
  ownerKeyUnchanged:true,macKeyUnchanged:true,
  reviewerKeyIsExternal:reviewer!==undefined,notDeployed:true,
})+"\n");
