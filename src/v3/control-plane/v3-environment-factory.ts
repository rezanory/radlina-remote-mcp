/**
 * Single production final-four activation factory for the existing V3 gateway.
 * Only accepts machine-DPAPI protected secret FILES and owner-pinned public
 * identity FILES, never bearer/HMAC secret values from WinSW XML/environment.
 * No side effects occur before the opt-in V3 gateway startup.
 */
import { readFile } from "node:fs/promises";
import { createPublicKey } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { unprotectBytes } from "../../auth/dpapi.js";
import { sha256 } from "../../utils/json.js";
import { requireOwnerApprovedMacOperatorPolicy } from "../device/p08-mac-operator-policy.js";
import {
  createV3FinalFourPhysicalComposition,
  type V3FinalFourBindingConfig,
} from "../integration/final4-physical-bootstrap.js";
import type {
  V3FinalFourFactoryContext,
  V3ComposedPhysicalFinalFour,
} from "./v3-physical-final4-runtime.js";

const HASH=/^[0-9a-f]{64}$/u;
function requiredEnv(name:string):string {
  const value=process.env[name];
  if(!value||value.length>4096||value.includes("\0")) {
    throw new Error("V3 final-four configuration not provided: "+name);
  }
  return value;
}
function boundedHash(name:string):string {
  const value=requiredEnv(name);
  if(!HASH.test(value))throw new Error("V3 final-four pinned SHA256 invalid: "+name);
  return value;
}
function absolutePrivateFile(name:string):string {
  const value=requiredEnv(name);
  if(!path.win32.isAbsolute(value)||value.toLowerCase().includes("\\v2\\")||
    value.includes("..")||value.includes("\r")||value.includes("\n")) {
    throw new Error("absolute isolated V3 secret file path required: "+name);
  }
  return value;
}
async function privateSecret(name:string,expected:"utf8"|"dpapi",limit:number):Promise<Buffer>{
  const value=await readFile(absolutePrivateFile(name));
  if(!value.length||value.length>limit)throw new Error("bounded V3 secret file missing: "+name);
  if(expected==="utf8") {
    const raw=Buffer.from(value.toString("utf8").trim(),"utf8");
    value.fill(0);
    if(raw.length<32||raw.length>512) {
      raw.fill(0);
      throw new Error("independent S03 bearer secret is invalid");
    }
    return raw;
  }
  const encoded=value.toString("utf8").trim();
  value.fill(0);
  const raw=await unprotectBytes(encoded);
  if(raw.length<32||raw.length>128){
    raw.fill(0);
    throw new Error("V3 machine-protected HMAC key strength invalid");
  }
  return raw;
}

/**
 * Factory is not registered by default. The V3 daemon must explicitly set
 * RADLINA_V3_FINAL4_ENABLE=1 and provide every credential path and public pin.
 */
export function finalFourFactoryFromOwnerEnvironment():
  (context:V3FinalFourFactoryContext)=>Promise<V3ComposedPhysicalFinalFour> {
  if(process.platform!=="win32"||
    os.hostname().toLowerCase()!=="laptop-13qineif"||
    process.env["RADLINA_V3_FINAL4_ENABLE"]!=="1"||
    process.env["RADLINA_V3_MAC_SIGNED_HEARTBEAT_ENABLED"]!=="1"||
    process.env["RADLINA_V3_PUBLIC_URL"]!=="https://v3-mcp.radlina.com") {
    throw new Error("physical independent V3 final-four bootstrap is disabled");
  }
  const binding=absolutePrivateFile("RADLINA_V3_FINAL4_CONFIG_PATH");
  const bindingHash=boundedHash("RADLINA_V3_FINAL4_CONFIG_SHA256");
  const signedPolicyPath=absolutePrivateFile("RADLINA_V3_SIGNED_MAC_OPERATOR_POLICY_PATH");
  const macPolicyHash=boundedHash("RADLINA_V3_SIGNED_MAC_OPERATOR_POLICY_SHA256");
  return async context=>{
    if(context.config.server.publicUrl!=="https://v3-mcp.radlina.com"||
      context.config.server.host!=="127.0.0.1"||
      !path.win32.isAbsolute(context.stateRoot)||
      !context.stateRoot.toLowerCase().startsWith("e:\\")) {
      throw new Error("V3 issuer, host and state isolation requirements not met");
    }
    // Resolve the one authoritative, owner-hashed binding BEFORE allocating
    // any physical relay or OAuth execution ports. The lower-level bootstrap
    // performs the complete strict schema validation of this same byte stream.
    const bindingBytes=await readFile(binding);
    if(!bindingBytes.length||bindingBytes.length>32768||
      sha256(bindingBytes)!==bindingHash){
      throw new Error("immutable final-four physical binding hash mismatch");
    }
    const approvedBinding=JSON.parse(bindingBytes.toString("utf8")) as V3FinalFourBindingConfig;
    if(approvedBinding.schema!=="radlina.v3.final-four-production-binding/v1"&&
      approvedBinding.schema!=="radlina.v3.i01-production-binding/v1"){
      throw new Error("unexpected physical production binding contract");
    }
    // Schema and owner-pinned SHA are both revalidated at the sole physical
    // constructor. A development-only binding is never a live I01 binding.
    const bytes=await readFile(signedPolicyPath);
    if(!bytes.length||bytes.length>16384||sha256(bytes)!==macPolicyHash)
      throw new Error("explicit owner-approved Mac capability policy hash changed");
    const signedMacPolicy=requireOwnerApprovedMacOperatorPolicy(
      JSON.parse(bytes.toString("utf8")),
    );
    const fingerprint=(publicPem:string)=>sha256(
      createPublicKey(publicPem).export({type:"spki",format:"der"}),
    );
    if(approvedBinding.macDeviceFingerprint!==signedMacPolicy.macPublicKeyFingerprint||
      approvedBinding.windowsTailnetNodeHash!==signedMacPolicy.windowsTailnetNodeHash||
      fingerprint(approvedBinding.ownerPublicKeyPem)!==fingerprint(signedMacPolicy.ownerPublicKeyPem)||
      approvedBinding.ownerOAuthClientPolicyPath.toLowerCase().includes("\\v2\\")||
      !path.win32.isAbsolute(approvedBinding.ownerOAuthClientPolicyPath)){
      throw new Error("Mac, owner, Tailnet and native ChatGPT binding are not one signed trust domain");
    }
    const token=await privateSecret("RADLINA_V3_S03_WRITER_TOKEN_FILE","utf8",2048);
    const hmac=await privateSecret("RADLINA_V3_S03_HMAC_DPAPI_FILE","dpapi",4096);
    try{
      const composition=createV3FinalFourPhysicalComposition({
        configPath:binding,
        configFileSha256:bindingHash,
        stateDirectory:context.stateRoot,
        registry:context.registry,
        signedMacPolicy,
        s03WriterToken:token.toString("utf8"),
        s03HmacKeyBase64:hmac.toString("base64"),
      });
      return{
        finalFour:composition.finalFour,
        physicalRelay:composition.relay,
        close:async()=>composition.close(),
      };
    }finally{
      token.fill(0);
      hmac.fill(0);
    }
  };
}
