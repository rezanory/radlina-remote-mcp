/**
 * Independent V3 S03 Mac Keychain witness bootstrap. This is a DIFFERENT
 * Ed25519 key from P03 macbook-main; only the public fingerprint is exported.
 * The audit key is durable, never printed or transmitted.
 */
import { execFile as callback } from "node:child_process";
import { readFile, stat, mkdir } from "node:fs/promises";
import { createPublicKey } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { sha256 } from "../../utils/json.js";
import { MacOSKeychainSecretProtector } from "../device/macos-agent.js";
import { MacOSDeviceIdentityStore } from "../device/macos-identity.js";
import type { S03WitnessSigningKey } from "./s03-mac-witness.js";

const execFile=promisify(callback);
async function privateFile(file:string):Promise<void>{
  const info=await stat(file);
  if(!info.isFile()||info.isSymbolicLink()||(info.mode&0o077)!==0){
    throw Error("S03 cannot access nonprivate Mac Keychain file");
  }
}
export async function openMacKeychainS03WitnessSigner():Promise<S03WitnessSigningKey>{
  if(process.platform!=="darwin"||os.hostname()!=="amirs-MacBook-Pro.local"||
    os.userInfo().username!=="amirsheikhzadeh"||
    process.env["RADLINA_V3_S03_WITNESS_MODE"]!=="isolated-macos"){
    throw Error("S03 independent physical macOS signer permission required");
  }
  const state=path.join(os.homedir(),".local","share","radlina","v3-beta","macbook-main-runner");
  const keychainFile=path.join(state,"v3-device.keychain-db");
  const passwordFile=path.join(state,"keychain-password.local");
  await privateFile(keychainFile);await privateFile(passwordFile);
  const password=(await readFile(passwordFile,"utf8")).trim();
  if(password.length<40||password.length>200)
    throw Error("Mac dedicated Keychain password metadata invalid");
  async function security(args:string[]){
    try{
      const {stdout}=await execFile("/usr/bin/security",args,{
        timeout:15000,maxBuffer:64*1024,
      });
      return stdout.trim();
    }catch{throw Error("S03 Mac protected Keychain operation denied");}
  }
  await security(["unlock-keychain","-p",password,keychainFile]);
  const keychain=new MacOSKeychainSecretProtector(
    "com.radlina.remote-mcp.v3.s03.external-witness",
    async(args)=>await security([...args,keychainFile]),
  );
  const privateState=path.join(os.homedir(),".local","share","radlina",
    "v3-beta","macbook-main-s03");
  await mkdir(privateState,{recursive:true,mode:0o700});
  const stateInfo=await stat(privateState);
  if(!stateInfo.isDirectory()||(stateInfo.mode&0o077)!==0)
    throw Error("S03 persistent private state must be 0700");
  const witnessStateFile=path.join(privateState,"witness-identity.json");
  await privateFile(witnessStateFile); // Witness keys are provisioned explicitly, never on daemon startup.
  const identity=await new MacOSDeviceIdentityStore(
    witnessStateFile,keychain,
  ).ensure("macbook-main-s03","3.0.0-alpha.1");
  if(identity.state.deviceId!=="macbook-main-s03")
    throw Error("S03 identity is not its own independent Mac witness");
  const publicKeyPem=identity.state.publicKeyPem;
  const pinned=process.env["RADLINA_V3_S03_EXPECTED_WITNESS_KEY_FINGERPRINT"];
  const actual=sha256(createPublicKey(publicKeyPem).export({type:"spki",format:"der"}));
  if(!pinned||!/^([a-f0-9]{64})$/u.test(pinned)||pinned!==actual)
    throw Error("independent Mac S03 public witness key pin missing or changed");
  return{
    publicKeyPem,
    signCanonical:async(payload:string)=>{
      const obj:unknown=JSON.parse(payload);
      if(typeof obj!=="object"||!obj||
        !["radlina.v3.s03.external-anchor/v1","radlina.v3.s03.external-witness/v1"].includes(String((obj as Record<string,unknown>)["schema"]))||
        Buffer.byteLength(payload,"utf8")>4096){
        throw Error("Mac S03 signer only allows bounded external audit receipts");
      }
      return identity.signCanonical(obj);
    },
  };
}
