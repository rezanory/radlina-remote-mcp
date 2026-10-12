/**
 * Manually invoked one-time creation/reuse of a SEPARATE S03 Mac Keychain
 * witness identity; never rotates the already enrolled P03 macbook-main key.
 * Exports ONLY public PEM and SHA256 fingerprint for owner pinning.
 */
import { execFile as execCallback } from "node:child_process";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { MacOSKeychainSecretProtector } from "../../src/v3/device/macos-agent.js";
import { MacOSDeviceIdentityStore } from "../../src/v3/device/macos-identity.js";
import { canonicalJson } from "../../src/utils/json.js";

const run=promisify(execCallback);
if(process.argv.length!==3||process.argv[2]!=="--prepare"||
  process.platform!=="darwin"||os.arch()!=="x64"||
  os.hostname()!=="amirs-MacBook-Pro.local"||
  os.userInfo().username!=="amirsheikhzadeh"){
  throw Error("explicit physical Mac S03 Keychain public identity preparation required");
}
const p03Root=path.join(os.homedir(),".local","share","radlina","v3-beta","macbook-main-runner");
const witness=path.join(os.homedir(),".local","share","radlina","v3-beta","macbook-main-s03");
const keychainFile=path.join(p03Root,"v3-device.keychain-db");
const passwordFile=path.join(p03Root,"keychain-password.local");
for(const filename of [keychainFile,passwordFile]){
  const metadata=await stat(filename);
  if(!metadata.isFile()||metadata.isSymbolicLink()||(metadata.mode&0o077)!==0)
    throw Error("existing dedicated Mac V3 Keychain must be private 0600");
}
process.umask(0o077);
await mkdir(witness,{recursive:true,mode:0o700});
const status=await stat(witness);
if(!status.isDirectory()||(status.mode&0o077)!==0)
  throw Error("S03 witness directory requires 0700");
const password=(await readFile(passwordFile,"utf8")).trim();
if(password.length<40||password.length>200)
  throw Error("existing Mac V3 Keychain unlock data invalid");
async function security(args:string[]):Promise<string>{
  try{
    const {stdout}=await run("/usr/bin/security",args,{timeout:15000,maxBuffer:65536});
    return stdout.trim();
  }catch{throw Error("dedicated Mac V3 Keychain operation unavailable");}
}
await security(["unlock-keychain","-p",password,keychainFile]);
const keychain=new MacOSKeychainSecretProtector(
  "com.radlina.remote-mcp.v3.s03.external-witness",
  async(args)=>await security([...args,keychainFile]),
);
const stateFile=path.join(witness,"witness-identity.json");
const identity=await new MacOSDeviceIdentityStore(stateFile,keychain)
  .ensure("macbook-main-s03","3.0.0-alpha.1");
if(identity.state.deviceId!=="macbook-main-s03")
  throw Error("independent Mac S03 witness identity mismatch");
const pem=path.join(witness,"witness-public.pem");
try{
  const existing=await readFile(pem,"utf8");
  if(existing!==identity.state.publicKeyPem)
    throw Error("existing S03 public-key pin differs; manual reconciliation required");
}catch(error){
  if(!(error instanceof Error)||!("code" in error)||error.code!=="ENOENT")throw error;
  await writeFile(pem,identity.state.publicKeyPem,{flag:"wx",mode:0o600});
}
const publicReceipt=path.join(witness,"witness-public-receipt.json");
const proof=canonicalJson({
  schema:"radlina.v3.s03.mac-public-key-preparation/v1",
  deviceId:identity.state.deviceId,
  agentInstanceId:identity.state.agentInstanceId,
  publicKeyPem:identity.state.publicKeyPem,
  fingerprint:identity.state.publicKeyFingerprint,
  keychainPrivateKeyExported:false,
})+"\n";
try{
  const existing=await readFile(publicReceipt,"utf8");
  if(existing!==proof)throw Error("S03 public receipt changed; no implicit overwrite");
}catch(error){
  if(!(error instanceof Error)||!("code" in error)||error.code!=="ENOENT")throw error;
  await writeFile(publicReceipt,proof,{flag:"wx",mode:0o600});
}
process.stdout.write(JSON.stringify({
  status:"INDEPENDENT_S03_MAC_PUBLIC_KEY_PREPARED",
  publicKeyPath:pem,publicReceiptPath:publicReceipt,
  fingerprint:identity.state.publicKeyFingerprint,
  privateKeyStoredInMacKeychain:true,
  macbookMainP03KeyUnchanged:true,
})+"\n");
