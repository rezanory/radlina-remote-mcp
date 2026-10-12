/**
 * Exact-owner Windows DPAPI CurrentUser signing. Never accessible to LocalSystem.
 * Private Ed25519 material does not leave a logged-in owner session.
 * Only explicitly named V3 operation/policy schemas may be signed.
 */
import { execFile as execCallback } from "node:child_process";
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import * as z from "zod/v4";
import { canonicalJson, sha256 } from "../../utils/json.js";
import { i01ExactOperationSchema } from "../integration/i01-secured-dispatch.js";
import { f01ExactFleetCommandSchema } from "../fleet/physical-adapters.js";

const run=promisify(execCallback);
const expectedPin="6259d21211f73fc9d2d7cc0174d9bfdc36424cd456878671ab5683468ca0fe93";
const ownerFile="C:\\Users\\Radlina\\AppData\\Local\\Radlina\\V3\\owner-signing\\owner.dpapi.json";
const storedSchema=z.object({
  schema:z.literal("radlina.v3.owner-current-user-key/v1"),
  ownerPrincipal:z.literal("laptop-13qineif\\radlina"),
  ownerSid:z.literal("S-1-5-21-827254616-2815314212-688626134-1001"),
  keyId:z.string().uuid(),
  publicKeyPem:z.string().includes("BEGIN PUBLIC KEY").max(4096),
  fingerprint:z.literal(expectedPin),
  protectedPrivateKey:z.string().min(100).max(16000),
}).strict();
export class V3ProtectedOwnerDenied extends Error {
  constructor(msg:string){super(msg);this.name="V3ProtectedOwnerDenied";}
}
async function dpapiCurrentUser(protectedKey:string):Promise<Buffer>{
  const script=[
    "$ErrorActionPreference='Stop'",
    "Add-Type -AssemblyName System.Security",
    "$value=[Convert]::FromBase64String([Console]::In.ReadToEnd())",
    "$out=[Security.Cryptography.ProtectedData]::Unprotect($value,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)",
    "[Console]::Out.Write([Convert]::ToBase64String($out))",
  ].join(";");
  const {spawn}=await import("node:child_process");
  return await new Promise<Buffer>((resolve,reject)=>{
    const child=spawn("powershell.exe",["-NoProfile","-NonInteractive","-Command",script],{
      windowsHide:true,stdio:["pipe","pipe","ignore"],
    });
    const chunks:Buffer[]=[];
    child.stdout.on("data",(c:Buffer)=>chunks.push(c));
    child.once("error",reject);
    child.once("close",code=>{
      if(code!==0){reject(new V3ProtectedOwnerDenied("owner CurrentUser DPAPI denied"));return;}
      resolve(Buffer.from(Buffer.concat(chunks).toString("utf8"),"base64"));
    });
    child.stdin.end(protectedKey);
  });
}
export class V3WindowsProtectedOwnerSigner {
  static async open():Promise<V3WindowsProtectedOwnerSigner>{
    if(process.platform!=="win32"||os.hostname().toLowerCase()!=="laptop-13qineif"||
      os.userInfo().username.toLowerCase()!=="radlina"){
      throw new V3ProtectedOwnerDenied("interactive enrolled Windows owner required");
    }
    const {stdout:user}=await run("whoami.exe",[],{timeout:8000,maxBuffer:2048});
    if(user.trim().toLowerCase()!=="laptop-13qineif\\radlina")
      throw new V3ProtectedOwnerDenied("Windows SYSTEM/runner is not the owner");
    const data=storedSchema.parse(JSON.parse(await readFile(ownerFile,"utf8")));
    const info=await stat(ownerFile);
    if(!info.isFile()||sha256(createPublicKey(data.publicKeyPem).export({
      type:"spki",format:"der",
    }))!==expectedPin)throw new V3ProtectedOwnerDenied("owner pinned public key changed");
    const raw=await dpapiCurrentUser(data.protectedPrivateKey);
    try{
      const key=createPrivateKey({key:raw,format:"der",type:"pkcs8"});
      if(key.asymmetricKeyType!=="ed25519"||
        createPublicKey(key).export({type:"spki",format:"pem"}).toString()!==data.publicKeyPem){
        throw new V3ProtectedOwnerDenied("owner protected private key does not match independent pin");
      }
      return new V3WindowsProtectedOwnerSigner(data.publicKeyPem,key);
    }finally{raw.fill(0);}
  }
  private constructor(
    readonly publicKeyPem:string,
    private readonly key:ReturnType<typeof createPrivateKey>,
  ){}
  signCanonical(message:string):string {
    if(Buffer.byteLength(message,"utf8")>256*1024)
      throw new V3ProtectedOwnerDenied("bounded owner operation required");
    const parsed:unknown=JSON.parse(message);
    if(!parsed||typeof parsed!=="object"||canonicalJson(parsed)!==message)
      throw new V3ProtectedOwnerDenied("owner must sign canonical JSON only");
    const value=parsed as Record<string,unknown>;
    switch(value["schema"]){
      case "radlina.v3.i01.exact-device-dispatch/v1":{
        const op=i01ExactOperationSchema.parse(value);
        if(op.expiresAtMs<=Date.now()||op.expiresAtMs-op.issuedAtMs>120000)
          throw new V3ProtectedOwnerDenied("owner I01 operation expired or unbounded");
        break;
      }
      case "radlina.v3.f01.exact-fleet-operation/v1":{
        const op=f01ExactFleetCommandSchema.parse(value);
        if(op.expiresAtMs<=Date.now()||op.expiresAtMs-op.issuedAtMs>90000)
          throw new V3ProtectedOwnerDenied("owner F01 release operation expired");
        break;
      }
      case "radlina.v3.i01.windows-local-user-decision/v1":{
        const signed=z.object({
          schema:z.literal("radlina.v3.i01.windows-local-user-decision/v1"),
          requestId:z.string().uuid(),
          promptHash:z.string().regex(/^[a-f0-9]{64}$/u),
          targetDeviceId:z.literal("windows-main"),
          sourceDeviceId:z.literal("macbook-main"),
          decision:z.enum(["approve","deny"]),
          nonce:z.string().uuid(),
          issuedAtMs:z.number().int().positive(),
          expiresAtMs:z.number().int().positive(),
        }).strict().parse(value);
        if(signed.issuedAtMs>Date.now()||signed.expiresAtMs<=Date.now()||
          signed.expiresAtMs-signed.issuedAtMs>120000){
          throw new V3ProtectedOwnerDenied("Windows local user decision expired or unbounded");
        }
        break;
      }
      case "radlina.v3.i01.macos-physical-operator-policy/v1":{
        const policy=z.object({
          schema:z.literal("radlina.v3.i01.macos-physical-operator-policy/v1"),
          macDeviceId:z.literal("macbook-main"),
          controllerDeviceId:z.literal("windows-main"),
          ownerPublicKeyPem:z.literal(this.publicKeyPem),
          macPublicKeyFingerprint:z.string().regex(/^[0-9a-f]{64}$/u),
          windowsTailnetNodeHash:z.string().regex(/^[0-9a-f]{64}$/u),
          allowedCapabilities:z.array(z.enum(["device.health","filesystem.read","filesystem.write"])).max(3),
          createdAt:z.string().datetime({offset:true}),
          expiresAt:z.string().datetime({offset:true}),
          approvalMode:z.literal("interactive-target-local"),
        }).strict().parse(value);
        if(Date.parse(policy.expiresAt)<=Date.now()||
          Date.parse(policy.expiresAt)-Date.parse(policy.createdAt)>30*24*60*60*1000){
          throw new V3ProtectedOwnerDenied("owner Mac policy TTL invalid");
        }
        break;
      }
      default: throw new V3ProtectedOwnerDenied("owner key is restricted to declared V3 schemas");
    }
    const signature=sign(null,Buffer.from(message,"utf8"),this.key).toString("base64");
    if(!verify(null,Buffer.from(message,"utf8"),createPublicKey(this.publicKeyPem),
      Buffer.from(signature,"base64"))){
      throw new V3ProtectedOwnerDenied("protected owner signer self-verification failed");
    }
    return signature;
  }
}
