/**
 * Separate physical Mac S03 witness HTTP service. TLS is terminated by the
 * independently provisioned v3-audit.radlina.com secure ingress; THIS process
 * binds only 127.0.0.1 and never accepts commands to execute on macOS.
 *
 * No tests, deployments or network side effects occur unless launched by the
 * explicitly installed per-user V3-only witness LaunchAgent.
 */
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import express from "express";
import * as z from "zod/v4";

import { sha256 } from "../../src/utils/json.js";
import { openMacKeychainS03WitnessSigner } from "../../src/v3/audit/s03-macos-signer.js";
import { S03MacIndependentWitnessJournal } from "../../src/v3/audit/s03-mac-witness.js";
import { S03AuthenticatedMacWireService } from "../../src/v3/audit/s03-mac-wire.js";

const POLICY_PATH=process.env["RADLINA_V3_S03_WITNESS_POLICY_PATH"];
const POLICY_SHA=process.env["RADLINA_V3_S03_WITNESS_POLICY_SHA256"];
const TOKEN_FILE=process.env["RADLINA_V3_S03_WRITER_TOKEN_FILE"];
const HMAC_FILE=process.env["RADLINA_V3_S03_HMAC_KEY_FILE"];
const MAC_HOST="amirs-MacBook-Pro.local";
async function privateFile(file:string,limit:number):Promise<Buffer>{
  if(!path.isAbsolute(file)||file.toLowerCase().includes("v2")){
    throw new Error("S03 Mac witness requires an absolute V3-only private file");
  }
  const metadata=await stat(file);
  if(!metadata.isFile()||metadata.isSymbolicLink()||(metadata.mode&0o077)!==0||
    metadata.size>limit||metadata.size<16){
    throw new Error("S03 witness private 0600 file and bounded content required");
  }
  return await readFile(file);
}
if(process.platform!=="darwin"||os.arch()!=="x64"||
  os.hostname()!==MAC_HOST||os.userInfo().username!=="amirsheikhzadeh"||
  process.env["RADLINA_V3_S03_WITNESS_MODE"]!=="isolated-macos"||
  !POLICY_PATH||!POLICY_SHA||!TOKEN_FILE||!HMAC_FILE||
  !/^[a-f0-9]{64}$/u.test(POLICY_SHA)){
  throw new Error("exact physical Mac owner-approved separate S03 V3 service required");
}
process.umask(0o077);
const policyBytes=await privateFile(POLICY_PATH,16*1024);
if(sha256(policyBytes)!==POLICY_SHA)
  throw new Error("S03 owner-approved trust policy fingerprint mismatch");
const policy=z.object({
  schema:z.literal("radlina.v3.s03.witness-pins/v1"),
  ownerPublicKeyPem:z.string().includes("BEGIN PUBLIC KEY").max(4096),
  ownerKeyFingerprint:z.string().regex(/^[a-f0-9]{64}$/u),
  physicalDevices:z.object({
    "windows-main":z.object({
      publicKeyFingerprint:z.string().regex(/^[a-f0-9]{64}$/u),
      agentInstanceId:z.string().uuid(),
    }).strict(),
    "macbook-main":z.object({
      publicKeyFingerprint:z.string().regex(/^[a-f0-9]{64}$/u),
      agentInstanceId:z.string().uuid(),
    }).strict(),
  }).strict(),
}).strict().parse(JSON.parse(policyBytes.toString("utf8")));
const bearerBytes=await privateFile(TOKEN_FILE,4096);
const token=bearerBytes.toString("utf8").trim();
const hmacBytes=await privateFile(HMAC_FILE,4096);
const hmac=Buffer.from(hmacBytes.toString("utf8").trim(),"base64");
hmacBytes.fill(0);
if(token.length<32||token.length>512||hmac.length<32||hmac.length>128){
  hmac.fill(0);
  throw new Error("independent S03 writer credentials must be pre-provisioned securely");
}
const signer=await openMacKeychainS03WitnessSigner();
const state=path.join(os.homedir(),".local","share","radlina","v3-beta","macbook-main-s03");
const journal=new S03MacIndependentWitnessJournal(path.join(state,"external-audit.sqlite3"),signer,policy);
const wire=new S03AuthenticatedMacWireService(journal,signer,token,hmac);
const app=express();
app.disable("x-powered-by");
app.use((_req,res,next)=>{
  res.setHeader("cache-control","no-store");
  res.setHeader("x-content-type-options","nosniff");
  next();
});
app.post("/api/v1/anchor",express.raw({
  type:"application/json",limit:"128kb",
}),async(request,response)=>{
  try{
    if(!Buffer.isBuffer(request.body)){
      response.status(415).json({error:"json_body_required"});return;
    }
    const result=await wire.accept(
      request.body,
      request.get("authorization")??"",
      request.get("x-radlina-s03-hmac")??"",
      request.get("idempotency-key")??"",
    );
    response.status(201).json(result);
  }catch{
    response.status(403).json({error:"mac_witness_signed_receipt_denied"});
  }
});
// Authenticated retrieval ONLY; never invokes witness.anchor() or modifies
// the independent Mac chain. A lost POST ACK is reconciled by request hash.
app.post("/api/v1/anchor/lookup",express.raw({
  type:"application/json",limit:"128kb",
}),async(request,response)=>{
  try{
    if(!Buffer.isBuffer(request.body)){
      response.status(415).json({error:"json_body_required"});return;
    }
    const found=wire.lookup(request.body,
      request.get("authorization")??"",
      request.get("x-radlina-s03-hmac")??"",
      request.get("idempotency-key")??"",
    );
    if(!found){response.status(404).json({error:"original_signed_witness_ack_not_found"});return;}
    response.status(200).json(found);
  }catch{response.status(403).json({error:"mac_witness_lookup_denied"});}
});
app.use((_req,res)=>res.status(404).json({error:"not_found"}));
const server=createServer(app);
server.listen(7444,"127.0.0.1");
await new Promise<void>((resolve,reject)=>{
  server.once("listening",resolve);
  server.once("error",reject);
});
process.stdout.write(JSON.stringify({
  generation:"v3",
  role:"physical-macos-independent-s03-witness",
  localHost:"127.0.0.1",
  port:7444,
  expectedSecureIngress:"https://v3-audit.radlina.com/api/v1/anchor",
  remoteExecutionEnabled:false,
  keychainSigningKeyExported:false,
  v2Untouched:true,
})+"\n");
let stopping=false;
const stop=()=>{
  if(stopping)return;
  stopping=true;
  server.close(()=>{journal.close();hmac.fill(0);});
};
process.once("SIGINT",stop);
process.once("SIGTERM",stop);
