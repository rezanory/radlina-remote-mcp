/**
 * Explicit V3-only Windows package completion: make the validated source
 * release self-contained (dist/scripts + runtime node_modules) WITHOUT
 * changing any service, task, V2 component, VPN, or physical device.
 *
 * This artifact is Windows-only. Mac must independently prepare and prove
 * runtime dependency compatibility before a two-device F01 rollout.
 */
import {createHash,randomUUID} from "node:crypto";
import {createReadStream} from "node:fs";
import {cp,lstat,mkdir,readFile,readdir,rename,stat,writeFile} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {verifyReleaseRoot,type ReleaseFile,type ReleaseManifest} from "../../src/admin/release-manifest.js";

const DIGEST=/^[a-f0-9]{64}$/u;
const BASE="E:\\radlina-v3-runtime";
const SNAPSHOT="E:\\radlina-remote-mcp-worktrees\\v3-stage2-release-20261012";
function deny(message:string):never{throw Error("V3_STAGE2_PREPARE_DENIED: "+message);}
const args=process.argv.slice(2);
const resume=args.length===4&&args[0]==="--resume";
if(process.platform!=="win32"||os.hostname().toLowerCase()!=="laptop-13qineif"||
  !(resume||(args.length===3&&args[0]==="--prepare")))
  deny("explicit physical Windows stage preparation or bounded resume required");
const candidate=args[1]!,approvedHash=args[2]!;
if(candidate!==path.win32.join(BASE,"stage2-candidate-dd9727d")||
  !DIGEST.test(approvedHash))deny("exact owner-approved staging candidate required");
const candidateInfo=await lstat(candidate);
if(!candidateInfo.isDirectory()||candidateInfo.isSymbolicLink())
  deny("candidate cannot be a symlink");
const valid=await verifyReleaseRoot(candidate,approvedHash);
if(valid.manifest.source.gitSha!=="dd9727d2146fe4079b3709ad449c1ae497d02e92")
  deny("candidate does not bind original stage-one validated Git commit");
if(valid.manifest.files.length>20000)deny("unexpected large release manifest");
const distScripts=path.join(SNAPSHOT,"dist","scripts");
const moduleRoot=path.join(SNAPSHOT,"node_modules");
for(const folder of [distScripts,moduleRoot]){
  const s=await lstat(folder);
  if(!s.isDirectory()||s.isSymbolicLink())deny("required isolated runtime tree missing");
}
for(const required of [
  "operations/v3-oauth-readonly-daemon.js",
  "operations/v3-windows-operator-cycle.js",
  "operations/v3-windows-fleet-cycle.js",
  "operations/v3-owner-interactive-cycle.js",
]){
  const s=await lstat(path.join(distScripts,required));
  if(!s.isFile()||s.isSymbolicLink())deny("V3 compiled executable missing: "+required);
}
const temp=resume?args[3]!:path.join(BASE,"stage2-prepared-"+randomUUID());
if(resume){
  if(path.win32.dirname(temp).toLowerCase()!==BASE.toLowerCase()||
    !/^stage2-prepared-[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(path.basename(temp)))
    deny("resume must name one exact original V3-only staging folder");
  const existing=await lstat(temp);
  if(!existing.isDirectory()||existing.isSymbolicLink())deny("original incomplete V3 stage unavailable");
  const manifestBytes=await readFile(path.join(temp,"RELEASE_MANIFEST.json"));
  if(createHash("sha256").update(manifestBytes).digest("hex")!==approvedHash)
    deny("cannot resume a modified or newly signed partial release");
  for(const file of valid.manifest.files){
    const staged=path.join(temp,...file.path.split("/"));
    const s=await lstat(staged);
    if(!s.isFile()||s.isSymbolicLink()||s.size!==file.bytes||
      (await sha256File(staged))!==file.sha256)
      deny("resumed original source release evidence changed: "+file.path);
  }
  // Never delete or recopy already staged immutable data.
}else{
  await cp(candidate,temp,{recursive:true,force:false,errorOnExist:true,dereference:false});
}
const copyTrees=[
  {root:distScripts,target:"dist/scripts"},
  {root:moduleRoot,target:"node_modules"},
];
async function walk(folder:string,prefix:string):Promise<string[]>{
  const names=await readdir(folder,{withFileTypes:true});
  const out:string[]=[];
  for(const item of names){
    const relative=prefix+"/"+item.name;
    if(item.isSymbolicLink())deny("symlink prohibited in verified release: "+relative);
    if(item.isDirectory())out.push(...await walk(path.join(folder,item.name),relative));
    else if(item.isFile())out.push(relative);
    else deny("unsupported release entry: "+relative);
  }
  return out;
}
async function sha256File(name:string):Promise<string>{
  const h=createHash("sha256");
  for await(const chunk of createReadStream(name))h.update(chunk as Buffer);
  return h.digest("hex");
}
const newFiles:ReleaseFile[]=[];
for(const part of copyTrees){
  const all=await walk(part.root,part.target);
  if(all.length>20000)deny("individual runtime tree exceeds declared release limits");
  const dest=path.join(temp,...part.target.split("/"));
  await mkdir(path.dirname(dest),{recursive:true});
  if(resume){
    const staged=await walk(dest,part.target);
    const stagedSet=new Set(staged);
    if(staged.length!==all.length||all.some(relative=>!stagedSet.has(relative)))
      deny("resumed runtime tree file set does not match immutable source");
  }else{
    await cp(part.root,dest,{recursive:true,force:false,errorOnExist:true,dereference:false});
  }
  // Bounded I/O concurrency: a serialized 16k-file hash loop exceeded the
  // process deadline on the physical Windows HDD during initial staging.
  for(let pos=0;pos<all.length;pos+=24){
    const records=await Promise.all(all.slice(pos,pos+24).map(async(relative)=>{
      const filepath=path.join(temp,...relative.split("/"));
      const s=await stat(filepath);
      return {path:relative,bytes:s.size,sha256:await sha256File(filepath)};
    }));
    newFiles.push(...records);
  }
}
const original=valid.manifest;
const all=[...original.files,...newFiles].sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
if(all.length>=20000||new Set(all.map(f=>f.path.toLowerCase())).size!==all.length)
  deny("duplicate or excessive immutable V3 release files");
const output:ReleaseManifest={...original,files:all};
const bytes=JSON.stringify(output,null,2)+"\n";
const id=createHash("sha256").update(bytes).digest("hex");
await writeFile(path.join(temp,"RELEASE_MANIFEST.json"),bytes,{flag:"w"});
await verifyReleaseRoot(temp,id);
const release=path.join(BASE,"releases",id);
try{await lstat(release);deny("immutable V3 release directory already exists");}
catch(e){if((e as NodeJS.ErrnoException).code!=="ENOENT")throw e;}
await rename(temp,release);
process.stdout.write(JSON.stringify({
  status:"WINDOWS_RUNTIME_RELEASE_STAGED_NOT_INSTALLED",
  release,manifestSha256:id,sourceSha:original.source.gitSha,
  manifestFiles:all.length,agentEntrypointsIncluded:true,
  selfContainedWindowsDependencies:true,
  macCompatibilityVerified:false,serviceChanged:false,v2Changed:false,
})+"\n");
