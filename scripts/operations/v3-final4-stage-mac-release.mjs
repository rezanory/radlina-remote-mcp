/**
 * Mac-only V3 source-to-release preparation. No LaunchAgent, fleet, V2,
 * Tailnet, Keychain, owner policy, reviewer identity or native command change.
 * Every copy is hashed, and the complete macOS-native 17k-file release is
 * re-verified by the canonical strict release-manifest verifier.
 */
import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { cp, copyFile, lstat, mkdir, readFile, readdir, rename, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"../..");
const args=process.argv.slice(2);
const deny=(reason)=>{throw new Error("V3_MAC_RELEASE_STAGE_DENIED: "+reason)};
if(args.length!==2||args[0]!=="--prepare"||!/^[a-f0-9]{40}$/u.test(args[1]??"")||
   process.platform!=="darwin"||process.arch!=="x64"||
   os.hostname()!=="amirs-MacBook-Pro.local"||os.userInfo().username!=="amirsheikhzadeh")
  deny("explicit pinned real Mac owner-only release preparation required");
const pinned=args[1];
const getGit=(...argv)=>execFileSync("git",argv,{cwd:root,encoding:"utf8",timeout:15000}).trim();
if(getGit("rev-parse","HEAD")!==pinned||getGit("status","--porcelain"))
  deny("exact immutable clean Git source required");
process.umask(0o077);
const base=path.join(os.homedir(),".local","share","radlina","v3-beta","macbook-main-agent");
const baseStat=await lstat(base);
if(!baseStat.isDirectory()||baseStat.isSymbolicLink()||(baseStat.mode&0o077)!==0)
  deny("existing Mac V3-only 0700 owner-managed release root required");
const releaseDirectory=path.join(base,"releases");
await mkdir(releaseDirectory,{recursive:true,mode:0o700});
if((await lstat(releaseDirectory)).isSymbolicLink())deny("symlink release root forbidden");
const sourceCandidate=path.join(base,"stage2-candidate-"+pinned.slice(0,7));
const staging=path.join(base,"stage2-prepared-"+randomUUID());
for(const item of [sourceCandidate,staging]){
  try{await lstat(item);deny("immutable stage directory already exists: "+path.basename(item));}
  catch(error){if(error?.code!=="ENOENT")throw error;}
}
for(const folder of ["dist/src","dist/scripts","node_modules","scripts/operations"]){
  const statValue=await lstat(path.join(root,folder));
  if(!statValue.isDirectory()||statValue.isSymbolicLink())deny("missing verified build tree: "+folder);
}
for(const file of ["node_modules/tsx/dist/cli.mjs","dist/scripts/operations/v3-mac-operator-cycle.js",
  "dist/scripts/operations/v3-mac-fleet-cycle.js","dist/scripts/operations/v3-s03-mac-witness-daemon.js"]){
  const s=await lstat(path.join(root,file));
  if(!s.isFile()||s.isSymbolicLink())deny("missing required native Mac V3 entrypoint: "+file);
}
const {verifyReleaseRoot,validateReleaseRelativePath}=await import(
  pathToFileURL(path.join(root,"dist","src","admin","release-manifest.js")).href);
const evidence=path.join(root,"governance","v3","V3_PARALLEL_NO_MAC_DEVELOPMENT_RECEIPTS_20261012.md");
const build=execFileSync(process.execPath,[
  path.join(root,"scripts","operations","build-release.mjs"),
  "--output",sourceCandidate,"--evidence",evidence,
],{cwd:root,encoding:"utf8",timeout:270000,maxBuffer:100000});
const candidateInfo=JSON.parse(build.trim());
const original=await verifyReleaseRoot(sourceCandidate,candidateInfo.manifest);
if(original.manifest.source.gitSha!==pinned||original.manifest.files.length>20000)
  deny("original source snapshot does not match pinned Mac Git SHA");
await cp(sourceCandidate,staging,{recursive:true,force:false,errorOnExist:true,dereference:false});
const hash=async filename=>{
  const h=createHash("sha256");
  for await(const chunk of createReadStream(filename))h.update(chunk);
  return h.digest("hex");
};
async function walk(directory,prefix){
  const entries=await readdir(directory,{withFileTypes:true});
  const out=[];
  for(const item of entries){
    // npm creates command symlinks in .bin; these are unnecessary for runtime
    // because all LaunchAgents use the exact absolute node + tsx cli path.
    if(prefix==="node_modules"&&item.name===".bin")continue;
    const rel=validateReleaseRelativePath(prefix+"/"+item.name);
    if(item.isSymbolicLink())deny("release dependency symlink forbidden: "+rel);
    if(item.isDirectory())out.push(...await walk(path.join(directory,item.name),rel));
    else if(item.isFile())out.push(rel);
    else deny("unsupported Mac runtime file: "+rel);
  }
  return out;
}
const originals=[...original.manifest.files];
const included=[];
for(const tree of ["dist/scripts","node_modules"]){
  const found=await walk(path.join(root,tree),tree);
  if(found.length>20000)deny("unbounded native Mac release tree");
  for(let offset=0;offset<found.length;offset+=24){
    included.push(...await Promise.all(found.slice(offset,offset+24).map(async(relative)=>{
      const destination=path.join(staging,...relative.split("/"));
      await mkdir(path.dirname(destination),{recursive:true});
      await copyFile(path.join(root,...relative.split("/")),destination);
      const s=await stat(destination);
      return {path:relative,bytes:s.size,sha256:await hash(destination)};
    })));
  }
}
const all=[...originals,...included].sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
if(all.length>=20000||new Set(all.map(x=>x.path.toLowerCase())).size!==all.length)
  deny("duplicate or excessive Mac manifest files");
const manifest={...original.manifest,files:all};
const bytes=JSON.stringify(manifest,null,2)+"\n";
const id=createHash("sha256").update(bytes).digest("hex");
await writeFile(path.join(staging,"RELEASE_MANIFEST.json"),bytes,{flag:"w"});
await verifyReleaseRoot(staging,id);
const completed=path.join(releaseDirectory,id);
try{await lstat(completed);deny("previous immutable Mac V3 release must not be overwritten");}
catch(error){if(error?.code!=="ENOENT")throw error;}
await rename(staging,completed);
console.log(JSON.stringify({
  status:"MAC_NATIVE_RUNTIME_RELEASE_STAGED_NOT_INSTALLED",
  sourceGitSha:pinned,
  releaseManifestSha256:id,
  releaseDirectory:completed,
  files:all.length,
  nodePlatform:"darwin-x64",
  macDependenciesIncluded:true,
  v2Changed:false,
  p08Changed:false,
  macAgentsInstalled:false,
  witnessStarted:false,
  physicalAcceptanceGranted:false,
}));
