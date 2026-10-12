/**
 * F01 native release switch drivers. MUST run in a separate physical-device
 * supervisor, never in RadlinaV3OAuthBeta or V2 service process.
 *
 * Windows controls ONLY RadlinaV3OAuthBeta; macOS controls ONLY the V3
 * com.radlina.remote-mcp.v3.mac-operator user LaunchAgent.
 * Unknown post-switch outcomes are not automatically retried/rolled back.
 */
import { execFile as execCallback } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { lstat, readFile, realpath, rename, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { verifyReleaseRoot } from "../../admin/release-manifest.js";
import type { LocalV3ReleaseHost } from "./local-release-agent.js";

const execFile=promisify(execCallback);
const HASH=/^[a-f0-9]{64}$/u;
function fail(message:string):never{throw new Error("F01 physical release denied: "+message);}
async function releaseId(file:string):Promise<string> {
  const bytes=await readFile(file);
  if(bytes.byteLength<100||bytes.byteLength>8*1024*1024)fail("bounded V3 manifest required");
  return createHash("sha256").update(bytes).digest("hex");
}
async function safeReleaseDir(root:string,requested:string):Promise<string>{
  const rootPhysical=await realpath(root);
  const target=await realpath(requested);
  const normalize=(s:string)=>process.platform==="win32"?s.toLowerCase():s;
  if(!normalize(target).startsWith(normalize(rootPhysical)+path.sep))
    fail("release directory escaped dedicated V3 root");
  const stat=await lstat(target);
  if(!stat.isDirectory()||stat.isSymbolicLink())fail("staged release root cannot be a link");
  return target;
}
async function exactRelease(root:string,manifest:string):Promise<{directory:string;entryFile:string}>{
  if(!HASH.test(manifest))fail("exact SHA256 release identifier required");
  const dir=await safeReleaseDir(root,path.join(root,manifest));
  const value=await verifyReleaseRoot(dir,manifest);
  if(value.manifestId!==manifest)fail("V3 release manifest digest changed");
  return{directory:dir,entryFile:value.entryFile};
}
async function execute(program:string,args:string[]):Promise<string>{
  try{
    const result=await execFile(program,args,{
      timeout:30000,maxBuffer:32*1024,windowsHide:true,
    });
    return result.stdout.trim();
  }catch{
    fail("V3 target supervisor native service action failed; reconcile uncertain outcome");
  }
}
export class WindowsV3NativeReleaseHost implements LocalV3ReleaseHost {
  readonly deviceId="windows-main" as const;
  readonly dedicatedV3ReleaseRoot="E:\\radlina-v3-runtime\\releases";
  private readonly xml="E:\\radlina-v3-runtime\\RadlinaV3OAuthBeta.xml";
  constructor(){
    if(process.platform!=="win32"||os.hostname().toLowerCase()!=="laptop-13qineif"||
      process.env["RADLINA_V3_FLEET_SUPERVISOR"]!=="1"||
      process.env["RADLINA_V3_PUBLIC_URL"]){
      fail("Windows physical F01 must run in separate V3 supervisor not in OAuth service");
    }
  }
  private async currentlyConfiguredDir():Promise<string>{
    const config=await readFile(this.xml,"utf8");
    if(!/<id>RadlinaV3OAuthBeta<\/id>/u.test(config)||
      /<id>RadlinaRemoteMCP<\/id>/u.test(config))fail("V2 or different service XML not allowed");
    const values=[...config.matchAll(/<workingdirectory>([^<]+)<\/workingdirectory>/gu)];
    if(values.length!==1||!values[0]?.[1])fail("unique exact V3 workingdirectory required");
    return await safeReleaseDir(this.dedicatedV3ReleaseRoot,values[0][1]);
  }
  async verifyStagedManifest(manifest:string):Promise<boolean>{
    try{await exactRelease(this.dedicatedV3ReleaseRoot,manifest);return true;}
    catch{return false;}
  }
  async currentManifest():Promise<string>{
    const directory=await this.currentlyConfiguredDir();
    return await releaseId(path.join(directory,"RELEASE_MANIFEST.json"));
  }
  async activateExactManifest(manifest:string,expectedPreviousHash:string):Promise<void>{
    if(await this.currentManifest()!==expectedPreviousHash)
      fail("Windows current V3 manifest differs from independently approved rollback base");
    const next=await exactRelease(this.dedicatedV3ReleaseRoot,manifest);
    const config=await readFile(this.xml,"utf8");
    const previous=await this.currentlyConfiguredDir();
    const oldTag="<workingdirectory>"+previous+"</workingdirectory>";
    const matches=[...config.matchAll(/<workingdirectory>([^<]+)<\/workingdirectory>/gu)];
    if(matches.length!==1||!matches[0]||path.win32.normalize(matches[0][1]??"").toLowerCase()!==
      path.win32.normalize(previous).toLowerCase())
      fail("Windows release XML CAS violated");
    const newText=config.replace(matches[0][0],"<workingdirectory>"+next.directory+"</workingdirectory>");
    const temp=this.xml+"."+randomUUID()+".pending";
    // Independent supervisor (not V3 OAuth process) controls service lifecycle.
    await writeFile(temp,newText,{flag:"wx"});
    await execute("C:\\Windows\\System32\\sc.exe",["stop","RadlinaV3OAuthBeta"]);
    // Preserve exact old XML with a durable rollback file; no destructive reset.
    const backup=this.xml+"."+expectedPreviousHash+".f01-pre-switch.xml";
    await rename(this.xml,backup);
    await rename(temp,this.xml);
    await execute("C:\\Windows\\System32\\sc.exe",["start","RadlinaV3OAuthBeta"]);
  }
  async verifyActiveRelease(manifest:string):Promise<{
    health:"healthy"|"degraded"|"unhealthy"|"unknown";
  }>{
    try{
      if(await this.currentManifest()!==manifest)return{health:"unhealthy"};
      const response=await fetch("http://127.0.0.1:7344/auth-health",{
        signal:AbortSignal.timeout(7000),
      });
      if(!response.ok)return{health:"degraded"};
      const result=await response.json() as {status?:string};
      return{health:result.status==="healthy"?"healthy":"unhealthy"};
    }catch{return{health:"unknown"};}
  }
}
export class MacV3NativeReleaseHost implements LocalV3ReleaseHost {
  readonly deviceId="macbook-main" as const;
  readonly dedicatedV3ReleaseRoot=path.join(os.homedir(),".local","share","radlina","v3-beta",
    "macbook-main-agent","releases");
  private readonly plist=path.join(os.homedir(),"Library","LaunchAgents",
    "com.radlina.remote-mcp.v3.mac-operator.plist");
  private readonly label="com.radlina.remote-mcp.v3.mac-operator";
  constructor(){
    if(process.platform!=="darwin"||os.hostname()!=="amirs-MacBook-Pro.local"||
      os.userInfo().username!=="amirsheikhzadeh"||
      process.env["RADLINA_V3_FLEET_SUPERVISOR"]!=="1"){
      fail("F01 Mac release change must be a dedicated user-level V3 supervisor");
    }
  }
  private async configuredDir():Promise<string>{
    const xml=await readFile(this.plist,"utf8");
    if(!xml.includes("<string>"+this.label+"</string>")||
      xml.includes("com.radlina.remote-mcp.v2"))fail("exact Mac V3 LaunchAgent label required");
    const parts=[...xml.matchAll(/<string>([^<]+\/releases\/[a-f0-9]{64})<\/string>/gu)];
    if(parts.length!==1||!parts[0]?.[1])fail("unique Mac V3 release pointer required");
    const directory=await safeReleaseDir(this.dedicatedV3ReleaseRoot,parts[0][1]);
    // LaunchAgent has three version-pinned references: the tsx loader,
    // the operator script and its RADLINA_V3_RELEASE_ROOT environment value.
    // Reject mixed releases rather than silently treating one pointer as truth.
    const required=[
      `<string>${directory}/node_modules/tsx/dist/cli.mjs</string>`,
      `<string>${directory}/scripts/operations/v3-mac-operator-cycle.ts</string>`,
      `<string>${directory}</string>`,
    ];
    if(required.some(tag=>xml.split(tag).length!==2))
      fail("Mac V3 LaunchAgent references must match one exact release");
    const ids=[...xml.matchAll(/\/releases\/([a-f0-9]{64})(?=\/|<)/gu)].map(match=>match[1]);
    if(ids.length!==3||new Set(ids).size!==1)
      fail("mixed Mac V3 LaunchAgent release paths");
    return directory;
  }
  async verifyStagedManifest(manifest:string):Promise<boolean>{
    try{await exactRelease(this.dedicatedV3ReleaseRoot,manifest);return true;}
    catch{return false;}
  }
  async currentManifest():Promise<string>{
    const dir=await this.configuredDir();
    return await releaseId(path.join(dir,"RELEASE_MANIFEST.json"));
  }
  async activateExactManifest(manifest:string,previousHash:string):Promise<void>{
    if(await this.currentManifest()!==previousHash)
      fail("Mac V3 active manifest mismatch");
    const next=await exactRelease(this.dedicatedV3ReleaseRoot,manifest);
    const current=await this.configuredDir();
    const oldXml=await readFile(this.plist,"utf8");
    const suffixes=[
      "/node_modules/tsx/dist/cli.mjs",
      "/scripts/operations/v3-mac-operator-cycle.ts",
      "",
    ];
    let replacement=oldXml;
    for(const suffix of suffixes){
      const previousTag="<string>"+current+suffix+"</string>";
      if(replacement.split(previousTag).length!==2)
        fail("Mac LaunchAgent exact versioned entrypoint changed");
      replacement=replacement.replace(previousTag,
        "<string>"+next.directory+suffix+"</string>");
    }
    const versionReferences=[...replacement.matchAll(
      /\/releases\/([a-f0-9]{64})(?=\/|<)/gu,
    )].map(match=>match[1]);
    if(versionReferences.length!==3||versionReferences.some(id=>id!==manifest))
      fail("Mac release switch left stale or mixed entrypoints");
    const temp=this.plist+"."+randomUUID()+".pending";
    await writeFile(temp,replacement,{flag:"wx",mode:0o600});
    const domain="gui/"+String(process.getuid?.()??-1);
    if(domain.endsWith("/-1"))fail("logged-in Mac GUI session required");
    await execute("/bin/launchctl",["bootout",domain+"/"+this.label]);
    const backup=this.plist+"."+previousHash+".f01-pre-switch.plist";
    await rename(this.plist,backup);
    await rename(temp,this.plist);
    await execute("/bin/launchctl",["bootstrap",domain,this.plist]);
  }
  async verifyActiveRelease(manifest:string):Promise<{
    health:"healthy"|"degraded"|"unhealthy"|"unknown";
  }>{
    try{
      if(await this.currentManifest()!==manifest)return{health:"unhealthy"};
      const domain="gui/"+String(process.getuid?.()??-1);
      const info=await execute("/bin/launchctl",["print",domain+"/"+this.label]);
      return{health:info.includes(this.label)?"healthy":"degraded"};
    }catch{return{health:"unknown"};}
  }
}
