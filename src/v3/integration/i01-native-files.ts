/**
 * I01 physical target execution: explicitly allowlisted native V3 text files.
 * No shell, arbitrary filesystem roots, symlinks or overwrites. Only an exact
 * owner-approved and recipient-approved operation reaches these methods.
 */
import { constants } from "node:fs";
import { mkdir, lstat, open, readFile, realpath, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { canonicalJson, sha256 } from "../../utils/json.js";
import type { I01TargetNativeCapabilities } from "./i01-recipient-agent.js";

export class I01NativeCapabilityDenied extends Error {
  constructor(msg:string){super(msg);this.name="I01NativeCapabilityDenied";}
}
function filename(input:unknown):string {
  if(typeof input!=="string" || Buffer.byteLength(input,"utf8")>250 ||
    !/^[\p{L}\p{N}_ .-]{1,100}\.txt$/u.test(input)||
    input==="."||input===".."||input.includes("/")||input.includes("\\")||
    input.startsWith(".")){
    throw new I01NativeCapabilityDenied("only bounded UTF-8 text filenames are allowed");
  }
  return input;
}
export type I01NativeFileResult = {
  deviceId:string;capability:string;file:string;bytes:number;
  sha256:string;readbackVerified:true;overwrite:false;
};
export class I01SafeNativeTextCapabilities implements I01TargetNativeCapabilities {
  readonly capabilities:ReadonlySet<string>=new Set([
    "device.health","filesystem.read","filesystem.write",
  ]);
  constructor(
    readonly deviceId:"macbook-main"|"windows-main",
    readonly root:string,
  ){
    const expected= deviceId==="macbook-main"
      ? path.join(os.homedir(),"Desktop","RadlinaV3")
      : "C:\\Users\\Radlina\\OneDrive\\Desktop\\RadlinaV3";
    if(!path.isAbsolute(root)||path.resolve(root).toLowerCase()!==path.resolve(expected).toLowerCase()||
      (deviceId==="macbook-main"&&process.platform!=="darwin")||
      (deviceId==="windows-main"&&process.platform!=="win32")){
      throw new I01NativeCapabilityDenied("exact physical local V3 text directory required");
    }
  }
  private async safeRoot():Promise<string>{
    await mkdir(this.root,{recursive:true,mode:0o700});
    const info=await lstat(this.root);
    if(!info.isDirectory()||info.isSymbolicLink())
      throw new I01NativeCapabilityDenied("V3 local text root cannot be a symlink");
    const resolved=await realpath(this.root);
    if(path.resolve(resolved).toLowerCase()!==path.resolve(this.root).toLowerCase())
      throw new I01NativeCapabilityDenied("physical V3 text root changed via reparse/symlink");
    return resolved;
  }
  async executeExact(capability:string,input:Record<string,unknown>,timeoutMs:number):Promise<unknown>{
    if(!this.capabilities.has(capability)||!Number.isInteger(timeoutMs)||
      timeoutMs<100||timeoutMs>120000){
      throw new I01NativeCapabilityDenied("unsupported exact V3 physical capability");
    }
    if(capability==="device.health"){
      return {
        deviceId:this.deviceId,hostname:os.hostname(),
        platform:process.platform,agentVersion:"3.0.0-alpha.1",
        nativeExecution:true,
      };
    }
    const folder=await this.safeRoot();
    const name=filename(input["name"]);
    const target=path.join(folder,name);
    if(path.dirname(target)!==folder)
      throw new I01NativeCapabilityDenied("file path escaped bounded V3 directory");
    if(capability==="filesystem.read"){
      const info=await lstat(target);
      if(!info.isFile()||info.isSymbolicLink()||info.size>65536){
        throw new I01NativeCapabilityDenied("bounded non-symlink text file required");
      }
      const bytes=await readFile(target);
      if(bytes.byteLength>65536)
        throw new I01NativeCapabilityDenied("V3 text read bounded by 64 KiB");
      return {
        deviceId:this.deviceId,file:name,
        content:bytes.toString("utf8"),bytes:bytes.byteLength,sha256:sha256(bytes),
      };
    }
    if(typeof input["content"]!=="string")
      throw new I01NativeCapabilityDenied("UTF-8 text required");
    const bytes=Buffer.from(input["content"],"utf8");
    if(bytes.length>65536)throw new I01NativeCapabilityDenied("V3 native file write 64 KiB limit");
    // O_EXCL prevents silent overwrites; O_NOFOLLOW rejects symlink targets where supported.
    const flags=constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|
      (constants.O_NOFOLLOW??0);
    const handle=await open(target,flags,0o600);
    try{
      await handle.writeFile(bytes);
      await handle.sync();
    }finally{await handle.close();}
    const back=await readFile(target);
    const info=await stat(target);
    if(!info.isFile()||!back.equals(bytes)) {
      throw new I01NativeCapabilityDenied("physical target readback failed; manual reconcile required");
    }
    const result:I01NativeFileResult={
      deviceId:this.deviceId,capability,file:name,bytes:back.length,
      sha256:sha256(back),readbackVerified:true,overwrite:false,
    };
    return result;
  }
}
