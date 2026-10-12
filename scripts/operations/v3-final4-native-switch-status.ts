/**
 * Read-only P08/F01 native release reconciliation snapshot.
 * Never repairs, retries, changes service state, produces signed acceptance,
 * overwrites an earlier receipt or consumes a protected owner key.
 */
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import os from "node:os";
import path from "node:path";

const HOSTS=new Set(["LAPTOP-13QINEIF","amirs-MacBook-Pro.local"]);
if(!HOSTS.has(os.hostname())||process.argv.length!==2)
  throw Error("exact known physical V3 device and read-only invocation required");
const windows=process.platform==="win32";
if(!windows&&process.platform!=="darwin")
  throw Error("only native V3 Windows or macOS supported");
const root=windows?"E:\\radlina-v3-runtime":path.join(os.homedir(),".local","share","radlina","v3-beta","macbook-main-agent");
const store=windows?path.win32.join(root,"supervisor","native-switch.sqlite3"):
  path.join(root,"fleet","native-switch.sqlite3");
const activeFile=windows?path.win32.join(root,"RadlinaV3OAuthBeta.xml"):
  path.join(os.homedir(),"Library","LaunchAgents","com.radlina.remote-mcp.v3.mac-operator.plist");
const releaseRoot=windows?path.win32.join(root,"releases"):path.join(root,"releases");
const bytes=await readFile(activeFile);
const xml=bytes.toString("utf8");
const matches=windows?[...xml.matchAll(/<workingdirectory>([^<]+)<\/workingdirectory>/gu)]:
  [...xml.matchAll(/<string>([^<]+\/releases\/[a-f0-9]{64})<\/string>/gu)];
if(matches.length!==1||!matches[0]?.[1])
  throw Error("unique isolated native V3 service release pointer required");
const current=matches[0][1];
const releaseId=path.basename(current);
if(!/^[a-f0-9]{64}$/u.test(releaseId)||path.normalize(current)!==path.normalize(path.join(releaseRoot,releaseId)))
  throw Error("native V3 active release pointer escaped the dedicated release root");
const manifest=await readFile(path.join(current,"RELEASE_MANIFEST.json"));
const hash=createHash("sha256").update(manifest).digest("hex");
let journal:unknown;
try{
  const db=new DatabaseSync(store,{readOnly:true});
  try{
    const rows=db.prepare(
      "SELECT switch_id,before_manifest,after_manifest,phase,created_at_ms,updated_at_ms "+
      "FROM v3_native_switches ORDER BY created_at_ms DESC LIMIT 10",
    ).all();
    journal=rows;
  }finally{db.close();}
}catch{journal={status:"UNAVAILABLE_OR_NOT_CREATED",acceptance:false};}
process.stdout.write(JSON.stringify({
  schema:"radlina.v3.f01.native-reconciliation-snapshot/v1",
  deviceId:windows?"windows-main":"macbook-main",
  snapshotAt:new Date().toISOString(),
  observedReleaseSha256:releaseId,
  manifestFileSha256:hash,
  manifestMatchesActive:hash===releaseId,
  recentNativeSwitches:journal,
  status:"READ_ONLY_EVIDENCE_NOT_OWNER_APPROVAL",
  allowedAutomaticRollback:false,
})+"\n");
