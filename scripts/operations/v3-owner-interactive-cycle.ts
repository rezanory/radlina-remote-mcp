/**
 * One interactive Windows owner-signing task cycle.
 * Never runs as SYSTEM, runner or V2 service account. The owner gets a native
 * explicit approval dialog for every high-risk I01/F01 operation.
 */
import os from "node:os";
import { V3OwnerProtectedSigningBroker } from "../../src/v3/security/windows-owner-broker.js";

if(
  process.platform!=="win32"||
  os.hostname().toLowerCase()!=="laptop-13qineif"||
  os.userInfo().username.toLowerCase()!=="radlina"||
  process.argv.length!==2
){
  throw Error("only interactive LAPTOP-13QINEIF\\Radlina owner may sign V3 work");
}
const broker=new V3OwnerProtectedSigningBroker(
  "E:\\radlina-v3-oauth-standalone\\final4\\owner-signing.sqlite3",
);
try{
  const work=await broker.nextForInteractiveOwner();
  if(work){
    const accepted=await broker.approveWithLocalHuman(work);
    process.stdout.write(JSON.stringify({
      status:accepted?"V3_OWNER_PHYSICAL_SIGNATURE_RECORDED":"V3_OWNER_PHYSICAL_APPROVAL_DENIED",
      requestId:work.requestId,
      v2Untouched:true,
    })+"\n");
  }
}finally{broker.close();}
