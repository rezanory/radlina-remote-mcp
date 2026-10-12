/**
 * Immutable server-side source binding for native ChatGPT V3 direct workflow.
 * User-provided workflowExecutionId is never proof of the source device.
 * A verified OAuth client/subject pair must bind it before any I01 execution.
 */
import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { VerifiedWorkflowOriginPort } from "../security/consent-dispatch.js";
import type { VerifiedDevicePrincipal } from "../security/consent-contracts.js";

export class V3WorkflowOwnerBindingDenied extends Error {
  constructor(message:string){super(message);this.name="V3WorkflowOwnerBindingDenied";}
}
export class V3ServerAuthenticatedWorkflowOrigins implements VerifiedWorkflowOriginPort {
  readonly db:DatabaseSync;
  constructor(file:string,private readonly now:()=>number=()=>Date.now()){
    if(!path.isAbsolute(file)||file.toLowerCase().includes("\\v2\\"))
      throw new V3WorkflowOwnerBindingDenied("isolated V3 workflow owner journal required");
    mkdirSync(path.dirname(file),{recursive:true});
    this.db=new DatabaseSync(file,{enableForeignKeyConstraints:true});
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS v3_i01_workflow_origins("+
      "execution_id TEXT PRIMARY KEY,subject TEXT NOT NULL,device_id TEXT NOT NULL,"+
      "client_id TEXT NOT NULL,bound_at_ms INTEGER NOT NULL);"
    );
  }
  bind(input:{workflowExecutionId:string;subject:string;clientId:string;deviceId:string}):void {
    if(!input.workflowExecutionId.trim()||!input.subject.trim()||!input.clientId.trim()||
      input.deviceId!=="windows-main"){
      throw new V3WorkflowOwnerBindingDenied("verified exact physical Windows source required");
    }
    const previous=this.db.prepare(
      "SELECT subject,client_id,device_id FROM v3_i01_workflow_origins WHERE execution_id=?"
    ).get(input.workflowExecutionId) as {
      subject:string;client_id:string;device_id:string;
    }|undefined;
    if(previous){
      if(previous.subject!==input.subject||previous.client_id!==input.clientId||
        previous.device_id!==input.deviceId){
        throw new V3WorkflowOwnerBindingDenied("workflow immutable origin changed");
      }
      return;
    }
    this.db.prepare(
      "INSERT INTO v3_i01_workflow_origins(execution_id,subject,device_id,client_id,bound_at_ms) "+
      "VALUES(?,?,?,?,?)"
    ).run(input.workflowExecutionId,input.subject,input.deviceId,input.clientId,this.now());
  }
  resolve(input:{workflowExecutionId:string;subject:string}):VerifiedDevicePrincipal|undefined {
    const row=this.db.prepare(
      "SELECT subject,device_id FROM v3_i01_workflow_origins WHERE execution_id=?"
    ).get(input.workflowExecutionId) as {subject:string;device_id:string}|undefined;
    return row?.subject===input.subject?
      {subject:row.subject,deviceId:row.device_id,attested:true}:undefined;
  }
  close():void{this.db.close();}
}
