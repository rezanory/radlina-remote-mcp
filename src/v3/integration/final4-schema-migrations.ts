/**
 * V3 final-four SQLite schema baseline v1.
 *
 * Only stamps PRAGMA user_version after verifying the real tables that the
 * existing V3 store constructors own. No data migration, DROP, DELETE,
 * vacuum, or destructive replay is ever performed. An unknown/newer schema
 * is fail-closed for an explicitly authorized future migration.
 *
 * Called only by the isolated Windows physical final-four bootstrap after
 * all eleven V3 stores have been constructed and before the gateway listens.
 */
import { lstatSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";

export const V3_FINAL4_SQLITE_SCHEMA_VERSION=1;
type TableContract=readonly [name:string,columns:readonly string[]];
type StoreContract={
  readonly file:string;
  readonly tables:readonly TableContract[];
  readonly requiredIndexes?:readonly string[];
};

/** Exact deployed names: never include the gateway-owned P03 registry DB. */
export const finalFourSqliteSchemaManifest:readonly StoreContract[]=[
  {file:"owner-origins.sqlite3",tables:[
    ["v3_native_workflow_origins",[
      "workflow_execution_id","subject","client_id","source_device_id","bound_at_ms",
    ]],
  ]},
  {file:"p03-sessions.sqlite3",tables:[
    ["v3_i01_p03_session_nonces",["nonce","device_id","authenticated_at_ms"]],
  ]},
  {file:"s02e-consent.sqlite3",tables:[
    ["v3_consent_requests",["request_id","idempotency_key","payload_json","state"]],
    ["v3_consent_grants",["grant_id","request_id","payload_json","remaining_uses","revoked_at_ms"]],
    ["v3_consent_uses",["attempt_id","grant_id","used_at_ms"]],
    ["v3_consent_decision_nonces",["nonce"]],
    ["v3_consent_decision_proofs",["request_id","evidence_json"]],
    ["v3_consent_events",["sequence","payload_json","previous_hash","event_hash"]],
  ]},
  {file:"i01-relay.sqlite3",tables:[
    ["v3_i01_outbox",[
      "request_id","device_id","operation_hash","sealed_message","sealed_result",
      "expires_at_ms","state","lease_id","created_at_ms","completed_at_ms",
    ]],
  ]},
  {file:"target-local-consent.sqlite3",tables:[
    ["v3_i01_local_consent",[
      "request_id","operation_sha256","source_device_id","target_device_id",
      "subject","request_json","reply_json","state","created_at_ms","expires_at_ms",
    ]],
  ]},
  {file:"fleet-relay.sqlite3",tables:[
    ["v3_f01_commands",[
      "operation_id","device_id","command_hash","sealed_command","sealed_reply",
      "expires_at_ms","state","lease_id","created_at_ms",
    ]],
  ]},
  {file:"fleet-recipient-consent.sqlite3",tables:[
    ["v3_f01_release_approvals",[
      "request_id","plan_id","device_id","action","target_hash","previous_hash",
      "state","signed_approval_json","created_at_ms","expires_at_ms",
    ]],
  ],requiredIndexes:["v3_f01_release_approvals_exact"]},
  {file:"owner-signing.sqlite3",tables:[
    ["v3_owner_signing_inbox",[
      "request_id","operation_hash","sealed_payload","requested_at_ms",
      "expires_at_ms","state","signature_base64",
    ]],
  ]},
  {file:"i01-intents.sqlite3",tables:[
    ["v3_i01_operations",[
      "operation_key","request_hash","target_device_id","request_id","state",
      "receipt_hash","audit_anchor_id","created_at_ms","completed_at_ms",
    ]],
  ]},
  {file:"fleet-plans.sqlite3",tables:[
    ["v3_fleet_plans",[
      "plan_id","idempotency_key","plan_json","state","transition_count",
    ]],
    ["v3_fleet_events",[
      "sequence","plan_id","event_json","previous_hash","event_hash",
    ]],
  ]},
  {file:"acceptance.sqlite3",tables:[
    ["v3_final_gate_decisions",[
      "gate","evidence_json","evidence_hash","owner_signature_hash",
      "reviewer_signature_hash","accepted_at_ms",
    ]],
  ]},
];

export class V3FinalFourMigrationDenied extends Error {
  constructor(message:string){super(message);this.name="V3FinalFourMigrationDenied";}
}

function verifyStore(db:DatabaseSync,contract:StoreContract):void {
  for(const [table,columns] of contract.tables){
    if(!/^v3_[a-z0-9_]+$/u.test(table))
      throw new V3FinalFourMigrationDenied("unexpected V3 table contract");
    const row=db.prepare(
      "SELECT type FROM sqlite_master WHERE type='table' AND name=?",
    ).get(table) as {type:string}|undefined;
    if(!row)throw new V3FinalFourMigrationDenied("V3 schema table missing: "+table);
    const present=new Set((db.prepare('PRAGMA table_info("'+table+'")').all() as
      Array<{name:string}>).map(column=>column.name));
    if(columns.some(name=>!present.has(name)))
      throw new V3FinalFourMigrationDenied("V3 table column baseline changed: "+table);
  }
  for(const index of contract.requiredIndexes??[]){
    const entry=db.prepare(
      "SELECT sql FROM sqlite_master WHERE type='index' AND name=?",
    ).get(index) as {sql:string|null}|undefined;
    if(!entry?.sql||!/CREATE UNIQUE INDEX/iu.test(entry.sql))
      throw new V3FinalFourMigrationDenied("V3 unique index baseline changed: "+index);
  }
}

/**
 * Safe, monotone v0 (existing unversioned v1 tables) -> v1 metadata adoption.
 * Each SQLite database advances idempotently under its own IMMEDIATE transaction.
 * Failing halfway cannot destroy data; completed v1 stamps remain valid.
 * No owner acceptance or production deployment is implied by schema stamping.
 */
export function requireFinalFourSchemaBaseline(stateDirectory:string):void {
  if(process.platform!=="win32"||!path.win32.isAbsolute(stateDirectory)||
    !stateDirectory.toLowerCase().startsWith("e:\\")||
    stateDirectory.toLowerCase().includes("\\v2\\")){
    throw new V3FinalFourMigrationDenied("isolated E: physical V3 schema root required");
  }
  const storeRoot=path.win32.join(stateDirectory,"final4");
  for(const contract of finalFourSqliteSchemaManifest){
    const filename=path.win32.join(storeRoot,contract.file);
    const state=lstatSync(filename);
    if(!state.isFile()||state.isSymbolicLink())
      throw new V3FinalFourMigrationDenied("V3 store must be a regular file: "+contract.file);
    const db=new DatabaseSync(filename,{enableForeignKeyConstraints:true});
    try{
      db.exec("BEGIN IMMEDIATE");
      try{
        const value=db.prepare("PRAGMA user_version").get() as
          {user_version:number}|undefined;
        const version=value?.user_version;
        if(typeof version!=="number"||!Number.isInteger(version)||version<0||
          version>V3_FINAL4_SQLITE_SCHEMA_VERSION){
          throw new V3FinalFourMigrationDenied(
            "unknown or newer V3 SQLite schema version: "+contract.file,
          );
        }
        verifyStore(db,contract);
        if(version===0)
          db.exec("PRAGMA user_version="+V3_FINAL4_SQLITE_SCHEMA_VERSION);
        db.exec("COMMIT");
      }catch(error){
        db.exec("ROLLBACK");
        throw error;
      }
    }finally{db.close();}
  }
}
