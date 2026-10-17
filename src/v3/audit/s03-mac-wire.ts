/**
 * S03 V3 independent Mac witness wire protocol.
 *
 * Exact match for Windows S03ExternalAuditClient (POST /api/v1/anchor):
 * token + HMAC authenticate the controller; the Mac independently verifies
 * owner signature, target Ed25519 receipt and chain persistence before ACK.
 * Never permits process execution or release modification.
 */
import { createHmac, createPublicKey, timingSafeEqual, verify } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import * as z from "zod/v4";

import { canonicalJson, sha256 } from "../../utils/json.js";
import type { S03WitnessSigningKey } from "./s03-mac-witness.js";
import { S03MacIndependentWitnessJournal } from "./s03-mac-witness.js";
import type { S03AnchorEvent } from "./s03-remote-anchor.js";

const HASH=z.string().regex(/^[0-9a-f]{64}$/u);
export const s03WireAppendSchema=z.object({
  schema:z.literal("radlina.v3.s03.external-append/v1"),
  kind:z.enum(["i01","f01"]),
  recordHash:HASH,
  payload:z.unknown(),
}).strict();
export type S03WireAppend=z.infer<typeof s03WireAppendSchema>;
export type S03WitnessWireAck={
  schema:"radlina.v3.s03.external-witness/v1";
  anchorId:string;
  recordHash:string;
  sequence:number;
  previousHash:string;
  chainHash:string;
  issuedAtMs:number;
};

export class S03WitnessWireDenied extends Error{
  constructor(reason:string){super(reason);this.name="S03WitnessWireDenied";}
}
function bearer(request:string,approved:string):boolean {
  if(!request.startsWith("Bearer ")||request.length>1024)return false;
  const value=Buffer.from(sha256(request.slice(7)),"hex");
  const target=Buffer.from(sha256(approved),"hex");
  return value.length===target.length&&timingSafeEqual(value,target);
}
function mac(value:string,key:Buffer,message:string):boolean{
  if(!HASH.safeParse(value).success)return false;
  const expected=createHmac("sha256",key).update(message).digest();
  const actual=Buffer.from(value,"hex");
  return expected.length===actual.length&&timingSafeEqual(actual,expected);
}
export class S03AuthenticatedMacWireService {
  private readonly db:DatabaseSync;
  constructor(
    private readonly journal:S03MacIndependentWitnessJournal,
    private readonly signing:S03WitnessSigningKey,
    private readonly controllerBearer:string,
    private readonly controllerHmac:Buffer,
    private readonly now:()=>number=()=>Date.now(),
  ){
    if(controllerBearer.length<32||controllerHmac.length<32){
      throw new S03WitnessWireDenied("independently provisioned private S03 writer credentials required");
    }
    this.db=journal.db;
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS v3_s03_wire_acks("+
      "request_hash TEXT PRIMARY KEY,record_hash TEXT NOT NULL,"+
      "ack_json TEXT NOT NULL,signature_base64 TEXT NOT NULL);"
    );
    this.db.exec(
      "CREATE TRIGGER IF NOT EXISTS s03_wire_no_update BEFORE UPDATE ON v3_s03_wire_acks "+
      "BEGIN SELECT RAISE(ABORT,'append_only'); END;"+
      "CREATE TRIGGER IF NOT EXISTS s03_wire_no_delete BEFORE DELETE ON v3_s03_wire_acks "+
      "BEGIN SELECT RAISE(ABORT,'append_only'); END;"
    );
  }
  /** Authenticated read-only recovery of an already persisted original ACK. */
  lookup(raw:Uint8Array,authHeader:string,hmacHeader:string,idempotencyKey:string):
    {witness:S03WitnessWireAck;signatureBase64:string}|null{
    if(raw.length===0||raw.length>128*1024)
      throw new S03WitnessWireDenied("bounded exact witness request required");
    const body=Buffer.from(raw).toString("utf8");
    if(!bearer(authHeader,this.controllerBearer)||!mac(hmacHeader,this.controllerHmac,body))
      throw new S03WitnessWireDenied("independent S03 writer credentials invalid");
    const wire=s03WireAppendSchema.parse(JSON.parse(body));
    if(canonicalJson(wire)!==body||idempotencyKey!==sha256(body))
      throw new S03WitnessWireDenied("exact immutable S03 lookup digest required");
    const existing=this.db.prepare(
      "SELECT record_hash,ack_json,signature_base64 FROM v3_s03_wire_acks WHERE request_hash=?",
    ).get(idempotencyKey) as {
      record_hash:string;ack_json:string;signature_base64:string;
    }|undefined;
    if(!existing)return null;
    if(existing.record_hash!==wire.recordHash)
      throw new S03WitnessWireDenied("S03 signed ACK record conflict");
    const witness=JSON.parse(existing.ack_json) as S03WitnessWireAck;
    const proof=Buffer.from(existing.signature_base64,"base64");
    if(witness.recordHash!==wire.recordHash||proof.length!==64||
      proof.toString("base64")!==existing.signature_base64||
      !verify(null,Buffer.from(canonicalJson(witness)),
        createPublicKey(this.signing.publicKeyPem),proof))
      throw new S03WitnessWireDenied("stored S03 witness receipt integrity failed");
    return{witness,signatureBase64:existing.signature_base64};
  }
  async accept(raw:Uint8Array,authHeader:string,hmacHeader:string,idempotencyKey:string):
    Promise<{witness:S03WitnessWireAck;signatureBase64:string}>{
    if(raw.length===0||raw.length>128*1024)throw new S03WitnessWireDenied("bounded witness request required");
    const body=Buffer.from(raw).toString("utf8");
    if(!bearer(authHeader,this.controllerBearer)||!mac(hmacHeader,this.controllerHmac,body)){
      throw new S03WitnessWireDenied("independent S03 writer credentials invalid");
    }
    const wire=s03WireAppendSchema.parse(JSON.parse(body));
    const canonical=canonicalJson(wire);
    if(canonical!==body)throw new S03WitnessWireDenied("canonical immutable audit envelope required");
    const requestHash=sha256(canonical);
    if(idempotencyKey!==requestHash){
      throw new S03WitnessWireDenied("S03 idempotency key not bound to exact signed event");
    }
    const prior=this.db.prepare(
      "SELECT record_hash,ack_json,signature_base64 FROM v3_s03_wire_acks WHERE request_hash=?"
    ).get(requestHash) as {
      record_hash:string;ack_json:string;signature_base64:string;
    }|undefined;
    if(prior){
      if(prior.record_hash!==wire.recordHash)
        throw new S03WitnessWireDenied("S03 idempotency conflict");
      return {
        witness:JSON.parse(prior.ack_json) as S03WitnessWireAck,
        signatureBase64:prior.signature_base64,
      };
    }
    const event:S03AnchorEvent={
      schema:"radlina.v3.s03.external-event/v1",
      kind:wire.kind==="i01"?"execution":"fleet",
      recordHash:wire.recordHash,
      event:wire.payload,
      issuedAt:new Date(this.now()).toISOString(),
    };
    // If the Mac committed the chain but failed before inserting the wire
    // ACK, recover that SAME chain record; never append a duplicate event.
    const previous=this.db.prepare(
      "SELECT sequence,prev_hash,chain_head,event_json,ack_json FROM v3_s03_external_chain "+
      "WHERE record_hash=? ORDER BY sequence",
    ).all(wire.recordHash) as Array<{
      sequence:number;prev_hash:string;chain_head:string;event_json:string;ack_json:string;
    }>;
    const existing=previous.filter(row=>{
      const value=JSON.parse(row.event_json) as S03AnchorEvent;
      return value.kind===event.kind&&canonicalJson(value.event)===canonicalJson(event.event);
    });
    if(existing.length>1||previous.length!==existing.length)
      throw new S03WitnessWireDenied("S03 prior anchor hash collision or duplicate chain requires review");
    // This method independently verifies P03 signatures before its first
    // append; older persisted evidence is recovered without re-signing a
    // time-expired owner command or creating another chain link.
    const proof=existing.length===1?null:await this.journal.anchor(event);
    const persisted=proof?.receipt??(JSON.parse(existing[0]!.ack_json) as {
      eventHash:string;chainHead:string;sequence:number;anchoredAt:string;
    });
    const row=this.db.prepare(
      "SELECT prev_hash,chain_head FROM v3_s03_external_chain WHERE event_hash=?"
    ).get(persisted.eventHash) as {prev_hash:string;chain_head:string}|undefined;
    if(!row||row.chain_head!==persisted.chainHead)
      throw new S03WitnessWireDenied("Mac S03 persisted hash-chain was not found");
    const witness:S03WitnessWireAck={
      schema:"radlina.v3.s03.external-witness/v1",
      anchorId:persisted.chainHead,
      recordHash:wire.recordHash,
      sequence:persisted.sequence,
      previousHash:row.prev_hash,
      chainHash:persisted.chainHead,
      issuedAtMs:Date.parse(persisted.anchoredAt),
    };
    const signatureBase64=await this.signing.signCanonical(canonicalJson(witness));
    const signature=Buffer.from(signatureBase64,"base64");
    if(signature.length!==64||
      !verify(null,Buffer.from(canonicalJson(witness)),createPublicKey(this.signing.publicKeyPem),signature)){
      throw new S03WitnessWireDenied("independent Mac witness signing failed");
    }
    // Successful result is durable before returning HTTP 201.
    this.db.prepare(
      "INSERT INTO v3_s03_wire_acks(request_hash,record_hash,ack_json,signature_base64) "+
      "VALUES(?,?,?,?)"
    ).run(requestHash,wire.recordHash,canonicalJson(witness),signatureBase64);
    return {witness,signatureBase64};
  }
}
