/**
 * I01 V3-only physical P03 device sessions and DPAPI-at-rest relay sealing.
 * All authenticated sessions bind a one-time nonce, current P03 public key,
 * independent live Tailscale observation and a recently accepted signed heartbeat.
 */
import { createPublicKey, verify } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import os from "node:os";
import { mkdirSync } from "node:fs";
import path from "node:path";
import * as z from "zod/v4";
import { protectBytes, unprotectBytes } from "../../auth/dpapi.js";
import { canonicalJson, sha256 } from "../../utils/json.js";
import { ed25519PublicKeyFingerprint } from "../device/owner-pinned-enrollment.js";
import type { SqliteDeviceRegistry } from "../device/registry.js";
import type { I01PhysicalDeviceSession, I01SealedOutboxData } from "./i01-sealed-outbox.js";

export const i01AgentSessionSchema = z.object({
  schema:z.literal("radlina.v3.i01.device-session/v1"),
  deviceId:z.enum(["macbook-main","windows-main"]),
  nonce:z.string().uuid(),
  signedAtMs:z.number().int().positive(),
}).strict();
export class I01PhysicalSessionDenied extends Error {
  constructor(message:string){super(message);this.name="I01PhysicalSessionDenied";}
}
export type ObservedP03Peer = {
  observeExactTailnetNodeHash(deviceId:"macbook-main"|"windows-main"):string|undefined;
};
export class I01ActualP03SessionAuthority implements I01PhysicalDeviceSession {
  private readonly db:DatabaseSync;
  constructor(
    private readonly registry:SqliteDeviceRegistry,
    file:string,
    private readonly peers:ObservedP03Peer,
    private readonly now:()=>number=()=>Date.now(),
  ){
    if(process.platform!=="win32"||os.hostname().toLowerCase()!=="laptop-13qineif"||
      !path.win32.isAbsolute(file)||file.toLowerCase().includes("\\v2\\")){
      throw new I01PhysicalSessionDenied("physical Windows controller isolated V3 storage required");
    }
    mkdirSync(path.dirname(file),{recursive:true});
    this.db=new DatabaseSync(file,{enableForeignKeyConstraints:true});
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec("CREATE TABLE IF NOT EXISTS v3_i01_p03_session_nonces("+
      "nonce TEXT PRIMARY KEY,device_id TEXT NOT NULL,authenticated_at_ms INTEGER NOT NULL);");
  }
  async assertPhysicalAgent(raw:{
    deviceId:string;nonce:string;signedAtMs:number;signatureBase64:string;
  }):Promise<void> {
    const session=i01AgentSessionSchema.parse({
      schema:"radlina.v3.i01.device-session/v1",
      deviceId:raw.deviceId,
      nonce:raw.nonce,
      signedAtMs:raw.signedAtMs,
    });
    if(Math.abs(this.now()-session.signedAtMs)>60000)
      throw new I01PhysicalSessionDenied("physical P03 session expired");
    const device=this.registry.require(session.deviceId);
    const age=this.now()-Date.parse(device.lastSeen);
    if(device.trustState!=="trusted"||device.status!=="online"||
      device.health==="unhealthy"||device.health==="unknown"||
      (session.deviceId==="macbook-main"&&device.health!=="healthy")||
      !Number.isFinite(age)||age<0||age>120000){
      throw new I01PhysicalSessionDenied("device P03 signed heartbeat not fresh");
    }
    const row=this.registry.db.prepare(
      "SELECT identity_json,device_public_key_pem,tailscale_node_hash "+
      "FROM v3_p03_trusted_identities WHERE device_id=?"
    ).get(session.deviceId) as {
      identity_json:string;device_public_key_pem:string;tailscale_node_hash:string;
    }|undefined;
    if(!row)throw new I01PhysicalSessionDenied("P03 dual-signature trusted identity missing");
    const identity=z.object({
      deviceId:z.literal(session.deviceId),
      agentInstanceId:z.string().uuid(),
      publicKeyFingerprint:z.string().regex(/^[0-9a-f]{64}$/u),
    }).passthrough().parse(JSON.parse(row.identity_json));
    if(ed25519PublicKeyFingerprint(row.device_public_key_pem)!==identity.publicKeyFingerprint)
      throw new I01PhysicalSessionDenied("P03 device public key was modified");
    const observed=this.peers.observeExactTailnetNodeHash(session.deviceId);
    if(!observed||observed!==row.tailscale_node_hash)
      throw new I01PhysicalSessionDenied("physical peer Tailnet identity unavailable");
    const proof=Buffer.from(raw.signatureBase64,"base64");
    if(proof.byteLength!==64||proof.toString("base64")!==raw.signatureBase64||
      !verify(null,Buffer.from(canonicalJson(session)),createPublicKey(row.device_public_key_pem),proof)){
      throw new I01PhysicalSessionDenied("physical P03 key did not sign exact one-time session");
    }
    // Replay resistance persists across restarts and is shared by poll and receipt endpoints.
    this.db.prepare(
      "INSERT INTO v3_i01_p03_session_nonces(nonce,device_id,authenticated_at_ms) VALUES(?,?,?)"
    ).run(session.nonce,session.deviceId,this.now());
  }
  close():void{this.db.close();}
}

/** Per-payload machine DPAPI. Never stores plaintext envelopes in WAL. */
export class I01WindowsDpapiSealer implements I01SealedOutboxData {
  async seal(bytes:Uint8Array):Promise<Uint8Array>{
    if(process.platform!=="win32"||bytes.byteLength===0||bytes.byteLength>256*1024)
      throw new I01PhysicalSessionDenied("V3 Windows bounded DPAPI sealing only");
    return Buffer.from(await protectBytes(bytes),"utf8");
  }
  async unseal(bytes:Uint8Array):Promise<Uint8Array>{
    if(process.platform!=="win32"||bytes.byteLength===0||bytes.byteLength>512*1024)
      throw new I01PhysicalSessionDenied("V3 Windows bounded DPAPI unsealing only");
    const value=Buffer.from(bytes).toString("utf8");
    if(!/^[a-zA-Z0-9+/=]+$/u.test(value))
      throw new I01PhysicalSessionDenied("V3 DPAPI envelope encoding invalid");
    const plaintext=await unprotectBytes(value);
    if(!plaintext.length||plaintext.length>256*1024) {
      plaintext.fill(0);
      throw new I01PhysicalSessionDenied("V3 DPAPI decrypted content exceeds bound");
    }
    return plaintext;
  }
}
