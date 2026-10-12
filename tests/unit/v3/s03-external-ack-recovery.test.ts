import { createPublicKey, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

import { canonicalJson, sha256 } from "../../../src/utils/json.js";
import {
  S03ExternalAuditClient,
  S03ExternalAuditUnavailable,
  type S03SignedWitnessAck,
} from "../../../src/v3/audit/s03-independent-witness.js";
import {
  f01ExactFleetCommandSchema,
  type F01SignedReply,
} from "../../../src/v3/fleet/physical-adapters.js";

afterEach(() => vi.unstubAllGlobals());

function setup() {
  // Ephemeral test-only Ed25519 key pairs. No production credentials or
  // physical Mac/Windows impersonation, no remote request and no gate receipt.
  const target = generateKeyPairSync("ed25519");
  const owner = generateKeyPairSync("ed25519");
  const witnessKey = generateKeyPairSync("ed25519");
  const command = f01ExactFleetCommandSchema.parse({
    schema: "radlina.v3.f01.exact-fleet-operation/v1",
    operationId: randomUUID(),
    planId: randomUUID(),
    deviceId: "windows-main",
    action: "fleet.verify",
    targetManifestSha256: "a".repeat(64),
    previousManifestSha256: "b".repeat(64),
    issuedAtMs: Date.now(),
    expiresAtMs: Date.now() + 60_000,
    nonce: randomUUID(),
  });
  const agentInstanceId = randomUUID();
  const replyUnsigned = {
    schema: "radlina.v3.f01.signed-fleet-reply/v1" as const,
    operationId: command.operationId,
    deviceId: command.deviceId,
    agentInstanceId,
    payload: { deviceId: command.deviceId, status: "prepared-test-only" },
  };
  const reply: F01SignedReply<typeof replyUnsigned.payload> = {
    ...replyUnsigned,
    deviceSignatureBase64: sign(
      null, Buffer.from(canonicalJson(replyUnsigned)), target.privateKey,
    ).toString("base64"),
  };
  const input: Parameters<S03ExternalAuditClient["anchorPhysicalReceipt"]>[0] = {
    planId: command.planId,
    deviceId: command.deviceId,
    commandHash: sha256(canonicalJson(command)),
    deviceReceiptHash: sha256(canonicalJson(reply.payload)),
    devicePublicKeyPem: target.publicKey.export({ type: "spki", format: "pem" }).toString(),
    ownerSignedCommand: {
      command,
      ownerSignatureBase64: sign(
        null, Buffer.from(canonicalJson(command)), owner.privateKey,
      ).toString("base64"),
    },
    signedReply: reply,
  };
  const witnessPem = witnessKey.publicKey.export({type:"spki",format:"pem"}).toString();
  const fingerprint = sha256(createPublicKey(witnessPem).export({type:"spki",format:"der"}));
  const client = new S03ExternalAuditClient(
    "https://v3-audit.radlina.com/api/v1/anchor",
    "unit-test-bearer-do-not-use-outside-process".repeat(2),
    Buffer.alloc(32, 11),
    witnessPem,
    fingerprint,
  );
  const ack = (body:string):S03SignedWitnessAck => {
    const recordHash = (JSON.parse(body) as {recordHash:string}).recordHash;
    const witnessed = {
      schema: "radlina.v3.s03.external-witness/v1" as const,
      anchorId: randomUUID(),
      recordHash,
      sequence: 1,
      previousHash: "0".repeat(64),
      chainHash: "c".repeat(64),
      issuedAtMs: Date.now(),
    };
    return {
      witness: witnessed,
      signatureBase64: sign(
        null, Buffer.from(canonicalJson(witnessed)), witnessKey.privateKey,
      ).toString("base64"),
    };
  };
  return {client, input, ack};
}

describe("S03 independent witness original ACK recovery", () => {
  it("accepts the exact independently signed receipt, without lookup", async () => {
    const {client,input,ack}=setup();
    const endpoints:string[]=[];
    vi.stubGlobal("fetch",vi.fn(async (url:string,req:{body:string})=>{
      endpoints.push(url);
      return new Response(JSON.stringify(ack(req.body)),{status:201});
    }));
    const receipt=await client.anchorPhysicalReceipt(input);
    expect(receipt.durable).toBe(true);
    expect(receipt.anchorId).toBeTruthy();
    expect(endpoints).toEqual(["https://v3-audit.radlina.com/api/v1/anchor"]);
  });

  it("looks up the original persisted ACK after a 5xx, never repeats the append", async () => {
    const {client,input,ack}=setup();
    const endpoints:string[]=[];
    vi.stubGlobal("fetch",vi.fn(async (url:string,req:{body:string})=>{
      endpoints.push(url);
      if(endpoints.length===1)return new Response("",{status:503});
      return new Response(JSON.stringify(ack(req.body)),{status:200});
    }));
    await expect(client.anchorPhysicalReceipt(input)).resolves.toMatchObject({durable:true});
    expect(endpoints).toEqual([
      "https://v3-audit.radlina.com/api/v1/anchor",
      "https://v3-audit.radlina.com/api/v1/anchor/lookup",
    ]);
  });

  it("recovers from a disconnected initial 201 ACK body without repeating the append", async () => {
    const {client,input,ack}=setup();
    const endpoints:string[]=[];
    vi.stubGlobal("fetch",vi.fn(async (url:string,req:{body:string})=>{
      endpoints.push(url);
      const response=new Response(JSON.stringify(ack(req.body)),{
        status:endpoints.length===1?201:200,
      });
      if(endpoints.length===1)vi.spyOn(response,"arrayBuffer").mockRejectedValueOnce(
        new Error("connection reset while reading successful HTTP body"),
      );
      return response;
    }));
    await expect(client.anchorPhysicalReceipt(input)).resolves.toMatchObject({durable:true});
    expect(endpoints).toEqual([
      "https://v3-audit.radlina.com/api/v1/anchor",
      "https://v3-audit.radlina.com/api/v1/anchor/lookup",
    ]);
  });

  it("fails closed if the original ACK is absent after an uncertain append", async () => {
    const {client,input}=setup();
    const endpoints:string[]=[];
    vi.stubGlobal("fetch",vi.fn(async (url:string)=>{
      endpoints.push(url);
      return new Response("",{status:endpoints.length===1?503:404});
    }));
    await expect(client.anchorPhysicalReceipt(input)).rejects.toThrow(
      S03ExternalAuditUnavailable,
    );
    expect(endpoints).toHaveLength(2);
    expect(endpoints[1]).toMatch(/\/lookup$/u);
  });

  it("rejects an altered signed ACK without attempting fallback lookup", async () => {
    const {client,input,ack}=setup();
    const endpoints:string[]=[];
    vi.stubGlobal("fetch",vi.fn(async (url:string,req:{body:string})=>{
      endpoints.push(url);
      const forged=ack(req.body);
      forged.witness.recordHash="e".repeat(64);
      return new Response(JSON.stringify(forged),{status:201});
    }));
    await expect(client.anchorPhysicalReceipt(input)).rejects.toThrow(
      /signature or exact persisted record invalid/u,
    );
    expect(endpoints).toEqual(["https://v3-audit.radlina.com/api/v1/anchor"]);
  });
});
