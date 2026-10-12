/**
 * One owner-signed, expiring Mac operator capability policy shared by both
 * physical Mac and Windows V3 P03 authority. Neither side can grant a new
 * capability from a request-only claimed permission.
 */
import { createPublicKey, verify } from "node:crypto";
import * as z from "zod/v4";
import { canonicalJson, sha256 } from "../../utils/json.js";

const OWNER_PIN="6259d21211f73fc9d2d7cc0174d9bfdc36424cd456878671ab5683468ca0fe93";
const MAC_PIN="f2c2e93ff120fbc5122cbb6b5a0b461a072f54bd8d226368c858fd0bd17037ea";
export const macOperatorCapability=z.enum(["device.health","filesystem.read","filesystem.write"]);
export const v3MacOperatorPolicySchema=z.object({
  schema:z.literal("radlina.v3.i01.macos-physical-operator-policy/v1"),
  macDeviceId:z.literal("macbook-main"),
  controllerDeviceId:z.literal("windows-main"),
  macPublicKeyFingerprint:z.literal(MAC_PIN),
  ownerPublicKeyPem:z.string().includes("BEGIN PUBLIC KEY").max(4096),
  windowsTailnetNodeHash:z.string().regex(/^[0-9a-f]{64}$/u),
  allowedCapabilities:z.array(macOperatorCapability).min(1).max(3),
  createdAt:z.string().datetime({offset:true}),
  expiresAt:z.string().datetime({offset:true}),
  approvalMode:z.literal("interactive-target-local"),
}).strict();
export const v3SignedMacOperatorPolicySchema=z.object({
  policy:v3MacOperatorPolicySchema,
  ownerSignatureBase64:z.string().min(80).max(200),
}).strict();
export type V3MacOperatorPolicy=z.infer<typeof v3MacOperatorPolicySchema>;

export function requireOwnerApprovedMacOperatorPolicy(input:unknown,now=Date.now()):V3MacOperatorPolicy {
  const {policy,ownerSignatureBase64}=v3SignedMacOperatorPolicySchema.parse(input);
  const pair=createPublicKey(policy.ownerPublicKeyPem);
  const fingerprint=sha256(pair.export({type:"spki",format:"der"}));
  const raw=Buffer.from(ownerSignatureBase64,"base64");
  if(fingerprint!==OWNER_PIN||
    raw.length!==64||raw.toString("base64")!==ownerSignatureBase64||
    !verify(null,Buffer.from(canonicalJson(policy)),pair,raw)||
    Date.parse(policy.createdAt)>now||
    Date.parse(policy.expiresAt)<=now||
    Date.parse(policy.expiresAt)-Date.parse(policy.createdAt)>30*24*60*60*1000||
    policy.allowedCapabilities[0]!=="device.health"||
    new Set(policy.allowedCapabilities).size!==policy.allowedCapabilities.length){
    throw new Error("physical Mac operator capabilities are not independently owner-approved");
  }
  return policy;
}
