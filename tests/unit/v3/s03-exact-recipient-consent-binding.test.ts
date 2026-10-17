import { describe, expect, it } from "vitest";

import { canonicalJson, sha256 } from "../../../src/utils/json.js";
import {
  assertS03ExactRecipientConsentBinding,
  S03WitnessDenied,
} from "../../../src/v3/audit/s03-mac-witness.js";

/**
 * Unit-only data validates the pure exact-operation binding. The real Mac
 * witness independently verifies the owner and recipient Ed25519 signatures
 * before calling this function. These tests do not start an agent, issue
 * credentials, impersonate a device, or constitute acceptance evidence.
 */
function fixture() {
  const issuedAtMs=1_784_200_000_000;
  const operation={
    workflowExecutionId:"a596cb9a-0e30-465d-a1dc-9116c33eab38",
    nodeId:"read-resource",
    attempt:1,
    sourceDeviceId:"windows-main",
    targetDeviceId:"macbook-main",
    subject:"owner",
    capability:"filesystem.read",
    inputSha256:"b".repeat(64),
    issuedAtMs,
  };
  const operationSha256=sha256(canonicalJson({
    workflowExecutionId:operation.workflowExecutionId,
    nodeId:operation.nodeId,
    attempt:operation.attempt,
    sourceDeviceId:operation.sourceDeviceId,
    targetDeviceId:operation.targetDeviceId,
    subject:operation.subject,
    capability:operation.capability,
    inputSha256:operation.inputSha256,
  }));
  const approval={
    operationSha256,
    sourceDeviceId:operation.sourceDeviceId,
    targetDeviceId:operation.targetDeviceId,
    subject:operation.subject,
    issuedAtMs:issuedAtMs-1000,
    expiresAtMs:issuedAtMs+30000,
  };
  return {operation,approval};
}
describe("S03 independently checks recipient-local consent for exact I01 operation",()=>{
  it("accepts only the exact operation hash, owner subject and issuance-valid approval",()=>{
    const {operation,approval}=fixture();
    expect(()=>assertS03ExactRecipientConsentBinding(operation,approval)).not.toThrow();
  });
  it("refuses approval hash from a different operation",()=>{
    const {operation,approval}=fixture();
    expect(()=>assertS03ExactRecipientConsentBinding(operation,{
      ...approval,operationSha256:"c".repeat(64),
    })).toThrow(S03WitnessDenied);
  });
  it("refuses replay into a different workflow or node attempt",()=>{
    const {operation,approval}=fixture();
    for(const altered of [
      {...operation,workflowExecutionId:"72f9e9fe-9cfa-4ecc-926c-2b318cb2c12a"},
      {...operation,nodeId:"other-node"},
      {...operation,attempt:2},
    ]){
      expect(()=>assertS03ExactRecipientConsentBinding(altered,approval)).toThrow(
        /exact owner operation/u,
      );
    }
  });
  it("refuses another capability, resource hash or source/target device",()=>{
    const {operation,approval}=fixture();
    for(const altered of [
      {...operation,capability:"filesystem.write"},
      {...operation,inputSha256:"e".repeat(64)},
      {...operation,sourceDeviceId:"macbook-main"},
      {...operation,targetDeviceId:"windows-main"},
    ]){
      expect(()=>assertS03ExactRecipientConsentBinding(altered,approval)).toThrow(
        S03WitnessDenied,
      );
    }
  });
  it("refuses a local signature for another subject or device",()=>{
    const {operation,approval}=fixture();
    for(const altered of [
      {...approval,subject:"other-owner"},
      {...approval,sourceDeviceId:"macbook-main"},
      {...approval,targetDeviceId:"windows-main"},
    ]){
      expect(()=>assertS03ExactRecipientConsentBinding(operation,altered)).toThrow(
        S03WitnessDenied,
      );
    }
  });
  it("refuses approvals issued after the operation, expired at issue, or exceeding two minutes",()=>{
    const {operation,approval}=fixture();
    for(const altered of [
      {...approval,issuedAtMs:operation.issuedAtMs+1},
      {...approval,expiresAtMs:operation.issuedAtMs},
      {...approval,issuedAtMs:operation.issuedAtMs-120001},
      {...approval,expiresAtMs:operation.issuedAtMs+120001},
      {...approval,issuedAtMs:NaN},
    ]){
      expect(()=>assertS03ExactRecipientConsentBinding(operation,altered)).toThrow(
        S03WitnessDenied,
      );
    }
  });
  it("permits delayed independent audit recovery only when consent was valid at original issuance",()=>{
    const {operation,approval}=fixture();
    // The audit may arrive long after the owner's operation. Never extend the
    // permission: validity is checked at original signed issuance, not now.
    expect(()=>assertS03ExactRecipientConsentBinding(operation,approval)).not.toThrow();
  });
});
