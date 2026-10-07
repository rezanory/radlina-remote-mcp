import { describe, expect, it } from "vitest";

import { canonicalJson, sha256 } from "../../../src/utils/json.js";
import {
  assertAgentHello,
  assertExecuteRequestForDevice,
  DeviceAgentProtocolError,
  parseAgentExecuteRequest,
  parseAgentExecutionReceipt,
} from "../../../src/v3/device/agent-protocol.js";
import { parseDeviceDescriptor } from "../../../src/v3/device/identity.js";

const descriptor = parseDeviceDescriptor({
  deviceId: "windows-main",
  hostname: "LAPTOP-13QINEIF",
  platform: "windows",
  architecture: "x64",
  agentVersion: "3.0.0-alpha.1",
  status: "online",
  lastSeen: "2026-10-07T12:00:00+03:00",
  capabilities: ["device.health", "process.exec"],
  tags: ["primary"],
  trustState: "trusted",
  health: "healthy",
});

function request(overrides: Record<string, unknown> = {}) {
  const input = { probe: true };
  return parseAgentExecuteRequest({
    requestId: "027e74f9-3e7c-42ec-bda2-d80ddf476a85",
    workflowExecutionId: "wf-1",
    nodeId: "health",
    attempt: 1,
    targetDeviceId: "windows-main",
    capability: "device.health",
    input,
    inputSha256: sha256(canonicalJson(input)),
    timeoutMs: 5_000,
    globalCorrelationId: "corr-1",
    traceId: "trace-1",
    ...overrides,
  });
}

describe("V3 device agent protocol", () => {
  it("binds hello identity to an exact trusted device descriptor", () => {
    expect(
      assertAgentHello({
        protocolVersion: "1.0.0",
        descriptor,
        identity: {
          deviceId: "windows-main",
          agentInstanceId: "ac84a918-41bd-4f1f-a492-62b7ba16b683",
          agentVersion: "3.0.0-alpha.1",
          publicKeyFingerprint: "a".repeat(64),
          enrolledAt: "2026-10-07T12:00:00+03:00",
        },
      }).descriptor.deviceId,
    ).toBe("windows-main");
  });

  it("rejects hello identity mismatch", () => {
    expect(() =>
      assertAgentHello({
        protocolVersion: "1.0.0",
        descriptor,
        identity: {
          deviceId: "macbook-main",
          agentInstanceId: "ac84a918-41bd-4f1f-a492-62b7ba16b683",
          agentVersion: "3.0.0-alpha.1",
          publicKeyFingerprint: "a".repeat(64),
          enrolledAt: "2026-10-07T12:00:00+03:00",
        },
      }),
    ).toThrow(/device mismatch/u);
  });

  it("accepts an exact-device execution request with verified input integrity", () => {
    expect(() => assertExecuteRequestForDevice(request(), descriptor)).not.toThrow();
  });

  it("forbids silent execution on a different device", () => {
    expect(() =>
      assertExecuteRequestForDevice(request({ targetDeviceId: "macbook-main" }), descriptor),
    ).toThrow(DeviceAgentProtocolError);
  });

  it("rejects unadvertised capabilities and tampered input identity", () => {
    expect(() =>
      assertExecuteRequestForDevice(request({ capability: "filesystem.info" }), descriptor),
    ).toThrow(/does not advertise capability/u);
    expect(() =>
      assertExecuteRequestForDevice(request({ inputSha256: "b".repeat(64) }), descriptor),
    ).toThrow(/input integrity/u);
  });

  it("parses a terminal execution receipt carrying local audit evidence", () => {
    const hash = "a".repeat(64);
    const receipt = parseAgentExecutionReceipt({
      workflowExecutionId: "wf-1",
      nodeId: "health",
      attempt: 1,
      resolvedDeviceId: "windows-main",
      capability: "device.health",
      inputSha256: hash,
      startedAt: "2026-10-07T12:00:00+03:00",
      terminalState: "completed",
      outputSha256: hash,
      localAuditReceiptHash: hash,
      globalCorrelationId: "corr-1",
      traceId: "trace-1",
      agentInstanceId: "ac84a918-41bd-4f1f-a492-62b7ba16b683",
      endedAt: "2026-10-07T12:00:01+03:00",
      errorCode: null,
    });
    expect(receipt.resolvedDeviceId).toBe("windows-main");
    expect(receipt.localAuditReceiptHash).toBe(hash);
  });
});
