import type { AuthInfo } from "@modelcontextprotocol/server";
import { describe, expect, it, vi } from "vitest";

import type { RadlinaComponent } from "../../../src/components/contracts.js";
import { CapabilityRegistry } from "../../../src/components/registry.js";
import { PolicyEngine } from "../../../src/policy/engine.js";
import { canonicalJson, sha256 } from "../../../src/utils/json.js";
import {
  HmacDistributedAuditSigner,
  verifyDistributedAuditRecord,
} from "../../../src/v3/audit/distributed.js";
import {
  CapabilityRuntimePolicyDenied,
  V3CapabilityRuntime,
  type LocalExecutionAuditPort,
} from "../../../src/v3/capability/runtime.js";
import { parseDeviceDescriptor } from "../../../src/v3/device/identity.js";
import { V3ExecutionPolicyGuard } from "../../../src/v3/security/policy.js";
import { testConfig } from "../../helpers/config.js";

const auth: AuthInfo = {
  token: "token",
  clientId: "client",
  scopes: ["device:read"],
  expiresAt: Math.floor(Date.now() / 1000) + 60,
};

const device = parseDeviceDescriptor({
  deviceId: "windows-main",
  hostname: "LAPTOP-13QINEIF",
  platform: "windows",
  architecture: "x64",
  agentVersion: "3.0.0-alpha.1",
  status: "online",
  lastSeen: "2026-10-07T14:00:00+03:00",
  capabilities: ["device.health"],
  tags: ["primary"],
  trustState: "trusted",
  health: "healthy",
});

function request(overrides: Record<string, unknown> = {}) {
  const input = { probe: true };
  return {
    requestId: "bf23b856-25d3-4bf0-bad9-8d9c003427df",
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
  };
}

function runtime(
  execute: RadlinaComponent["capabilities"][number]["execute"],
  localAudit: LocalExecutionAuditPort = { record: async () => "c".repeat(64) },
) {
  const registry = new CapabilityRegistry();
  registry.register({
    id: "radlina.device",
    version: "3.0.0",
    description: "test",
    capabilities: [
      {
        id: "device.health",
        version: "1.0.0",
        description: "health",
        requiredScope: "device:read",
        risk: "low",
        readOnly: true,
        idempotent: true,
        execute,
      },
    ],
  });
  const guard = new V3ExecutionPolicyGuard(
    new PolicyEngine(testConfig("C:\\workspace"), {
      killSwitch: () => false,
      emergencyReadOnly: () => false,
    }),
  );
  const signer = new HmacDistributedAuditSigner(Buffer.alloc(32, 3));
  const times = ["2026-10-07T14:00:00+03:00", "2026-10-07T14:00:01+03:00"];
  return {
    signer,
    runtime: new V3CapabilityRuntime(registry, guard, localAudit, signer, () => times.shift()!),
  };
}

function context(overrides: Record<string, unknown> = {}) {
  return {
    auth,
    subject: "owner",
    profile: "test",
    device,
    agentInstanceId: "99a1533f-59a8-44dc-b0ea-40d189eb5e38",
    isCancelled: () => false,
    ...overrides,
  };
}

describe("V3 capability runtime", () => {
  it("executes one authorized capability and returns local/global execution evidence", async () => {
    const { runtime: executor, signer } = runtime(async () => ({ status: "healthy" }));
    const outcome = await executor.execute(request(), context());

    expect(outcome.ok).toBe(true);
    if (!outcome.ok) throw new Error("expected success");
    expect(outcome.result).toEqual({ status: "healthy" });
    expect(outcome.receipt).toMatchObject({
      resolvedDeviceId: "windows-main",
      terminalState: "completed",
      capability: "device.health",
    });
    expect(verifyDistributedAuditRecord(outcome.audit, signer)).toBe(true);
    expect(outcome.audit.localAuditReceiptHash).toBe("c".repeat(64));
  });

  it("fails before execution when V2 user scope policy denies the capability", async () => {
    const execute = vi.fn(async () => ({ status: "healthy" }));
    const localAudit = { record: vi.fn(async () => "c".repeat(64)) };
    const { runtime: executor } = runtime(execute, localAudit);

    await expect(
      executor.execute(request(), context({ auth: { ...auth, scopes: [] } })),
    ).rejects.toThrow(CapabilityRuntimePolicyDenied);
    expect(execute).not.toHaveBeenCalled();
    expect(localAudit.record).not.toHaveBeenCalled();
  });

  it("rejects tampered input identity before provider execution", async () => {
    const execute = vi.fn(async () => ({ status: "healthy" }));
    const { runtime: executor } = runtime(execute);
    await expect(
      executor.execute(request({ inputSha256: "b".repeat(64) }), context()),
    ).rejects.toThrow(/input integrity/u);
    expect(execute).not.toHaveBeenCalled();
  });

  it("returns a failed receipt and signed audit record when execution fails", async () => {
    const { runtime: executor, signer } = runtime(async () => {
      throw new Error("probe failed");
    });
    const outcome = await executor.execute(request(), context());

    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("expected failure");
    expect(outcome.error.message).toBe("probe failed");
    expect(outcome.receipt.terminalState).toBe("failed");
    expect(outcome.receipt.outputSha256).toBeNull();
    expect(verifyDistributedAuditRecord(outcome.audit, signer)).toBe(true);
  });

  it("records cancellation as a cancelled terminal receipt", async () => {
    const { runtime: executor } = runtime(async () => {
      throw new Error("cancelled during execution");
    });
    const outcome = await executor.execute(request(), context({ isCancelled: () => true }));
    expect(outcome.ok).toBe(false);
    expect(outcome.receipt.terminalState).toBe("cancelled");
  });
});
