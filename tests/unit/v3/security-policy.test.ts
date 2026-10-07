import type { AuthInfo } from "@modelcontextprotocol/server";
import { describe, expect, it } from "vitest";

import { PolicyEngine } from "../../../src/policy/engine.js";
import { parseDeviceDescriptor } from "../../../src/v3/device/identity.js";
import { V3ExecutionPolicyGuard } from "../../../src/v3/security/policy.js";
import { testConfig } from "../../helpers/config.js";

const auth: AuthInfo = {
  token: "test-token",
  clientId: "test-client",
  scopes: ["device:read", "process:execute"],
  expiresAt: Math.floor(Date.now() / 1000) + 60,
};

function basePolicy() {
  return new PolicyEngine(testConfig("C:\\workspace"), {
    killSwitch: () => false,
    emergencyReadOnly: () => false,
  });
}

function device(overrides: Record<string, unknown> = {}) {
  return parseDeviceDescriptor({
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
    ...overrides,
  });
}

function request(overrides: Record<string, unknown> = {}) {
  return {
    auth,
    profile: "test",
    tool: "operator_submit",
    requiredScope: "process:execute",
    risk: "high" as const,
    capability: "process.exec",
    target: { deviceId: "windows-main" },
    device: device(),
    ...overrides,
  };
}

describe("V3 execution policy guard", () => {
  it("allows execution only after the V2 user policy and V3 device policy both pass", () => {
    const decision = new V3ExecutionPolicyGuard(basePolicy()).authorize(request());
    expect(decision).toEqual({
      allowed: true,
      reason: "user, target, trust, health and capability policy allow execution",
      resolvedDeviceId: "windows-main",
    });
  });

  it("preserves V2 fail-closed scope authorization", () => {
    const decision = new V3ExecutionPolicyGuard(basePolicy()).authorize(
      request({ auth: { ...auth, scopes: ["device:read"] } }),
    );
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("user authorization denied");
  });

  it("denies untrusted devices before dispatch", () => {
    const guard = new V3ExecutionPolicyGuard(basePolicy());
    for (const trustState of ["pending", "revoked", "quarantined"] as const) {
      const decision = guard.authorize(request({ device: device({ trustState }) }));
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain("device trust denied");
    }
  });

  it("denies exact-device and selector mismatches", () => {
    const guard = new V3ExecutionPolicyGuard(basePolicy());
    expect(guard.authorize(request({ target: { deviceId: "macbook-main" } })).reason).toContain(
      "exact device selector mismatch",
    );
    expect(guard.authorize(request({ target: { platform: "macos" } })).allowed).toBe(false);
    expect(guard.authorize(request({ target: { approvedTag: "gpu" } })).reason).toContain(
      "approved tag selector mismatch",
    );
  });

  it("denies non-dispatchable status and unhealthy devices", () => {
    const guard = new V3ExecutionPolicyGuard(basePolicy());
    for (const status of ["offline", "draining", "unknown"] as const) {
      expect(guard.authorize(request({ device: device({ status }) })).allowed).toBe(false);
    }
    expect(guard.authorize(request({ device: device({ health: "unhealthy" }) })).allowed).toBe(
      false,
    );
  });

  it("denies capabilities not advertised by the resolved device", () => {
    const decision = new V3ExecutionPolicyGuard(basePolicy()).authorize(
      request({ capability: "filesystem.info" }),
    );
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("does not advertise capability");
  });
});
