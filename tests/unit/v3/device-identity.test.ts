import { describe, expect, it } from "vitest";

import {
  assertAgentIdentityMatchesDevice,
  assertTrustedAgentForDevice,
  assertTrustedDevice,
  DeviceIdentityError,
  parseAgentIdentityClaim,
  parseDeviceDescriptor,
} from "../../../src/v3/device/identity.js";

const fingerprint = "a".repeat(64);

function descriptor(overrides: Record<string, unknown> = {}) {
  return parseDeviceDescriptor({
    deviceId: "windows-main",
    hostname: "LAPTOP-13QINEIF",
    platform: "windows",
    architecture: "x64",
    agentVersion: "3.0.0-alpha.1",
    status: "online",
    lastSeen: "2026-10-07T12:00:00+03:00",
    capabilities: ["device.health", "process.exec"],
    tags: ["primary", "owner"],
    trustState: "trusted",
    health: "healthy",
    ...overrides,
  });
}

function claim(overrides: Record<string, unknown> = {}) {
  return parseAgentIdentityClaim({
    deviceId: "windows-main",
    agentInstanceId: "e420f3d8-6b3a-4f9a-8d31-6dadb327b6be",
    agentVersion: "3.0.0-alpha.1",
    publicKeyFingerprint: fingerprint,
    enrolledAt: "2026-10-07T12:00:00+03:00",
    ...overrides,
  });
}

describe("V3 device identity", () => {
  it("accepts the frozen first-class Windows device descriptor", () => {
    const parsed = descriptor();
    expect(parsed.deviceId).toBe("windows-main");
    expect(parsed.platform).toBe("windows");
    expect(parsed.trustState).toBe("trusted");
  });

  it("accepts a macOS descriptor through the same identity contract", () => {
    const parsed = descriptor({
      deviceId: "macbook-main",
      hostname: "MacBook",
      platform: "macos",
      architecture: "arm64",
      capabilities: ["device.health"],
      tags: ["primary"],
    });
    expect(parsed.platform).toBe("macos");
    expect(parsed.architecture).toBe("arm64");
  });

  it("rejects malformed logical device ids", () => {
    expect(() => descriptor({ deviceId: "Windows Main" })).toThrow();
    expect(() => descriptor({ deviceId: "windows_main" })).toThrow();
  });

  it("rejects duplicate capabilities and tags", () => {
    expect(() => descriptor({ capabilities: ["device.health", "device.health"] })).toThrow(
      /capabilities must be unique/u,
    );
    expect(() => descriptor({ tags: ["primary", "primary"] })).toThrow(/tags must be unique/u);
  });

  it("fails closed for pending, revoked, or quarantined device trust", () => {
    for (const trustState of ["pending", "revoked", "quarantined"] as const) {
      expect(() => assertTrustedDevice(descriptor({ trustState }))).toThrow(DeviceIdentityError);
    }
  });

  it("requires agent claims to bind to the exact logical device and version", () => {
    expect(() =>
      assertAgentIdentityMatchesDevice(descriptor(), claim({ deviceId: "macbook-main" })),
    ).toThrow(/device mismatch/u);
    expect(() =>
      assertAgentIdentityMatchesDevice(descriptor(), claim({ agentVersion: "3.0.0-alpha.2" })),
    ).toThrow(/agent version mismatch/u);
  });

  it("accepts a trusted agent only when trust and exact identity both match", () => {
    expect(() => assertTrustedAgentForDevice(descriptor(), claim())).not.toThrow();
    expect(() =>
      assertTrustedAgentForDevice(descriptor({ trustState: "revoked" }), claim()),
    ).toThrow(/not trusted/u);
  });
});
