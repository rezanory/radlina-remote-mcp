import { describe, expect, it } from "vitest";

import { parseDeviceDescriptor, type DeviceDescriptor } from "../../../src/v3/device/identity.js";
import {
  DeviceRouter,
  DeviceRoutingError,
  type DeviceRegistryReader,
} from "../../../src/v3/device/router.js";

function device(deviceId: string, overrides: Partial<DeviceDescriptor> = {}): DeviceDescriptor {
  return parseDeviceDescriptor({
    deviceId,
    hostname: deviceId,
    platform: "windows",
    architecture: "x64",
    agentVersion: "3.0.0-alpha.1",
    status: "online",
    lastSeen: "2026-10-07T15:00:00+03:00",
    capabilities: ["device.health"],
    tags: ["primary"],
    trustState: "trusted",
    health: "healthy",
    ...overrides,
  });
}

function registry(devices: DeviceDescriptor[]): DeviceRegistryReader {
  return {
    get: (deviceId) => devices.find((entry) => entry.deviceId === deviceId),
    list: () => [...devices],
  };
}

describe("V3 DeviceRouter", () => {
  it("routes an exact device only when that exact device is eligible", () => {
    const router = new DeviceRouter(registry([device("windows-main"), device("windows-backup")]));
    expect(router.route({ deviceId: "windows-main" }, "device.health")).toMatchObject({
      exact: true,
      device: { deviceId: "windows-main" },
    });
  });

  it("never silently fails over an exact-device selector", () => {
    const router = new DeviceRouter(
      registry([device("windows-main", { status: "offline" }), device("windows-backup")]),
    );
    expect(() => router.route({ deviceId: "windows-main" }, "device.health")).toThrow(
      /will not fail over/u,
    );
    expect(() =>
      router.reroute({ deviceId: "windows-main" }, "device.health", "windows-main", true),
    ).toThrow(/never permits failover/u);
  });

  it("selects the healthiest stable candidate for a dynamic selector", () => {
    const router = new DeviceRouter(
      registry([
        device("z-degraded", { status: "degraded", health: "degraded" }),
        device("b-healthy"),
        device("a-healthy"),
      ]),
    );
    expect(router.route({ capability: "device.health" }, "device.health").device.deviceId).toBe(
      "a-healthy",
    );
  });

  it("supports platform, approved-tag, architecture, health and version constraints", () => {
    const router = new DeviceRouter(
      registry([
        device("windows-main"),
        device("macbook-main", {
          platform: "macos",
          architecture: "arm64",
          agentVersion: "3.0.0-alpha.2",
          tags: ["primary", "apple"],
        }),
      ]),
      { matches: (version, range) => version === range },
    );
    expect(
      router.route(
        {
          platform: "macos",
          architecture: "arm64",
          agentVersionRange: "3.0.0-alpha.2",
          health: "healthy",
        },
        "device.health",
      ).device.deviceId,
    ).toBe("macbook-main");
    expect(router.route({ approvedTag: "apple" }, "device.health").device.deviceId).toBe(
      "macbook-main",
    );
  });

  it("reroutes only dynamic selectors when policy explicitly permits it", () => {
    const router = new DeviceRouter(registry([device("a-primary"), device("b-backup")]));
    const target = { capability: "device.health" } as const;
    expect(() => router.reroute(target, "device.health", "a-primary", false)).toThrow(/disabled/u);
    expect(router.reroute(target, "device.health", "a-primary", true).device.deviceId).toBe(
      "b-backup",
    );
  });

  it("fails closed when no trusted healthy capable device matches", () => {
    const router = new DeviceRouter(
      registry([
        device("pending", { trustState: "pending" }),
        device("wrong-capability", { capabilities: ["process.exec"] }),
      ]),
    );
    expect(() => router.route({ capability: "device.health" }, "device.health")).toThrow(
      DeviceRoutingError,
    );
  });
});
