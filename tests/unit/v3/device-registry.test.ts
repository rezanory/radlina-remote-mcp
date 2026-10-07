import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { parseDeviceDescriptor, type DeviceDescriptor } from "../../../src/v3/device/identity.js";
import { DeviceRegistryConflict, SqliteDeviceRegistry } from "../../../src/v3/device/registry.js";

const roots: string[] = [];

async function registry(): Promise<SqliteDeviceRegistry> {
  const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-device-registry-"));
  roots.push(root);
  return new SqliteDeviceRegistry(path.join(root, "devices.sqlite3"));
}

function device(overrides: Partial<DeviceDescriptor> = {}): DeviceDescriptor {
  return parseDeviceDescriptor({
    deviceId: "windows-main",
    hostname: "LAPTOP-13QINEIF",
    platform: "windows",
    architecture: "x64",
    agentVersion: "3.0.0-alpha.1",
    status: "online",
    lastSeen: "2026-10-07T12:00:00+03:00",
    capabilities: ["device.health"],
    tags: ["primary"],
    trustState: "pending",
    health: "healthy",
    ...overrides,
  });
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("V3 SqliteDeviceRegistry", () => {
  it("registers a new device only in pending trust", async () => {
    const runtime = await registry();
    expect(runtime.register(device())).toMatchObject({
      replayed: false,
      device: { deviceId: "windows-main", trustState: "pending" },
    });
    expect(() =>
      runtime.register(device({ deviceId: "trusted-new", trustState: "trusted" })),
    ).toThrow(/must start with pending trust/u);
    runtime.close();
  });

  it("replays stable registration without mutating identity or trust", async () => {
    const runtime = await registry();
    runtime.register(device());
    expect(runtime.register(device())).toMatchObject({ replayed: true });
    expect(runtime.require("windows-main").trustState).toBe("pending");
    runtime.close();
  });

  it("rejects a reused logical device id with changed stable identity", async () => {
    const runtime = await registry();
    runtime.register(device());
    expect(() => runtime.register(device({ hostname: "OTHER" }))).toThrow(DeviceRegistryConflict);
    expect(() => runtime.register(device({ platform: "macos", architecture: "arm64" }))).toThrow(
      /platform changed/u,
    );
    runtime.close();
  });

  it("applies heartbeat updates without allowing trust mutation", async () => {
    const runtime = await registry();
    runtime.register(device());
    const updated = runtime.heartbeat("windows-main", {
      lastSeen: "2026-10-07T12:05:00+03:00",
      status: "degraded",
      health: "degraded",
      agentVersion: "3.0.0-alpha.2",
      capabilities: ["device.health", "process.exec"],
    });
    expect(updated).toMatchObject({
      status: "degraded",
      health: "degraded",
      agentVersion: "3.0.0-alpha.2",
      trustState: "pending",
    });
    expect(runtime.capabilities("windows-main")).toEqual(["device.health", "process.exec"]);
    runtime.close();
  });

  it("lists devices deterministically and fails closed for missing ids", async () => {
    const runtime = await registry();
    runtime.register(device({ deviceId: "windows-main" }));
    runtime.register(
      device({
        deviceId: "macbook-main",
        hostname: "MacBook",
        platform: "macos",
        architecture: "arm64",
      }),
    );
    expect(runtime.list().map((entry) => entry.deviceId)).toEqual(["macbook-main", "windows-main"]);
    expect(() => runtime.require("missing")).toThrow(/was not found/u);
    runtime.close();
  });
});
