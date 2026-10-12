import os from "node:os";
import path from "node:path";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import type { AuthInfo } from "@modelcontextprotocol/server";
import { describe, expect, it } from "vitest";
import { Store } from "../../../src/persistence/store.js";
import { SqliteDeviceRegistry } from "../../../src/v3/device/registry.js";
import { V3WindowsScopedFiles } from "../../../src/v3/gateway/windows-scoped-files.js";
import { testConfig } from "../../helpers/config.js";

const owner: AuthInfo = {
  token: "local-unit-test-only",
  clientId: "approved-v3-client",
  scopes: ["device:read", "filesystem:read", "filesystem:write"],
  expiresAt: Math.floor(Date.now() / 1000) + 300,
  extra: { sub: "owner" },
};
const readonly: AuthInfo = {
  ...owner,
  scopes: ["device:read", "filesystem:read"],
};
describe("V3 Windows native scoped files", () => {
  it("enforces exact trusted host, OAuth scope, safe paths, readback and idempotency", async () => {
    if (process.platform !== "win32") return;
    const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-scoped-files-"));
    const workspace = path.join(root, "desktop");
    await mkdir(workspace);
    const config = testConfig(root);
    config.storage.directory = path.join(root, "state");
    const store = new Store(config.storage.directory);
    const registry = new SqliteDeviceRegistry(path.join(root, "v3-devices.sqlite3"));
    registry.register({
      deviceId: "windows-main",
      hostname: os.hostname(),
      platform: "windows",
      architecture: "x64",
      agentVersion: "3.0.0-alpha.1",
      status: "degraded",
      lastSeen: new Date().toISOString(),
      capabilities: ["device.health"],
      tags: [],
      trustState: "pending",
      health: "unknown",
    });
    const record = registry.require("windows-main");
    registry.db
      .prepare("UPDATE v3_devices SET descriptor_json=? WHERE device_id=?")
      .run(JSON.stringify({ ...record, trustState: "trusted" }), "windows-main");
    const files = new V3WindowsScopedFiles(config, store, registry, workspace, root);
    const idempotencyKey = randomUUID();
    try {
      const request = {
        targetDeviceId: "windows-main" as const,
        relativePath: "نازی.txt",
        content: "عسلی",
        overwrite: false,
        idempotencyKey,
      };
      await expect(files.write(request, readonly)).rejects.toThrow(/scope/u);
      await expect(
        files.write({ ...request, relativePath: "..\\escape.txt" }, owner),
      ).rejects.toThrow(/approved Windows root/u);
      await expect(
        files.write({ ...request, relativePath: "C:\\\\Windows\\\\system.ini" }, owner),
      ).rejects.toThrow(/approved Windows root/u);
      const first = (await files.write(request, owner)) as Record<string, unknown>;
      expect(first).toMatchObject({
        targetDeviceId: "windows-main",
        readbackVerified: true,
        bytes: Buffer.byteLength("عسلی", "utf8"),
        crossDeviceProductionAcceptance: false,
      });
      expect(await readFile(path.join(workspace, "نازی.txt"), "utf8")).toBe("عسلی");
      expect(await files.write(request, owner)).toEqual(first);
      await expect(files.write({ ...request, content: "different" }, owner)).rejects.toThrow(
        /idempotency/u,
      );
      const readable = await files.read(
        {
          targetDeviceId: "windows-main",
          relativePath: "نازی.txt",
        },
        readonly,
      );
      expect(readable).toMatchObject({ content: "عسلی", bytes: 8 });
      await expect(
        files.write({ ...request, idempotencyKey: randomUUID() }, owner),
      ).rejects.toThrow();
      config.policy.killSwitch = true;
      await expect(
        files.read({ targetDeviceId: "windows-main", relativePath: "نازی.txt" }, readonly),
      ).rejects.toThrow(/emergency/u);
    } finally {
      await files.close();
      registry.close();
      store.close();
      await rm(root, { recursive: true, force: true });
    }
  }, 30000);
});
