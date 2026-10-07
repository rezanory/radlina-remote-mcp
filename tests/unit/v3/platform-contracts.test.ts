import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import {
  assertPlatformAdapterConformance,
  type PlatformAdapter,
  type PlatformKind,
} from "../../../src/v3/platform/contracts.js";

function fakeAdapter(platform: PlatformKind): PlatformAdapter {
  return {
    id: `${platform}-fixture`,
    platform,
    secrets: {
      protect: async (value) => value,
      unprotect: async (value) => value,
    },
    process: {
      start: async () => ({ sessionId: "process-1", pid: 1 }),
      read: async (sessionId) => ({ sessionId, status: "complete", exitCode: 0 }),
      interact: async () => undefined,
      terminate: async () => undefined,
    },
    filesystem: {
      getFileInfo: async (path) => ({ path, kind: "file", size: 0, modifiedAt: null }),
      readFile: async () => new Uint8Array(),
      writeFile: async () => undefined,
      listDirectory: async () => [],
    },
    search: {
      start: async () => ({ searchId: "search-1" }),
      status: async (searchId) => ({ searchId, status: "complete", resultCount: 0 }),
      results: async () => [],
      cancel: async () => undefined,
    },
    lifecycle: {
      readiness: async () => ({ ready: true }),
      scheduleRestart: async () => undefined,
    },
    deviceInfo: {
      getDeviceInfo: async () => ({
        hostname: `${platform}-fixture`,
        platform,
        architecture: platform === "windows" ? "x64" : "arm64",
        agentVersion: "3.0.0-alpha.1",
        health: "healthy",
      }),
    },
  };
}

describe("V3 platform contracts", () => {
  it.each(["windows", "macos"] as const)(
    "accepts a complete %s adapter fixture through the same platform-neutral contract",
    async (platform) => {
      const info = await assertPlatformAdapterConformance(fakeAdapter(platform));
      expect(info.platform).toBe(platform);
      expect(info.health).toBe("healthy");
    },
  );

  it("rejects adapter/device platform identity mismatch", async () => {
    const adapter = fakeAdapter("windows");
    adapter.deviceInfo = {
      getDeviceInfo: async () => ({
        hostname: "wrong",
        platform: "macos",
        architecture: "arm64",
        agentVersion: "3.0.0-alpha.1",
        health: "healthy",
      }),
    };

    await expect(assertPlatformAdapterConformance(adapter)).rejects.toThrow(
      /platform adapter mismatch/u,
    );
  });

  it("keeps the platform contract package free of Node/OS implementation imports", async () => {
    const source = await readFile(
      new URL("../../../src/v3/platform/contracts.ts", import.meta.url),
      "utf8",
    );

    expect(source).not.toMatch(/from\s+["']node:/u);
    expect(source).not.toMatch(/require\s*\(/u);
    expect(source).not.toContain("WinSW");
    expect(source).not.toContain("launchd");
    expect(source).not.toContain("DPAPI");
    expect(source).not.toContain("Keychain");
    expect(source).not.toContain("Tailscale");
  });
});
