import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { persistTrustedOwnerConfig, trustedOwnerConfig } from "../../src/admin/trusted-owner.js";
import { loadConfig } from "../../src/config/index.js";
import { testConfig } from "../helpers/config.js";

describe("trusted owner mode", () => {
  it("raises the default profile to full filesystem and direct executable parity", () => {
    const next = trustedOwnerConfig(testConfig("C:\\workspace"));
    const profile = next.profiles[next.policy.defaultProfile]!;
    expect(profile.roots).toEqual(["C:\\"]);
    expect(profile.allowShell).toBe(true);
    expect(profile.allowTrash).toBe(true);
    expect(profile.envAllowlist).toContain("PATH");
    expect(next.policy.rateLimitPerMinute).toBe(10_000);
    expect(next.policy.maxSessions).toBe(256);
  });

  it("persists schema-valid configuration atomically", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "radlina-owner-"));
    try {
      const file = path.join(dir, "local.yaml");
      const receipt = await persistTrustedOwnerConfig(file, testConfig(dir));
      expect(receipt).toMatchObject({
        profile: "test",
        roots: ["C:\\"],
        allowShell: true,
        allowTrash: true,
        restartRequired: true,
      });
      const loaded = await loadConfig(file);
      expect(loaded.profiles["test"]!.allowShell).toBe(true);
      expect(loaded.profiles["test"]!.roots).toEqual(["C:\\"]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
