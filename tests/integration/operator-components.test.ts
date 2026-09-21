import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import type { AuthInfo } from "@modelcontextprotocol/server";
import { afterEach, describe, expect, it } from "vitest";

import { createBuiltinComponents } from "../../src/components/builtin.js";
import { CapabilityRegistry } from "../../src/components/registry.js";
import { OperatorManager } from "../../src/operator/manager.js";
import { Store } from "../../src/persistence/store.js";
import { PolicyEngine } from "../../src/policy/engine.js";
import { FilesystemService } from "../../src/tools/filesystem/service.js";
import { ProcessManager } from "../../src/tools/process/manager.js";
import { testConfig } from "../helpers/config.js";

const cleanup: string[] = [];
const admin: AuthInfo = {
  token: "operator-components",
  clientId: "operator-components",
  scopes: ["admin"],
  expiresAt: Math.floor(Date.now() / 1000) + 60,
};

afterEach(async () => {
  for (const directory of cleanup.splice(0)) await rm(directory, { recursive: true, force: true });
});

async function waitForTerminal(manager: OperatorManager, jobId: string) {
  for (let attempt = 0; attempt < 600; attempt += 1) {
    const status = (await manager.status("subject", jobId)) as {
      status: string;
      steps: Array<{ status: string; result: Record<string, unknown> | null }>;
    };
    if (!["queued", "running"].includes(status.status)) return status;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("operator integration plan timed out");
}

describe("built-in V2 operator components", () => {
  it("verifies a filesystem precondition then executes and verifies a real process", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "radlina-operator-components-"));
    cleanup.push(root);
    const marker = path.join(root, "marker.txt");
    await writeFile(marker, "ready\n", "utf8");
    const config = testConfig(root);
    const profile = config.profiles["test"]!;
    profile.commands = [{ executable: process.execPath, argumentPatterns: [".*"] }];
    const store = new Store(config.storage.directory);
    try {
      const policy = new PolicyEngine(config, {
        killSwitch: () => false,
        emergencyReadOnly: () => false,
      });
      const filesystems = new Map([
        ["test", new FilesystemService([root], 1024 * 1024, path.join(root, ".trash"), false)],
      ]);
      const processes = new ProcessManager(config, store, policy);
      const registry = new CapabilityRegistry();
      for (const component of createBuiltinComponents({
        config,
        filesystems,
        processes,
        startedAt: Date.now(),
      }))
        registry.register(component);
      const manager = new OperatorManager(store, policy, registry);

      const submitted = await manager.submit(admin, "subject", "test", {
        title: "real component execution",
        steps: [
          {
            id: "precondition",
            capability: "filesystem.info",
            input: { path: marker, expectedType: "file" },
            maxAttempts: 2,
          },
          {
            id: "execute",
            capability: "process.exec",
            input: {
              executable: process.execPath,
              args: ["--version"],
              cwd: root,
              successExitCodes: [0],
            },
            maxAttempts: 1,
          },
        ],
      });
      const result = await waitForTerminal(manager, submitted.jobId);
      expect(result.status).toBe("completed");
      expect(result.steps.map((step) => step.status)).toEqual(["completed", "completed"]);
      expect(result.steps[0]?.result?.["verified"]).toBe(true);
      expect(result.steps[1]?.result?.["verified"]).toBe(true);
      expect(result.steps[1]?.result?.["exitCode"]).toBe(0);
    } finally {
      store.close();
    }
  });
});
