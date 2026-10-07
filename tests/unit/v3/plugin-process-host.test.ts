import { describe, expect, it } from "vitest";

import {
  ProcessIsolatedPluginHostFactory,
  type PluginSourceResolver,
} from "../../../src/v3/plugin/process-host.js";
import type { PluginManifest } from "../../../src/v3/plugin/runtime.js";

const manifest: PluginManifest = {
  pluginId: "echo-plugin",
  version: "1.0.0",
  description: "Echo plugin",
  capabilities: [
    {
      id: "echo-plugin.echo",
      version: "1.0.0",
      description: "Echo",
      requiredScope: "device:read",
      risk: "low",
      readOnly: true,
      idempotent: true,
    },
  ],
};

function resolver(source: string): PluginSourceResolver {
  return { resolve: async () => source };
}

describe("V3 process-isolated plugin host", () => {
  it("runs in a separate Node process with filesystem permission disabled", async () => {
    const factory = new ProcessIsolatedPluginHostFactory(
      process.execPath,
      resolver(
        "async ({ payload }) => ({ payload, childPid: process.pid, fsReadAllowed: process.permission?.has('fs.read') ?? null })",
      ),
      5_000,
    );
    const host = await factory.load(manifest);
    const result = (await host.invoke({
      capability: "echo-plugin.echo",
      payload: { value: 1 },
      context: { subject: "owner", profile: "test", isCancelled: () => false },
    })) as { payload: unknown; childPid: number; fsReadAllowed: boolean | null };

    expect(result.payload).toEqual({ value: 1 });
    expect(result.childPid).not.toBe(process.pid);
    expect(result.fsReadAllowed).toBe(false);
    await host.shutdown();
  });

  it("fails closed for capabilities not declared by the plugin manifest", async () => {
    const factory = new ProcessIsolatedPluginHostFactory(
      process.execPath,
      resolver("async () => ({ ok: true })"),
      5_000,
    );
    const host = await factory.load(manifest);
    await expect(
      host.invoke({
        capability: "other-plugin.run",
        payload: {},
        context: { subject: "owner", profile: "test", isCancelled: () => false },
      }),
    ).rejects.toThrow(/not declared/u);
    await host.shutdown();
  });
});
