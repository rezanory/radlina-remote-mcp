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
  it("runs plugin code in a separate permission-enabled Node process", async () => {
    const factory = new ProcessIsolatedPluginHostFactory(
      process.execPath,
      resolver(
        "async ({ payload, context }) => ({ payload, subject: context.subject, childPid: process.pid, fsReadAllowed: process.permission?.has('fs.read') ?? null })",
      ),
      5_000,
    );
    const host = await factory.load(manifest);
    const result = (await host.invoke({
      capability: "echo-plugin.echo",
      payload: { value: 1 },
      context: {
        subject: "owner",
        profile: "test",
        isCancelled: () => false,
      },
    })) as {
      payload: unknown;
      subject: string;
      childPid: number;
      fsReadAllowed: boolean | null;
    };

    expect(result.payload).toEqual({ value: 1 });
    expect(result.subject).toBe("owner");
    expect(result.childPid).not.toBe(process.pid);
    expect(result.fsReadAllowed).toBe(false);
    await host.shutdown();
  });

  it("does not inherit parent environment values or auth fields", async () => {
    process.env["RADLINA_PLUGIN_TEST_SECRET"] = "parent-secret";
    try {
      const factory = new ProcessIsolatedPluginHostFactory(
        process.execPath,
        resolver(
          "async ({ context }) => ({ contextKeys: Object.keys(context).sort(), inheritedSecret: process.env.RADLINA_PLUGIN_TEST_SECRET ?? null })",
        ),
        5_000,
      );
      const host = await factory.load(manifest);
      await expect(
        host.invoke({
          capability: "echo-plugin.echo",
          payload: {},
          context: {
            subject: "owner",
            profile: "test",
            isCancelled: () => false,
          },
        }),
      ).resolves.toEqual({
        contextKeys: ["cancelled", "profile", "subject"],
        inheritedSecret: null,
      });
      await host.shutdown();
    } finally {
      delete process.env["RADLINA_PLUGIN_TEST_SECRET"];
    }
  });

  it("fails closed for undeclared capabilities", async () => {
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
