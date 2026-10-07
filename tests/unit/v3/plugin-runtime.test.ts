import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { CapabilityRegistry } from "../../../src/components/registry.js";
import { HmacDistributedAuditSigner } from "../../../src/v3/audit/distributed.js";
import { FilesystemArtifactBus } from "../../../src/v3/artifact/bus.js";
import {
  PluginRuntime,
  PluginRuntimeError,
  type IsolatedPluginHost,
} from "../../../src/v3/plugin/runtime.js";

const roots: string[] = [];

async function runtime() {
  const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-plugin-"));
  roots.push(root);
  const registry = new CapabilityRegistry();
  const invoke = vi.fn<IsolatedPluginHost["invoke"]>(async ({ payload }) => ({
    echoed: payload,
  }));
  const shutdown = vi.fn<IsolatedPluginHost["shutdown"]>(async () => undefined);
  const host: IsolatedPluginHost = { invoke, shutdown };
  const signer = new HmacDistributedAuditSigner(Buffer.alloc(32, 6));
  return {
    registry,
    host,
    invoke,
    shutdown,
    signer,
    runtime: new PluginRuntime(
      registry,
      { load: async () => host },
      new FilesystemArtifactBus(path.join(root, "artifacts")),
      signer,
      () => "2026-10-07T16:00:00+03:00",
    ),
  };
}

function manifest() {
  return {
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
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("V3 plugin runtime", () => {
  it("loads an isolated plugin host and registers namespaced capabilities", async () => {
    const value = await runtime();
    const loaded = await value.runtime.load(manifest());
    expect(value.runtime.list()).toEqual(["echo-plugin"]);
    expect(value.registry.listCapabilities()).toEqual([
      expect.objectContaining({
        id: "echo-plugin.echo",
        componentId: "plugin.echo-plugin",
      }),
    ]);
    expect(loaded.receiptArtifact.mediaType).toContain("plugin-load-receipt");
    expect(value.runtime.verifyLoadReceipt(loaded.receipt)).toBe(true);
  });

  it("executes plugin code only through the registered isolated host boundary", async () => {
    const value = await runtime();
    await value.runtime.load(manifest());
    const provider = value.registry.resolve("echo-plugin.echo");
    await expect(
      provider.execute(
        {
          subject: "owner",
          profile: "test",
          auth: undefined,
          isCancelled: () => false,
        },
        { value: 1 },
      ),
    ).resolves.toEqual({ echoed: { value: 1 } });
    const call = value.invoke.mock.calls[0]?.[0];
    expect(call?.capability).toBe("echo-plugin.echo");
    expect(call?.payload).toEqual({ value: 1 });
    expect(call?.context.subject).toBe("owner");
    expect(call?.context.profile).toBe("test");
  });

  it("never passes authentication credentials into the plugin host context", async () => {
    const value = await runtime();
    await value.runtime.load(manifest());
    const provider = value.registry.resolve("echo-plugin.echo");
    await provider.execute(
      {
        subject: "owner",
        profile: "test",
        auth: {
          token: "secret-token",
          clientId: "client",
          scopes: ["device:read"],
          expiresAt: Math.floor(Date.now() / 1000) + 60,
        },
        isCancelled: () => false,
      },
      {},
    );
    const call = value.invoke.mock.calls[0]?.[0];
    expect(call).toBeDefined();
    expect(Object.prototype.hasOwnProperty.call(call!.context, "auth")).toBe(false);
  });

  it("rejects duplicate loads and improperly namespaced capabilities", async () => {
    const value = await runtime();
    await value.runtime.load(manifest());
    await expect(value.runtime.load(manifest())).rejects.toThrow(PluginRuntimeError);
    await expect(
      value.runtime.load({
        ...manifest(),
        pluginId: "other-plugin",
        capabilities: [{ ...manifest().capabilities[0], id: "echo-plugin.echo" }],
      }),
    ).rejects.toThrow(/namespaced/u);
  });

  it("unregisters capabilities and shuts down the isolated host", async () => {
    const value = await runtime();
    await value.runtime.load(manifest());
    await expect(value.runtime.unload("echo-plugin")).resolves.toBe(true);
    expect(value.runtime.list()).toEqual([]);
    expect(() => value.registry.resolve("echo-plugin.echo")).toThrow(/not available/u);
    expect(value.shutdown).toHaveBeenCalledTimes(1);
  });
});
