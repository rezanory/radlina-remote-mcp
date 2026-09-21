import { describe, expect, it } from "vitest";

import type { RadlinaComponent } from "../../src/components/contracts.js";
import { CapabilityRegistry } from "../../src/components/registry.js";

function component(id: string, capabilityId: string): RadlinaComponent {
  return {
    id,
    version: "1.0.0",
    description: id,
    capabilities: [
      {
        id: capabilityId,
        version: "1.0.0",
        description: capabilityId,
        requiredScope: "device:read",
        risk: "low",
        readOnly: true,
        idempotent: true,
        execute: async () => ({ ok: true }),
      },
    ],
  };
}

describe("CapabilityRegistry", () => {
  it("registers and resolves independently versioned component capabilities", async () => {
    const registry = new CapabilityRegistry();
    registry.register(component("example.health", "example.health.check"));

    expect(registry.listComponents()).toEqual([
      expect.objectContaining({ id: "example.health", capabilities: ["example.health.check"] }),
    ]);
    expect(registry.listCapabilities()).toEqual([
      expect.objectContaining({
        id: "example.health.check",
        componentId: "example.health",
        idempotent: true,
      }),
    ]);
    await expect(
      registry
        .resolve("example.health.check")
        .execute(
          { subject: "test", profile: "test", auth: undefined, isCancelled: () => false },
          {},
        ),
    ).resolves.toEqual({ ok: true });
  });

  it("fails closed on duplicate capability ownership without partially registering", () => {
    const registry = new CapabilityRegistry();
    registry.register(component("example.one", "example.shared"));

    expect(() => registry.register(component("example.two", "example.shared"))).toThrow(
      /already has a provider/u,
    );
    expect(registry.listComponents().map((entry) => entry.id)).toEqual(["example.one"]);
  });

  it("removes only the selected component and its providers", () => {
    const registry = new CapabilityRegistry();
    registry.register(component("example.one", "example.one.read"));
    registry.register(component("example.two", "example.two.read"));

    expect(registry.unregister("example.one")).toBe(true);
    expect(() => registry.resolve("example.one.read")).toThrow(/not available/u);
    expect(registry.resolve("example.two.read").id).toBe("example.two.read");
  });
});
