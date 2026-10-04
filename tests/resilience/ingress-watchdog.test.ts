import { describe, expect, it } from "vitest";

import { IngressWatchdog } from "../../src/reliability/ingress.js";
import { testConfig } from "../helpers/config.js";

describe("public ingress watchdog", () => {
  it("retries transient public failures before declaring the public ingress down", async () => {
    const config = testConfig("C:\\radlina-ingress-retry-test");
    config.server.publicUrl = "https://device.example.test";
    let publicAttempts = 0;
    const watchdog = new IngressWatchdog(config, {
      fetch: async (input) => {
        if (String(input).includes("device.example.test")) {
          publicAttempts += 1;
          if (publicAttempts < 3) {
            throw new Error("simulated transient public ingress failure");
          }
        }
        return new Response(null, { status: 401 });
      },
    });

    watchdog.enable();
    const snapshot = await watchdog.probe();

    expect(snapshot).toMatchObject({ localReady: true, publicReady: true });
    expect(snapshot.public.consecutiveFailures).toBe(0);
    expect(snapshot.public.detail).toContain("after 3 attempts");
    expect(publicAttempts).toBe(3);
  });

  it("tracks LOCAL_READY and PUBLIC_READY independently with bounded failure telemetry", async () => {
    const config = testConfig("C:\\radlina-ingress-test");
    config.server.publicUrl = "https://device.example.test";
    let publicDown = false;
    const requested: string[] = [];
    const watchdog = new IngressWatchdog(config, {
      fetch: async (input) => {
        const url = String(input);
        requested.push(url);
        if (url.includes("device.example.test") && publicDown) {
          throw new Error("simulated public ingress outage");
        }
        return new Response(null, { status: 401 });
      },
    });

    expect(watchdog.snapshot()).toMatchObject({
      enabled: false,
      localReady: null,
      publicReady: null,
    });

    watchdog.enable();
    const healthy = await watchdog.probe();
    expect(healthy).toMatchObject({ localReady: true, publicReady: true });
    expect(healthy.public.lastSuccessAt).toBeTruthy();
    expect(healthy.public.consecutiveFailures).toBe(0);
    expect(healthy.public.latencyMs).toBeGreaterThanOrEqual(0);
    expect(requested.some((url) => url === "https://device.example.test/mcp")).toBe(true);

    publicDown = true;
    const degraded = await watchdog.probe();
    expect(degraded.localReady).toBe(true);
    expect(degraded.publicReady).toBe(false);
    expect(degraded.public.lastFailureAt).toBeTruthy();
    expect(degraded.public.lastSuccessAt).toBe(healthy.public.lastSuccessAt);
    expect(degraded.public.consecutiveFailures).toBe(1);
    expect(degraded.public.detail).toContain("simulated public ingress outage");
  });

  it("records sanitized Tailscale state separately from public HTTP reachability", async () => {
    const config = testConfig("C:\\radlina-tailscale-test");
    config.server.publicUrl = "https://device.example.ts.net";
    let tailscaleOnline = true;
    const watchdog = new IngressWatchdog(config, {
      fetch: async () => new Response(null, { status: 401 }),
      tailscaleStatus: async () => ({
        BackendState: tailscaleOnline ? "Running" : "Stopped",
        Health: tailscaleOnline ? [] : ["network-map-stale"],
        Self: { Online: tailscaleOnline, Relay: "fra" },
        SecretMaterialThatMustNotLeak: "nodekey:redacted-by-design",
      }),
    });

    watchdog.enable();
    const healthy = await watchdog.probe();
    expect(healthy).toMatchObject({ localReady: true, publicReady: true, tailscaleReady: true });
    expect(healthy.tailscale).toMatchObject({
      backendState: "Running",
      selfOnline: true,
      relay: "fra",
      healthIssueCount: 0,
      consecutiveFailures: 0,
    });
    expect(JSON.stringify(healthy)).not.toContain("nodekey:");

    tailscaleOnline = false;
    const degraded = await watchdog.probe();
    expect(degraded.publicReady).toBe(true);
    expect(degraded.tailscaleReady).toBe(false);
    expect(degraded.tailscale).toMatchObject({
      backendState: "Stopped",
      selfOnline: false,
      healthIssueCount: 1,
      consecutiveFailures: 1,
    });
  });

  it("keeps local ingress ready when public startup returns 502 and records later recovery", async () => {
    const config = testConfig("C:\\radlina-startup-ingress-test");
    config.server.publicUrl = "https://device.example.test";
    let publicStatus = 502;
    const watchdog = new IngressWatchdog(config, {
      fetch: async (input) =>
        new Response(null, {
          status: String(input).includes("device.example.test") ? publicStatus : 401,
        }),
    });

    watchdog.enable();
    const startup = await watchdog.probe();
    expect(startup).toMatchObject({ localReady: true, publicReady: false });
    expect(startup.public).toMatchObject({ statusCode: 502, consecutiveFailures: 1 });

    publicStatus = 401;
    const recovered = await watchdog.probe();
    expect(recovered).toMatchObject({ localReady: true, publicReady: true });
    expect(recovered.public).toMatchObject({ statusCode: 401, consecutiveFailures: 0 });
    expect(recovered.public.lastSuccessAt).toBeTruthy();
  });
});
