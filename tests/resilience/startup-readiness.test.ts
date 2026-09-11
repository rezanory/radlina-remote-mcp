import { once } from "node:events";
import { createServer, type Server } from "node:http";

import { afterEach, describe, expect, it } from "vitest";

import { postBindReadiness } from "../../src/app-entry.js";

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          server.close(() => resolve());
        }),
    ),
  );
});

async function listen(statusCode: number): Promise<number> {
  const server = createServer((_request, response) => {
    response.statusCode = statusCode;
    response.end();
  });
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("TEST_SERVER_ADDRESS_UNAVAILABLE");
  return address.port;
}

function runtimeStub(): {
  runtime: Parameters<typeof postBindReadiness>[0];
  ingressCalls: { value: number };
} {
  const ingressCalls = { value: 0 };
  const runtime = {
    config: {
      policy: { defaultProfile: "radlina" },
      profiles: { radlina: {} },
    },
    audit: {
      files: async () => [],
      verify: async () => ({ valid: true }),
    },
    reliability: {
      enableIngressChecks: () => {
        ingressCalls.value += 1;
      },
      probe: async () => {
        ingressCalls.value += 1;
        throw new Error("PUBLIC_INGRESS_SIMULATED_UNAVAILABLE");
      },
    },
  } as unknown as Parameters<typeof postBindReadiness>[0];
  return { runtime, ingressCalls };
}

describe("startup readiness boundary", () => {
  it("confirms local auth readiness without gating boot on public ingress", async () => {
    const port = await listen(401);
    const { runtime, ingressCalls } = runtimeStub();

    await expect(postBindReadiness(runtime, "127.0.0.1", port)).resolves.toBeUndefined();
    expect(ingressCalls.value).toBe(0);
  });

  it("still fails closed when the local auth boundary is not ready", async () => {
    const port = await listen(502);
    const { runtime } = runtimeStub();

    await expect(postBindReadiness(runtime, "127.0.0.1", port)).rejects.toThrow(
      "AUTH_BOUNDARY_SELF_PROBE_FAILED_502",
    );
  });
});
