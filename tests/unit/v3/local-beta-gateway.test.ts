import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { describe, expect, it } from "vitest";

import { startLocalV3BetaGateway } from "../../../src/v3/gateway/beta.js";

const token = randomBytes(48).toString("hex");

function resultObject(value: Awaited<ReturnType<Client["callTool"]>>) {
  const entry = value.content.find((item) => item.type === "text");
  if (!entry || entry.type !== "text") throw new Error("missing MCP JSON response");
  return JSON.parse(entry.text) as { result?: Record<string, unknown> };
}

describe("V3 local beta gateway — isolated C01 transport", () => {
  it("fails closed for insecure token, V2 port and reused V2 storage", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-beta-options-"));
    try {
      await expect(
        startLocalV3BetaGateway({
          stateDirectory: root,
          port: 7337,
          bearerToken: token,
        }),
      ).rejects.toThrow(/port/u);
      await expect(
        startLocalV3BetaGateway({
          stateDirectory: root,
          port: 0,
          bearerToken: "short",
        }),
      ).rejects.toThrow(/token/u);
      await expect(
        startLocalV3BetaGateway({
          stateDirectory: path.join(root, ".state"),
          port: 0,
          bearerToken: token,
        }),
      ).rejects.toThrow(/production/u);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("starts an independent loopback gateway, denies unauthenticated reads and operator writes", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-beta-runtime-"));
    let gateway: Awaited<ReturnType<typeof startLocalV3BetaGateway>> | undefined;
    let client: Client | undefined;
    try {
      gateway = await startLocalV3BetaGateway({
        stateDirectory: root,
        port: 0,
        bearerToken: token,
      });
      expect(gateway.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/mcp$/u);
      expect(gateway.port).not.toBe(7337);

      const denied = await fetch(gateway.healthUrl);
      expect(denied.status).toBe(401);
      const wrongToken = await fetch(gateway.healthUrl, {
        headers: { authorization: "Bearer wrong" },
      });
      expect(wrongToken.status).toBe(401);

      const healthResponse = await fetch(gateway.healthUrl, {
        headers: { authorization: `Bearer ${token}` },
      });
      expect(healthResponse.status).toBe(200);
      await expect(healthResponse.json()).resolves.toMatchObject({
        mode: "isolated-readonly-pre-enrollment",
        productionReady: false,
        enrolledDeviceCount: 0,
      });

      client = new Client(
        { name: "radlina-v3-local-beta-test", version: "1.0.0" },
        { versionNegotiation: { mode: "auto" } },
      );
      const transport = new StreamableHTTPClientTransport(new URL(gateway.url), {
        requestInit: {
          headers: { authorization: `Bearer ${token}` },
        },
      });
      await client.connect(transport);
      const names = (await client.listTools()).tools.map((tool) => tool.name);
      expect(names).toContain("list_devices");
      expect(names).toContain("operator_submit");

      const devices = resultObject(await client.callTool({ name: "list_devices", arguments: {} }));
      expect(devices.result?.["devices"]).toEqual([]);
      const metadata = resultObject(
        await client.callTool({
          name: "get_capabilities",
          arguments: {},
        }),
      );
      expect(metadata.result?.["deviceCount"]).toBe(0);
      const admin = resultObject(
        await client.callTool({
          name: "v3_admin_status",
          arguments: {},
        }),
      );
      expect(admin.result).toMatchObject({
        productionReady: false,
        ready: false,
        enrolledDeviceCount: 0,
      });
      const operator = await client.callTool({
        name: "operator_submit",
        arguments: {
          title: "operation must remain denied",
          profile: "radlina",
          steps: [{ id: "health", capability: "device.health", input: {}, maxAttempts: 1 }],
          idempotencyKey: "f9e7a0be-6b97-4a83-a0fd-fca754e7dd6d",
        },
      });
      expect(operator.isError).toBe(true);
    } finally {
      if (client) await client.close();
      if (gateway) await gateway.shutdown();
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);
});
