import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";

import { startLocalV3BetaGateway } from "../../src/v3/gateway/beta.js";

type Envelope = { result?: Record<string, unknown> };

function unwrap(value: Awaited<ReturnType<Client["callTool"]>>): Record<string, unknown> {
  const item = value.content.find((entry) => entry.type === "text");
  if (!item || item.type !== "text") throw new Error("MCP response lacks text");
  const envelope = JSON.parse(item.text) as Envelope;
  if (!envelope.result) throw new Error("MCP response lacks result");
  return envelope.result;
}

const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-beta-acceptance-"));
const token = randomBytes(48).toString("hex");
let gateway: Awaited<ReturnType<typeof startLocalV3BetaGateway>> | undefined;
let client: Client | undefined;

try {
  let v2Unchanged: boolean | null = null;
  if (process.platform === "win32") {
    const before = await fetch("http://127.0.0.1:7337/mcp", {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(5_000),
    });
    v2Unchanged = before.status === 401;
  }

  gateway = await startLocalV3BetaGateway({
    stateDirectory: root,
    port: 0,
    bearerToken: token,
  });
  const unauthorized = await fetch(gateway.healthUrl);
  const authorized = await fetch(gateway.healthUrl, {
    headers: { authorization: `Bearer ${token}` },
  });
  const runtimeHealth = (await authorized.json()) as {
    productionReady?: boolean;
    enrolledDeviceCount?: number;
    mode?: string;
  };

  client = new Client(
    { name: "radlina-v3-beta-real-acceptance", version: "1.0.0" },
    { versionNegotiation: { mode: "auto" } },
  );
  await client.connect(
    new StreamableHTTPClientTransport(new URL(gateway.url), {
      requestInit: { headers: { authorization: `Bearer ${token}` } },
    }),
  );
  const availableTools = (await client.listTools()).tools.map((tool) => tool.name);
  const devices = unwrap(await client.callTool({ name: "list_devices", arguments: {} }));
  const capabilities = unwrap(
    await client.callTool({
      name: "get_capabilities",
      arguments: {},
    }),
  );
  const admin = unwrap(await client.callTool({ name: "v3_admin_status", arguments: {} }));
  const refused = await client.callTool({
    name: "operator_submit",
    arguments: {
      title: "must be refused",
      profile: "radlina",
      steps: [{ id: "health", capability: "device.health", input: {}, maxAttempts: 1 }],
      idempotencyKey: "43be3e9b-e5f6-4a6e-930b-ce62b08d1ccb",
    },
  });

  if (process.platform === "win32") {
    const after = await fetch("http://127.0.0.1:7337/mcp", {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(5_000),
    });
    v2Unchanged = v2Unchanged && after.status === 401;
  }

  const checks = {
    localhostOnly: gateway.url.startsWith("http://127.0.0.1:"),
    noV2PortCollision: gateway.port !== 7337,
    unauthorizedRejected: unauthorized.status === 401,
    localTokenAccepted: authorized.status === 200,
    mcpConnected: availableTools.includes("list_devices"),
    registryIsRealAndEmpty:
      JSON.stringify(devices["devices"]) === "[]" && capabilities["deviceCount"] === 0,
    productionNotClaimed:
      admin["ready"] === false &&
      admin["productionReady"] === false &&
      runtimeHealth.productionReady === false,
    operatorBlocked: refused.isError === true,
    v2AuthorizationUnaffected: v2Unchanged,
  };
  const pass = Object.entries(checks).every(
    ([key, value]) => (key === "v2AuthorizationUnaffected" && value === null) || value === true,
  );

  process.stdout.write(
    JSON.stringify({
      input: { mode: "isolated V3 beta MCP", deviceId: "no-enrollment-yet" },
      runtime: {
        platform: process.platform,
        transport: "streamable-http",
        gatewayBind: "127.0.0.1",
        state: "temporary independent SQLite registry",
        server: "accepted C01 V3 control-plane",
      },
      execution: checks,
      output: {
        v3McpProtocol: client.getNegotiatedProtocolVersion(),
        enrolledDevices: runtimeHealth.enrolledDeviceCount,
        advertisedTools: availableTools.length,
      },
      acceptance: pass ? "LOCAL_V3_BETA_PASS" : "FAIL",
      productionAcceptance: "NOT_GRANTED_MACBOOK_AND_OAUTH_PENDING",
    }) + "\n",
  );
  if (!pass) process.exitCode = 1;
} finally {
  if (client) await client.close();
  if (gateway) await gateway.shutdown();
  await rm(root, { recursive: true, force: true });
}
