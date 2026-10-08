import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { createMcpExpressApp } from "@modelcontextprotocol/express";
import { toNodeHandler } from "@modelcontextprotocol/node";
import { createMcpHandler } from "@modelcontextprotocol/server";

import { canonicalJson, sha256 } from "../../src/utils/json.js";
import { parseDeviceDescriptor } from "../../src/v3/device/identity.js";
import { SmartOperatorAdapter } from "../../src/v3/operator/adapter.js";
import {
  buildV3ControlPlaneServer,
  type V3ControlPlanePorts,
  type V3McpExecutionGuard,
} from "../../src/v3/control-plane/mcp.js";
import type { DispatchReceipt } from "../../src/v3/workflow/contracts.js";
import { InMemoryWorkflowTelemetry } from "../../src/v3/workflow/observability.js";
import {
  WorkflowSqliteStore,
  type WorkflowPayloadCodec,
} from "../../src/v3/workflow/persistence.js";
import { WorkflowRecoveryEngine } from "../../src/v3/workflow/recovery.js";
import {
  CanonicalWorkflowRuntime,
  type WorkflowDispatchInput,
} from "../../src/v3/workflow/runtime.js";
import { WorkflowScheduler } from "../../src/v3/workflow/scheduler.js";

class Codec implements WorkflowPayloadCodec {
  async encode(value: string): Promise<string> {
    return Buffer.from(value, "utf8").toString("base64");
  }
  async decode(value: string): Promise<string> {
    return Buffer.from(value, "base64").toString("utf8");
  }
}

class Guard implements V3McpExecutionGuard {
  private readonly cache = new Map<string, unknown>();

  async run<T>(
    input: Parameters<V3McpExecutionGuard["run"]>[0],
    handler: () => Promise<T>,
  ): Promise<T> {
    const key =
      input.idempotencyKey === undefined ? undefined : `${input.tool}:${input.idempotencyKey}`;
    if (key && this.cache.has(key)) return this.cache.get(key) as T;
    const result = await handler();
    if (key) this.cache.set(key, result);
    return result;
  }
}

function resultEnvelope(result: Awaited<ReturnType<Client["callTool"]>>): Record<string, unknown> {
  const item = result.content.find((entry) => entry.type === "text");
  if (!item || item.type !== "text") throw new Error("MCP response text missing");
  const parsed = JSON.parse(item.text) as { result?: unknown };
  if (!parsed.result || typeof parsed.result !== "object") {
    throw new Error("MCP result envelope missing");
  }
  return parsed.result as Record<string, unknown>;
}

const root = await mkdtemp(path.join(os.tmpdir(), "radlina-v3-c01-acceptance-"));
const store = new WorkflowSqliteStore(path.join(root, "workflow.sqlite3"), new Codec());
const scheduler = new WorkflowScheduler(store);
const recovery = new WorkflowRecoveryEngine(
  store,
  { lookup: async () => undefined },
  { isIdempotent: () => true },
);
const workflow = new CanonicalWorkflowRuntime(
  store,
  scheduler,
  recovery,
  new InMemoryWorkflowTelemetry(),
  {
    execute: async (input: WorkflowDispatchInput) => {
      const receipt: DispatchReceipt = {
        workflowExecutionId: input.workflowExecutionId,
        nodeId: input.node.id,
        attempt: input.attempt,
        resolvedDeviceId: "windows-main",
        capability: input.node.capability,
        inputSha256: sha256(canonicalJson(input.node.input)),
        startedAt: new Date().toISOString(),
        terminalState: "completed",
        outputSha256: sha256(canonicalJson({ ok: true })),
        localAuditReceiptHash: "a".repeat(64),
        globalCorrelationId: "corr-c01",
        traceId: "trace-c01",
      };
      return { receipt, output: { ok: true } };
    },
  },
);

const launched: Array<Promise<unknown>> = [];
const operator = new SmartOperatorAdapter(
  workflow,
  {
    launch: (executionId) => {
      launched.push(workflow.runUntilIdle(executionId));
    },
  },
  { isIdempotent: () => true },
  { defaultTarget: { deviceId: "windows-main" } },
);

const devices = [
  parseDeviceDescriptor({
    deviceId: "windows-main",
    hostname: "LAPTOP-13QINEIF",
    platform: "windows",
    architecture: "x64",
    agentVersion: "3.0.0-alpha.1",
    status: "online",
    lastSeen: new Date().toISOString(),
    capabilities: ["device.health"],
    tags: ["primary"],
    trustState: "trusted",
    health: "healthy",
  }),
  parseDeviceDescriptor({
    deviceId: "macbook-main",
    hostname: "MacBook",
    platform: "macos",
    architecture: "arm64",
    agentVersion: "3.0.0-alpha.1",
    status: "online",
    lastSeen: new Date().toISOString(),
    capabilities: ["device.health"],
    tags: ["primary", "apple"],
    trustState: "trusted",
    health: "healthy",
  }),
];

const ports: V3ControlPlanePorts = {
  guard: new Guard(),
  identity: { subject: () => "owner" },
  devices: {
    list: () => [...devices],
    get: (deviceId) => devices.find((device) => device.deviceId === deviceId),
  },
  capabilities: {
    list: () => [
      { id: "device.health", risk: "low" },
      { id: "process.exec", risk: "high" },
    ],
  },
  operator,
  admin: {
    status: async () => ({
      ready: true,
      generation: "v3-multidevice-agent-os",
      acceptedComponents: 24,
    }),
  },
};

const app = createMcpExpressApp({
  host: "127.0.0.1",
  allowedHosts: ["127.0.0.1", "localhost"],
  allowedOrigins: [],
  jsonLimit: "1mb",
});
const handler = createMcpHandler(() => buildV3ControlPlaneServer(ports), {
  legacy: "reject",
});
const nodeHandler = toNodeHandler(handler);
app.all("/mcp", (request, response) => {
  void nodeHandler(request, response, request.body);
});

const server = app.listen(0, "127.0.0.1");
await new Promise<void>((resolve, reject) => {
  server.once("listening", resolve);
  server.once("error", reject);
});

const address = server.address() as AddressInfo;
const client = new Client(
  { name: "radlina-v3-c01-acceptance", version: "1.0.0" },
  { versionNegotiation: { mode: "auto" } },
);

try {
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${address.port}/mcp`)),
  );

  const tools = await client.listTools();
  const names = new Set(tools.tools.map((tool) => tool.name));

  const capabilities = resultEnvelope(
    await client.callTool({ name: "get_capabilities", arguments: {} }),
  );
  const listedDevices = resultEnvelope(
    await client.callTool({ name: "list_devices", arguments: {} }),
  );
  const listedCapabilities = resultEnvelope(
    await client.callTool({ name: "list_capabilities", arguments: {} }),
  );

  const key = "24b45b07-f9e2-412e-90fa-c76a0db6f66c";
  const args = {
    title: "C01 operational acceptance",
    profile: "radlina",
    idempotencyKey: key,
    steps: [
      {
        id: "health",
        capability: "device.health",
        input: {},
        maxAttempts: 1,
      },
    ],
  };
  const submitted = resultEnvelope(
    await client.callTool({ name: "operator_submit", arguments: args }),
  );
  const replayed = resultEnvelope(
    await client.callTool({ name: "operator_submit", arguments: args }),
  );

  const jobId = String(submitted["jobId"]);
  await Promise.all(launched);
  const status = resultEnvelope(
    await client.callTool({ name: "operator_status", arguments: { jobId } }),
  );
  const admin = resultEnvelope(await client.callTool({ name: "v3_admin_status", arguments: {} }));

  const requiredTools = [
    "who_am_i",
    "get_capabilities",
    "list_devices",
    "get_device",
    "list_capabilities",
    "operator_submit",
    "operator_status",
    "operator_resume",
    "operator_cancel",
    "v3_admin_status",
  ];

  const acceptance =
    client.getNegotiatedProtocolVersion() === "2026-07-28" &&
    requiredTools.every((name) => names.has(name)) &&
    capabilities["generation"] === "v3-multidevice-agent-os" &&
    capabilities["deviceCount"] === 2 &&
    JSON.stringify(listedDevices).includes("windows-main") &&
    JSON.stringify(listedDevices).includes("macbook-main") &&
    JSON.stringify(listedCapabilities).includes("device.health") &&
    replayed["jobId"] === submitted["jobId"] &&
    status["status"] === "completed" &&
    admin["ready"] === true;

  process.stdout.write(
    JSON.stringify({
      input: {
        transport: "streamable-http",
        toolCount: tools.tools.length,
        operatorIdempotencyKey: key,
      },
      runtime: {
        client: "MCP Client",
        controlPlane: "buildV3ControlPlaneServer",
        operator: "SmartOperatorAdapter",
        workflowAuthority: "CanonicalWorkflowRuntime",
      },
      execution: {
        protocol: client.getNegotiatedProtocolVersion(),
        deviceCount: capabilities["deviceCount"],
        operatorJobId: jobId,
        replayJobId: replayed["jobId"],
        finalStatus: status["status"],
      },
      output: {
        requiredToolsPresent: requiredTools.every((name) => names.has(name)),
        adminReady: admin["ready"],
      },
      acceptance: acceptance ? "PASS" : "FAIL",
    }),
  );
  if (!acceptance) process.exitCode = 1;
} finally {
  await client.close();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  store.close();
  await rm(root, { recursive: true, force: true });
}
