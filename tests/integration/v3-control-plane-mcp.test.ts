import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { createMcpExpressApp } from "@modelcontextprotocol/express";
import { toNodeHandler } from "@modelcontextprotocol/node";
import { createMcpHandler } from "@modelcontextprotocol/server";
import { afterEach, describe, expect, it } from "vitest";

import { AppError } from "../../src/errors.js";
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

const cleanup: string[] = [];

class Codec implements WorkflowPayloadCodec {
  async encode(value: string): Promise<string> {
    return Buffer.from(value, "utf8").toString("base64");
  }
  async decode(value: string): Promise<string> {
    return Buffer.from(value, "base64").toString("utf8");
  }
}

class InMemoryGuard implements V3McpExecutionGuard {
  private readonly cache = new Map<string, unknown>();

  constructor(private readonly denyAdmin = false) {}

  async run<T>(
    input: Parameters<V3McpExecutionGuard["run"]>[0],
    handler: () => Promise<T>,
  ): Promise<T> {
    if (this.denyAdmin && input.scope === "admin") {
      throw new AppError("POLICY_DENIED", "admin scope denied");
    }
    const cacheKey =
      input.idempotencyKey === undefined ? undefined : `${input.tool}:${input.idempotencyKey}`;
    if (cacheKey && this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey) as T;
    }
    const result = await handler();
    if (cacheKey) this.cache.set(cacheKey, result);
    return result;
  }
}

function envelope(result: Awaited<ReturnType<Client["callTool"]>>): Record<string, unknown> {
  const item = result.content.find((entry) => entry.type === "text");
  if (!item || item.type !== "text") throw new Error("MCP response text missing");
  const parsed = JSON.parse(item.text) as { result?: unknown };
  if (!parsed.result || typeof parsed.result !== "object") {
    throw new Error("MCP result envelope missing");
  }
  return parsed.result as Record<string, unknown>;
}

async function ports(
  root: string,
  denyAdmin = false,
): Promise<{
  ports: V3ControlPlanePorts;
  close: () => void;
}> {
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
      lastSeen: "2026-10-08T09:00:00+03:00",
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
      lastSeen: "2026-10-08T09:00:00+03:00",
      capabilities: ["device.health"],
      tags: ["primary", "apple"],
      trustState: "trusted",
      health: "healthy",
    }),
  ];

  return {
    ports: {
      guard: new InMemoryGuard(denyAdmin),
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
    },
    close: () => store.close(),
  };
}

async function startControlPlane(controlPorts: V3ControlPlanePorts) {
  const app = createMcpExpressApp({
    host: "127.0.0.1",
    allowedHosts: ["127.0.0.1", "localhost"],
    allowedOrigins: [],
    jsonLimit: "1mb",
  });
  const handler = createMcpHandler(() => buildV3ControlPlaneServer(controlPorts), {
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
    { name: "radlina-v3-c01-test", version: "1.0.0" },
    { versionNegotiation: { mode: "auto" } },
  );
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${address.port}/mcp`)),
  );
  return { server, client };
}

afterEach(async () => {
  for (const directory of cleanup.splice(0)) {
    await rm(directory, { recursive: true, force: true });
  }
});

describe("V3 C01 MCP control plane", () => {
  it("serves devices, capabilities, V2-compatible operator calls, and admin status over real MCP HTTP", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "radlina-v3-c01-"));
    cleanup.push(root);
    const runtime = await ports(root);
    const { server, client } = await startControlPlane(runtime.ports);

    try {
      expect(client.getNegotiatedProtocolVersion()).toBe("2026-07-28");
      const tools = await client.listTools();
      expect(new Set(tools.tools.map((tool) => tool.name))).toEqual(
        expect.objectContaining(
          new Set([
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
          ]),
        ),
      );

      const capabilities = envelope(
        await client.callTool({ name: "get_capabilities", arguments: {} }),
      );
      expect(capabilities).toMatchObject({
        generation: "v3-multidevice-agent-os",
        deviceCount: 2,
        capabilityCount: 2,
      });

      const devices = envelope(await client.callTool({ name: "list_devices", arguments: {} }));
      expect(JSON.stringify(devices)).toContain("windows-main");
      expect(JSON.stringify(devices)).toContain("macbook-main");

      const device = envelope(
        await client.callTool({
          name: "get_device",
          arguments: { deviceId: "macbook-main" },
        }),
      );
      expect(device).toMatchObject({ deviceId: "macbook-main", platform: "macos" });

      const key = "6fb70dc7-dc6f-4eeb-b284-6994ea514c90";
      const submitted = envelope(
        await client.callTool({
          name: "operator_submit",
          arguments: {
            title: "C01 compatibility acceptance",
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
          },
        }),
      );
      const replay = envelope(
        await client.callTool({
          name: "operator_submit",
          arguments: {
            title: "C01 compatibility acceptance",
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
          },
        }),
      );
      expect(replay["jobId"]).toBe(submitted["jobId"]);

      const jobId = String(submitted["jobId"]);
      let status: Record<string, unknown> | undefined;
      for (let attempt = 0; attempt < 50; attempt += 1) {
        status = envelope(await client.callTool({ name: "operator_status", arguments: { jobId } }));
        if (status["status"] === "completed") break;
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      expect(status?.["status"]).toBe("completed");

      const admin = envelope(await client.callTool({ name: "v3_admin_status", arguments: {} }));
      expect(admin).toMatchObject({ ready: true, acceptedComponents: 24 });

      const completedCancel = envelope(
        await client.callTool({
          name: "operator_cancel",
          arguments: {
            jobId,
            idempotencyKey: "8d10c6c7-c77c-4a3e-a7b1-427f42c4ed45",
          },
        }),
      );
      expect(completedCancel).toMatchObject({ requested: false, status: "completed" });
    } finally {
      await client.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      runtime.close();
    }
  });

  it("fails closed before operator execution when the control guard denies admin scope", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "radlina-v3-c01-deny-"));
    cleanup.push(root);
    const runtime = await ports(root, true);
    const { server, client } = await startControlPlane(runtime.ports);
    try {
      const result = await client.callTool({
        name: "operator_submit",
        arguments: {
          title: "denied",
          profile: "radlina",
          idempotencyKey: "46e4ea47-123d-48d2-9abd-e595f3e4b0bb",
          steps: [
            {
              id: "health",
              capability: "device.health",
              input: {},
              maxAttempts: 1,
            },
          ],
        },
      });
      expect(result.isError).toBe(true);
      expect(JSON.stringify(result.content)).toContain("POLICY_DENIED");
    } finally {
      await client.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      runtime.close();
    }
  });
});
