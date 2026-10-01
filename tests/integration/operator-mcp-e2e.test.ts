import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { stringify as stringifyYaml } from "yaml";
import { afterEach, describe, expect, it } from "vitest";

import { createHttpApp } from "../../src/http.js";
import { closeRuntime, createRuntime } from "../../src/runtime.js";
import { testConfig } from "../helpers/config.js";
import { issueToken } from "../helpers/oauth.js";

const cleanup: string[] = [];

afterEach(async () => {
  for (const directory of cleanup.splice(0)) {
    await rm(directory, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  }
});

function envelope(result: Awaited<ReturnType<Client["callTool"]>>): Record<string, unknown> {
  const item = result.content.find((entry) => entry.type === "text");
  if (!item || item.type !== "text") throw new Error("MCP response text missing");
  const parsed = JSON.parse(item.text) as { result?: unknown };
  if (!parsed.result || typeof parsed.result !== "object")
    throw new Error("MCP result envelope missing");
  return parsed.result as Record<string, unknown>;
}

function operatorPollDelay(attempt: number): number {
  // Keep E2E polling inside the real 60 req/min token-bucket budget even when jobs are slow.
  return Math.min(1_000, 50 * 2 ** Math.min(attempt, 5));
}

async function waitForOperator(client: Client, jobId: string): Promise<Record<string, unknown>> {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const response = await client.callTool({
      name: "operator_status",
      arguments: { jobId },
    });
    expect(response.isError).not.toBe(true);
    const result = envelope(response);
    if (!["queued", "running"].includes(String(result["status"]))) return result;
    await new Promise((resolve) => setTimeout(resolve, operatorPollDelay(attempt)));
  }
  throw new Error("operator MCP job did not reach a terminal state");
}

describe("V2 Smart Operator live MCP E2E", () => {
  it("runs classic file probes and durable operator jobs over Streamable HTTP", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "radlina-v2-live-e2e-"));
    cleanup.push(root);

    const config = testConfig(root);
    config.profiles["test"]!.commands = [
      { executable: process.execPath, argumentPatterns: [".*"] },
    ];
    config.policy.maxProcessRuntimeMs = 20_000;
    const configFile = path.join(root, "config.yaml");
    await writeFile(configFile, stringifyYaml(config), "utf8");

    const runtime = await createRuntime(configFile, { reconcileSessions: true });
    const server = createHttpApp(runtime).listen(0, "127.0.0.1");
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });

    const client = new Client(
      { name: "radlina-v2-live-e2e", version: "1.0.0" },
      { versionNegotiation: { mode: "auto" } },
    );

    try {
      const address = server.address() as AddressInfo;
      const base = `http://127.0.0.1:${address.port}`;
      const accessToken = await issueToken(
        base,
        runtime.auth,
        "device:read filesystem:read filesystem:write process:read process:execute admin offline_access",
      );
      await client.connect(
        new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
          authProvider: { token: async () => accessToken },
        }),
      );

      expect(client.getNegotiatedProtocolVersion()).toBe("2026-07-28");

      const version = envelope(await client.callTool({ name: "version", arguments: {} }));
      expect(version["server"]).toBe("2.0.0-alpha.1");
      expect(version["generation"]).toBe("v2-smart-operator");

      const components = envelope(
        await client.callTool({ name: "list_components", arguments: {} }),
      );
      expect(JSON.stringify(components)).toContain("radlina.filesystem");
      expect(JSON.stringify(components)).toContain("radlina.process");

      const capabilities = envelope(
        await client.callTool({ name: "list_capabilities", arguments: {} }),
      );
      expect(JSON.stringify(capabilities)).toContain("filesystem.info");
      expect(JSON.stringify(capabilities)).toContain("process.exec");

      const probe = path.join(root, "v2-e2e-probe.txt");
      const write = await client.callTool({
        name: "write_file",
        arguments: {
          path: probe,
          content: "v2-e2e-probe",
          overwrite: false,
          profile: "test",
          idempotencyKey: "f7c73caa-1a7e-4eeb-af40-46a8e10e60dc",
        },
      });
      expect(write.isError).not.toBe(true);

      const read = await client.callTool({
        name: "read_file",
        arguments: { path: probe, profile: "test", offset: 0, length: 4096 },
      });
      expect(read.isError).not.toBe(true);
      expect(JSON.stringify(envelope(read))).toContain("v2-e2e-probe");

      const submitted = envelope(
        await client.callTool({
          name: "operator_submit",
          arguments: {
            title: "V2 isolated live acceptance",
            profile: "test",
            idempotencyKey: "62a95f28-762c-4ad8-9b51-dd74da435c2f",
            steps: [
              {
                id: "verify-file",
                capability: "filesystem.info",
                input: { path: probe, expectedType: "file" },
                maxAttempts: 2,
              },
              {
                id: "verify-node",
                capability: "process.exec",
                input: {
                  executable: process.execPath,
                  args: ["--version"],
                  cwd: root,
                  successExitCodes: [0],
                },
                maxAttempts: 1,
              },
            ],
          },
        }),
      );
      const jobId = String(submitted["jobId"]);
      expect(jobId).toMatch(/^[0-9a-f-]{36}$/u);

      const completed = await waitForOperator(client, jobId);
      expect(completed["status"]).toBe("completed");
      expect(JSON.stringify(completed)).toContain('"verified":true');

      const recent = envelope(
        await client.callTool({ name: "operator_recent", arguments: { limit: 10 } }),
      );
      expect(JSON.stringify(recent)).toContain(jobId);

      const resumeCompleted = await client.callTool({
        name: "operator_resume",
        arguments: {
          jobId,
          idempotencyKey: "d0ad0b21-d1c5-49ce-b280-d6df1d676e11",
        },
      });
      expect(resumeCompleted.isError).toBe(true);
      expect(JSON.stringify(resumeCompleted.content)).toContain("CONFLICT");

      const slow = envelope(
        await client.callTool({
          name: "operator_submit",
          arguments: {
            title: "V2 cancellation acceptance",
            profile: "test",
            idempotencyKey: "31f9df7a-f29f-484d-80a6-960f91f481aa",
            steps: [
              {
                id: "slow-process",
                capability: "process.exec",
                input: {
                  executable: process.execPath,
                  args: ["-e", "setTimeout(() => {}, 15000)"],
                  cwd: root,
                  timeoutMs: 15000,
                  successExitCodes: [0],
                },
                maxAttempts: 1,
              },
            ],
          },
        }),
      );
      const slowJobId = String(slow["jobId"]);

      for (let attempt = 0; attempt < 30; attempt += 1) {
        const snapshot = envelope(
          await client.callTool({ name: "operator_status", arguments: { jobId: slowJobId } }),
        );
        if (snapshot["status"] === "running") break;
        await new Promise((resolve) => setTimeout(resolve, operatorPollDelay(attempt)));
      }

      const cancelled = await client.callTool({
        name: "operator_cancel",
        arguments: {
          jobId: slowJobId,
          idempotencyKey: "1a2d999c-eb6b-465b-b9af-b51d4918d29f",
        },
      });
      expect(cancelled.isError).not.toBe(true);
      expect((await waitForOperator(client, slowJobId))["status"]).toBe("cancelled");

      const failed = envelope(
        await client.callTool({
          name: "operator_submit",
          arguments: {
            title: "V2 resume route acceptance",
            profile: "test",
            idempotencyKey: "8882e34e-a868-407d-824b-6f239ec46ab0",
            steps: [
              {
                id: "intentional-failure",
                capability: "filesystem.info",
                input: { path: probe, expectedType: "directory" },
                maxAttempts: 1,
              },
            ],
          },
        }),
      );
      const failedJobId = String(failed["jobId"]);
      expect((await waitForOperator(client, failedJobId))["status"]).toBe("failed");

      const resumeExhausted = await client.callTool({
        name: "operator_resume",
        arguments: {
          jobId: failedJobId,
          idempotencyKey: "84af4fbb-e2a6-458d-a6dd-b7821589338b",
        },
      });
      expect(resumeExhausted.isError).toBe(true);
      expect(JSON.stringify(resumeExhausted.content)).toContain("exhausted");
    } finally {
      await client.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await closeRuntime(runtime);
    }
  }, 90_000);
});
