import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { stringify as stringifyYaml } from "yaml";
import { afterEach, describe, expect, it } from "vitest";

import { createHttpApp } from "../../src/http.js";
import { closeRuntime, createRuntime } from "../../src/runtime.js";
import { testConfig } from "../helpers/config.js";
import { issueToken } from "../helpers/oauth.js";

const cleanup: string[] = [];
const execFile = promisify(execFileCallback);
const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const inspectorLauncher = path.join(
  projectRoot,
  "node_modules",
  "@modelcontextprotocol",
  "inspector",
  "clients",
  "launcher",
  "build",
  "index.js",
);

afterEach(async () => {
  for (const directory of cleanup.splice(0)) await rm(directory, { recursive: true, force: true });
});

describe("Streamable HTTP MCP", () => {
  it("negotiates the current protocol, lists all tools, runs reads, and denies missing mutation scope", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "radlina-mcp-"));
    cleanup.push(root);
    const configFile = path.join(root, "config.yaml");
    await writeFile(configFile, stringifyYaml(testConfig(root)), "utf8");
    const runtime = await createRuntime(configFile);
    const server = createHttpApp(runtime).listen(0, "127.0.0.1");
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });
    const client = new Client(
      { name: "radlina-integration-test", version: "1.0.0" },
      { versionNegotiation: { mode: "auto" } },
    );
    let reconnectClient: Client | undefined;
    try {
      const address = server.address() as AddressInfo;
      const base = `http://127.0.0.1:${address.port}`;
      const accessToken = await issueToken(base, runtime.auth);
      const inspectorConfig = path.join(root, "inspector.json");
      await writeFile(
        inspectorConfig,
        JSON.stringify({
          mcpServers: {
            radlina: {
              type: "http",
              url: `${base}/mcp`,
              protocolEra: "modern",
              headers: { Authorization: `Bearer ${accessToken}` },
            },
          },
        }),
        "utf8",
      );
      const inspector = await execFile(
        process.execPath,
        [
          inspectorLauncher,
          "--cli",
          "--config",
          inspectorConfig,
          "--server",
          "radlina",
          "--method",
          "tools/list",
          "--strict",
          "--format",
          "json",
        ],
        {
          cwd: projectRoot,
          timeout: 20_000,
          maxBuffer: 2 * 1024 * 1024,
          windowsHide: true,
          env: { ...process.env, MCP_CLIENT_CONFIG_PATH: path.join(root, "inspector-client.json") },
        },
      );
      expect(inspector.stdout).toContain('"tools"');
      const transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
        authProvider: { token: async () => accessToken },
      });
      await client.connect(transport);
      expect(client.getNegotiatedProtocolVersion()).toBe("2026-07-28");
      const tools = await client.listTools();
      expect(tools.tools).toHaveLength(50);
      const toolNames = new Set(tools.tools.map((tool) => tool.name));
      for (const required of [
        "list_components",
        "list_capabilities",
        "operator_submit",
        "operator_status",
        "operator_recent",
        "operator_resume",
        "operator_cancel",
        "admin_stage_release",
        "admin_verify_release",
        "admin_upgrade_preflight",
        "admin_activate_release",
        "admin_upgrade_status",
        "admin_rollback_release",
        "admin_verify_post_restart",
        "admin_enable_trusted_owner",
      ])
        expect(toolNames.has(required)).toBe(true);
      expect(tools.tools.every((tool) => tool.annotations?.openWorldHint === false)).toBe(true);
      const ping = await client.callTool({ name: "ping", arguments: {} });
      expect(ping.isError).not.toBe(true);
      const capabilities = await client.callTool({ name: "get_capabilities", arguments: {} });
      const capabilityContent = capabilities.content.find((item) => item.type === "text");
      if (!capabilityContent || capabilityContent.type !== "text")
        throw new Error("capability response text missing");
      const capabilityEnvelope = JSON.parse(capabilityContent.text) as {
        result: Record<string, unknown>;
      };
      for (const flag of [
        "persistentOwnerTrust",
        "offlineAccess",
        "refreshRotation",
        "refreshReplayGrace",
        "authHealth",
        "oauthTelemetry",
        "sessionRebindSupport",
      ]) {
        expect(capabilityEnvelope.result[flag]).toBe(true);
      }
      const adminDenied = await client.callTool({
        name: "admin_upgrade_status",
        arguments: {},
      });
      expect(adminDenied.isError).toBe(true);
      expect(adminDenied.content).toEqual(
        expect.arrayContaining([
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
          expect.objectContaining({ text: expect.stringContaining("POLICY_DENIED") }),
        ]),
      );
      const denied = await client.callTool({
        name: "write_file",
        arguments: {
          path: "denied.txt",
          content: "no",
          idempotencyKey: "e180874a-36ce-48c6-a4dc-fffb690a3ffd",
        },
      });
      expect(denied.isError).toBe(true);
      expect(denied.content).toEqual(
        expect.arrayContaining([
          // Vitest asymmetric matchers intentionally erase their generic value type.
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
          expect.objectContaining({ text: expect.stringContaining("POLICY_DENIED") }),
        ]),
      );

      await client.close();
      reconnectClient = new Client(
        { name: "radlina-reconnect-test", version: "1.0.0" },
        { versionNegotiation: { mode: "auto" } },
      );
      await reconnectClient.connect(
        new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
          authProvider: { token: async () => accessToken },
        }),
      );
      expect((await reconnectClient.callTool({ name: "ping", arguments: {} })).isError).not.toBe(
        true,
      );
    } finally {
      await reconnectClient?.close();
      await client.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await closeRuntime(runtime);
    }
  }, 60_000);
});
