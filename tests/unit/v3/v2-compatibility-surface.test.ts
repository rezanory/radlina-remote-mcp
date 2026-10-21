import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { describe, expect, it } from "vitest";

import { startV3ReadOnlyOAuthGateway } from "../../../src/v3/gateway/oauth-readonly.js";
import { testConfig } from "../../helpers/config.js";
import { issueToken } from "../../helpers/oauth.js";

async function openPort(): Promise<number> {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw Error("TCP port was not allocated");
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return address.port;
}

describe("V3 V2 compatibility in its own OAuth process", () => {
  it("exposes local V2 operators while keeping V3 device registry and V2 service state separate", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-v2-compat-"));
    const cfg = testConfig(root);
    const stateDirectory = path.join(root, "v3-only");
    const port = await openPort();
    let gateway: Awaited<ReturnType<typeof startV3ReadOnlyOAuthGateway>> | undefined;
    let client: Client | undefined;
    let writer: Client | undefined;
    try {
      // Starting this runtime must not create or open the original V2 store.
      expect(existsSync(cfg.storage.directory)).toBe(false);
      gateway = await startV3ReadOnlyOAuthGateway({
        baseConfig: cfg,
        stateDirectory,
        publicUrl: `http://127.0.0.1:${port}`,
        port,
        enableV2Compatibility: true,
      });
      expect(existsSync(cfg.storage.directory)).toBe(false);
      expect(existsSync(path.join(stateDirectory, "v2-compatibility", "state"))).toBe(true);
      const token = await issueToken(`http://127.0.0.1:${port}`, gateway.auth, "device:read filesystem:read");
      client = new Client(
        { name: "v3-v2-parity-smoke", version: "1.0.0" },
        { versionNegotiation: { mode: "auto" } },
      );
      await client.connect(new StreamableHTTPClientTransport(new URL(gateway.url), {
        requestInit: { headers: { authorization: `Bearer ${token}` } },
      }));
      const names = (await client.listTools()).tools.map((tool) => tool.name);
      expect(new Set(names).size).toBe(names.length);
      expect(names).toHaveLength(44);
      const declared = await client.callTool({ name: "get_capabilities", arguments: {} });
      const reported = declared.structuredContent as { result: { tools: string[] } };
      expect(new Set(reported.result.tools)).toEqual(new Set(names));
      for (const name of [
        "get_capabilities", "list_devices", "get_device", "v3_admin_status",
        "who_am_i", "ping", "list_directory", "read_file", "write_file",
        "start_search", "search_results", "start_process", "read_process_output",
        "operator_submit", "operator_status", "operator_resume", "list_capabilities",
        "get_effective_config", "simulate_policy", "active_sessions",
      ]) expect(names).toContain(name);
      for (const name of [
        "admin_activate_release", "admin_rollback_release", "admin_enable_trusted_owner",
        "admin_stage_release",
      ]) expect(names).not.toContain(name);
      const capability = await client.callTool({ name: "v3_admin_status", arguments: {} });
      expect(capability.structuredContent).toMatchObject({
        result: {
          deviceCount: 0,
          remoteExecutionEnabled: false,
          productionReady: false,
          v2CompatibilityEnabled: true,
          v2LegacyUpgradeOperationsIsolated: true,
        },
      });
      const devices = await client.callTool({ name: "list_devices", arguments: {} });
      expect(devices.structuredContent).toMatchObject({ result: { devices: [] } });
      const ping = await client.callTool({ name: "ping", arguments: {} });
      expect(ping.isError).not.toBe(true);
      const denied = await client.callTool({
        name: "operator_submit",
        arguments: {
          title: "must fail without admin scope",
          steps: [{ id: "health", capability: "device.health", input: {} }],
          idempotencyKey: "8f9f7591-e6a1-4664-a536-805bd7e72b99",
        },
      });
      expect(denied.isError).toBe(true);
      // A separately approved write scope must actually reach the V3-only filesystem runtime.
      const writeToken = await issueToken(`http://127.0.0.1:${port}`, gateway.auth,
        "device:read filesystem:read filesystem:write");
      writer = new Client({ name: "v3-parity-writer", version: "1.0.0" },
        { versionNegotiation: { mode: "auto" } });
      await writer.connect(new StreamableHTTPClientTransport(new URL(gateway.url), {
        requestInit: { headers: { authorization: `Bearer ${writeToken}` } },
      }));
      const output = path.join(root, "v3-parity-real-file.txt");
      const written = await writer.callTool({ name: "write_file", arguments: {
        path: output, content: "V3 isolated local parity write",
        idempotencyKey: "b19fb34b-999c-43ed-b466-e236369414e5",
      }});
      expect(written.isError).not.toBe(true);
      expect(await readFile(output, "utf8")).toBe("V3 isolated local parity write");
      const readBack = await writer.callTool({ name: "read_file", arguments: { path: output } });
      expect(readBack.isError).not.toBe(true);
      expect(existsSync(cfg.storage.directory)).toBe(false);
    } finally {
      await writer?.close();
      await client?.close();
      await gateway?.shutdown();
      await rm(root, { recursive: true, force: true });
    }
  }, 60_000);
});
