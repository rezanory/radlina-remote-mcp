import { createHash, randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:net";
import os, { tmpdir } from "node:os";
import path from "node:path";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { describe, expect, it } from "vitest";

import { SqliteDeviceRegistry } from "../../../src/v3/device/registry.js";
import { startV3ReadOnlyOAuthGateway } from "../../../src/v3/gateway/oauth-readonly.js";
import { testConfig } from "../../helpers/config.js";

async function freePort(): Promise<number> {
  const listener = createServer();
  listener.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    listener.once("listening", resolve);
    listener.once("error", reject);
  });
  const address = listener.address();
  if (!address || typeof address === "string") throw Error("expected TCP port");
  await new Promise<void>((resolve) => listener.close(() => resolve()));
  return address.port;
}

describe("V3 OAuth-native MCP Windows file write acceptance", () => {
  it("requires approved filesystem:write scope and creates a real local Windows file", async () => {
    if (process.platform !== "win32") return;
    const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-mcp-files-"));
    const desktop = path.join(root, "owner-desktop");
    const stateDirectory = path.join(root, "v3-isolated");
    await mkdir(desktop);
    const cfg = testConfig(root);
    const registry = new SqliteDeviceRegistry(path.join(stateDirectory, "v3-devices.sqlite3"));
    registry.register({
      deviceId: "windows-main",
      hostname: os.hostname(),
      platform: "windows",
      architecture: "x64",
      agentVersion: "3.0.0-alpha.1",
      status: "degraded",
      lastSeen: new Date().toISOString(),
      capabilities: ["device.health"],
      tags: [],
      trustState: "pending",
      health: "unknown",
    });
    const candidate = registry.require("windows-main");
    // Test-fixture only: production P03 trust comes from an actual dual-signature admission.
    registry.db
      .prepare("UPDATE v3_devices SET descriptor_json=? WHERE device_id=?")
      .run(JSON.stringify({ ...candidate, trustState: "trusted" }), "windows-main");
    registry.close();

    const port = await freePort();
    const origin = "http://127.0.0.1:" + port;
    let gateway: Awaited<ReturnType<typeof startV3ReadOnlyOAuthGateway>> | undefined;
    const clients: Client[] = [];

    async function authorizedClient(scope: string): Promise<Client> {
      if (!gateway) throw Error("gateway not started");
      const reg = await fetch(origin + "/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          redirect_uris: ["http://127.0.0.1/callback"],
          client_name: "v3-file-scope-test",
        }),
      });
      expect(reg.status).toBe(201);
      const { client_id } = (await reg.json()) as { client_id: string };
      const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
      const params = new URLSearchParams({
        response_type: "code",
        client_id,
        redirect_uri: "http://127.0.0.1/callback",
        code_challenge: createHash("sha256").update(verifier).digest("base64url"),
        code_challenge_method: "S256",
        resource: gateway.auth.resourceUrl.href,
        scope,
        state: "scope-check",
      });
      const auth = await fetch(origin + "/authorize?" + params.toString());
      expect(auth.status).toBe(200);
      const body = await auth.text();
      const requestId = /Request ID: <code>([0-9a-f-]+)<\/code>/u.exec(body)?.[1];
      expect(requestId).toBeTruthy();
      expect(gateway.auth.approve(requestId!, "owner-approved-v3")).toBe(true);
      const grant = await fetch(origin + "/authorize?request_id=" + requestId, {
        redirect: "manual",
      });
      expect(grant.status).toBe(302);
      const callback = new URL(grant.headers.get("location")!);
      const tokenResponse = await fetch(origin + "/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id,
          redirect_uri: "http://127.0.0.1/callback",
          code_verifier: verifier,
          resource: gateway.auth.resourceUrl.href,
          code: callback.searchParams.get("code")!,
        }),
      });
      expect(tokenResponse.status).toBe(200);
      const token = (await tokenResponse.json()) as { access_token: string; scope: string };
      expect(token.scope).toBe(scope);
      const cli = new Client(
        { name: "v3-native-files-test", version: "1.0.0" },
        {
          versionNegotiation: { mode: "auto" },
        },
      );
      await cli.connect(
        new StreamableHTTPClientTransport(new URL(gateway.url), {
          requestInit: { headers: { authorization: "Bearer " + token.access_token } },
        }),
      );
      clients.push(cli);
      return cli;
    }

    try {
      gateway = await startV3ReadOnlyOAuthGateway({
        baseConfig: cfg,
        stateDirectory,
        publicUrl: origin,
        port,
        windowsFileRoot: desktop,
      });
      const metadata = await fetch(origin + "/.well-known/oauth-authorization-server");
      expect(metadata.status).toBe(200);
      expect(
        ((await metadata.json()) as { scopes_supported: string[] }).scopes_supported,
      ).toContain("filesystem:write");
      const lowScope = await authorizedClient("device:read");
      const names = (await lowScope.listTools()).tools.map((t) => t.name);
      expect(names).toContain("v3_windows_write_text_file");
      expect(names).toContain("v3_windows_read_text_file");
      const write = {
        targetDeviceId: "windows-main",
        relativePath: "v3-مستقیم.txt",
        content: "عسلی",
        overwrite: false,
        idempotencyKey: randomUUID(),
      };
      const denied = await lowScope
        .callTool({
          name: "v3_windows_write_text_file",
          arguments: write,
        })
        .catch(() => ({ isError: true }));
      expect(denied.isError).toBe(true);
      const owner = await authorizedClient("device:read filesystem:read filesystem:write");
      const created = await owner.callTool({
        name: "v3_windows_write_text_file",
        arguments: write,
      });
      expect(created.isError).not.toBe(true);
      expect(created.structuredContent).toMatchObject({
        result: { targetDeviceId: "windows-main", readbackVerified: true, bytes: 8 },
      });
      expect(await readFile(path.join(desktop, "v3-مستقیم.txt"), "utf8")).toBe("عسلی");
      const copy = await owner.callTool({
        name: "v3_windows_write_text_file",
        arguments: write,
      });
      expect(copy.structuredContent).toEqual(created.structuredContent);
      const readback = await owner.callTool({
        name: "v3_windows_read_text_file",
        arguments: { targetDeviceId: "windows-main", relativePath: "v3-مستقیم.txt" },
      });
      expect(readback.structuredContent).toMatchObject({ result: { content: "عسلی", bytes: 8 } });
      const invalid = await owner
        .callTool({
          name: "v3_windows_write_text_file",
          arguments: { ...write, relativePath: "..\\escape.txt", idempotencyKey: randomUUID() },
        })
        .catch(() => ({ isError: true }));
      expect(invalid.isError).toBe(true);
      const admin = await owner.callTool({ name: "v3_admin_status", arguments: {} });
      expect(admin.structuredContent).toMatchObject({
        result: {
          productionReady: false,
          remoteExecutionEnabled: false,
          localWindowsFileOperationsEnabled: true,
        },
      });
    } finally {
      for (const client of clients) await client.close();
      await gateway?.shutdown();
      await rm(root, { recursive: true, force: true });
    }
  }, 45000);
});
