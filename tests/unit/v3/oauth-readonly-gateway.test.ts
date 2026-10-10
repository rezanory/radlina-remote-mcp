import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { describe, expect, it } from "vitest";

import { startV3ReadOnlyOAuthGateway } from "../../../src/v3/gateway/oauth-readonly.js";
import { testConfig } from "../../helpers/config.js";

async function availablePort(): Promise<number> {
  const listener = createServer();
  listener.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    listener.once("listening", resolve);
    listener.once("error", reject);
  });
  const address = listener.address();
  if (!address || typeof address === "string") throw new Error("expected TCP port");
  await new Promise<void>((resolve) => listener.close(() => resolve()));
  return address.port;
}

describe("V3 independent read-only OAuth gateway", () => {
  it("rejects V2 state overlap, V2 origin, insecure remote origin and reused port", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-oauth-negative-"));
    const cfg = testConfig(root);
    const opts = {
      baseConfig: cfg,
      stateDirectory: path.join(root, "v3-state"),
      publicUrl: "http://127.0.0.1:7344",
      port: 7344,
    };
    try {
      await expect(
        startV3ReadOnlyOAuthGateway({
          ...opts,
          stateDirectory: cfg.storage.directory,
        }),
      ).rejects.toThrow(/overlap/u);
      await expect(
        startV3ReadOnlyOAuthGateway({
          ...opts,
          publicUrl: cfg.server.publicUrl,
        }),
      ).rejects.toThrow(/different OAuth issuer/u);
      await expect(
        startV3ReadOnlyOAuthGateway({
          ...opts,
          publicUrl: "http://external.example.test",
        }),
      ).rejects.toThrow(/HTTPS/u);
      await expect(
        startV3ReadOnlyOAuthGateway({
          ...opts,
          port: 7337,
        }),
      ).rejects.toThrow(/independent/u);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("authenticates a separate client, exposes only four reads, and blocks privilege escalation", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-oauth-active-"));
    const cfg = testConfig(root);
    const port = await availablePort();
    const origin = "http://127.0.0.1:" + port;
    let gateway: Awaited<ReturnType<typeof startV3ReadOnlyOAuthGateway>> | undefined;
    let client: Client | undefined;
    try {
      gateway = await startV3ReadOnlyOAuthGateway({
        baseConfig: cfg,
        stateDirectory: path.join(root, "v3-state"),
        publicUrl: origin,
        port,
      });
      const anonymous = await fetch(gateway.url, { method: "POST" });
      expect(anonymous.status).toBe(401);
      const authHealth = await fetch(origin + "/auth-health");
      expect(authHealth.status).toBe(200);
      expect(await authHealth.json()).toMatchObject({
        status: "healthy",
        mode: "internal",
        signingReady: true,
        tokenEndpointReady: true,
      });
      const unauthorizedScope = await fetch(origin + "/authorize?scope=admin");
      expect(unauthorizedScope.status).toBe(400);
      expect(await unauthorizedScope.json()).toMatchObject({ error: "invalid_scope" });

      const registration = await fetch(origin + "/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          redirect_uris: ["http://127.0.0.1/callback"],
          client_name: "v3-readonly-test",
        }),
      });
      expect(registration.status).toBe(201);
      const { client_id } = (await registration.json()) as { client_id: string };
      const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
      const authUrl = new URL(origin + "/authorize");
      authUrl.search = new URLSearchParams({
        response_type: "code",
        client_id,
        redirect_uri: "http://127.0.0.1/callback",
        code_challenge: createHash("sha256").update(verifier).digest("base64url"),
        code_challenge_method: "S256",
        resource: gateway.auth.resourceUrl.href,
        scope: "device:read offline_access",
        state: "readonly-check",
      }).toString();
      const ask = await fetch(authUrl);
      expect(ask.status).toBe(200);
      const html = await ask.text();
      const approvalId = /Request ID: <code>([0-9a-f-]+)<\/code>/u.exec(html)?.[1];
      expect(approvalId).toBeTruthy();
      expect(gateway.auth.approve(approvalId!, "v3-owner-test")).toBe(true);
      const grant = await fetch(origin + "/authorize?request_id=" + approvalId, {
        redirect: "manual",
      });
      expect(grant.status).toBe(302);
      const callback = new URL(grant.headers.get("location")!);
      expect(callback.searchParams.get("state")).toBe("readonly-check");
      const tokenResponse = await fetch(origin + "/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: callback.searchParams.get("code")!,
          client_id,
          redirect_uri: "http://127.0.0.1/callback",
          code_verifier: verifier,
          resource: gateway.auth.resourceUrl.href,
        }),
      });
      expect(tokenResponse.status).toBe(200);
      const token = (await tokenResponse.json()) as { access_token: string; scope: string };
      expect(token.scope).toBe("device:read offline_access");

      client = new Client(
        { name: "v3-oauth-smoke", version: "1.0.0" },
        { versionNegotiation: { mode: "auto" } },
      );
      await client.connect(
        new StreamableHTTPClientTransport(new URL(gateway.url), {
          requestInit: { headers: { authorization: "Bearer " + token.access_token } },
        }),
      );
      const names = (await client.listTools()).tools.map((t) => t.name).sort();
      expect(names).toEqual(["get_capabilities", "get_device", "list_devices", "v3_admin_status"]);
      const dev = await client.callTool({ name: "list_devices", arguments: {} });
      expect(dev.isError).not.toBe(true);
      expect(dev.structuredContent).toMatchObject({ result: { devices: [] } });
      const state = await client.callTool({ name: "v3_admin_status", arguments: {} });
      expect(state.structuredContent).toMatchObject({
        result: { productionReady: false, remoteExecutionEnabled: false, deviceCount: 0 },
      });
      expect(names).not.toContain("operator_submit");
    } finally {
      if (client) await client.close();
      if (gateway) await gateway.shutdown();
      await rm(root, { recursive: true, force: true });
    }
  }, 45000);
});
