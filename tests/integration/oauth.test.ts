import { mkdtemp, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";

import express from "express";
import { afterEach, describe, expect, it } from "vitest";

import { AuthService } from "../../src/auth/service.js";
import { Store } from "../../src/persistence/store.js";
import { testConfig } from "../helpers/config.js";

const cleanup: string[] = [];

afterEach(async () => {
  for (const directory of cleanup.splice(0)) await rm(directory, { recursive: true, force: true });
});

describe("internal OAuth", () => {
  it("requires local approval, validates PKCE, issues scoped tokens, and rotates refresh tokens", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "radlina-oauth-"));
    cleanup.push(root);
    const config = testConfig(root);
    const store = new Store(config.storage.directory);
    const auth = new AuthService(config, store);
    await auth.initialize();
    const app = express();
    app.use(express.json({ limit: "32kb" }));
    auth.install(app);
    const server = app.listen(0, "127.0.0.1");
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });
    try {
      const address = server.address() as AddressInfo;
      const base = `http://127.0.0.1:${address.port}`;
      const registration = await fetch(`${base}/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ redirect_uris: ["http://127.0.0.1/callback"], client_name: "test" }),
      });
      expect(registration.status).toBe(201);
      const client = (await registration.json()) as { client_id: string };
      const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
      const challenge = createHash("sha256").update(verifier).digest("base64url");
      const authorize = new URL(`${base}/authorize`);
      authorize.search = new URLSearchParams({
        response_type: "code",
        client_id: client.client_id,
        redirect_uri: "http://127.0.0.1/callback",
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource: auth.resourceUrl.href,
        scope: "device:read filesystem:read",
        state: "state-1",
      }).toString();
      const approvalResponse = await fetch(authorize);
      const approvalHtml = await approvalResponse.text();
      const requestId = /Request ID: <code>([0-9a-f-]+)<\/code>/u.exec(approvalHtml)?.[1];
      expect(requestId).toBeTruthy();
      if (!requestId) throw new Error("approval request ID missing");
      expect(auth.approve(requestId, "test-user")).toBe(true);
      const redirect = await fetch(
        `${base}/authorize?request_id=${encodeURIComponent(requestId)}`,
        { redirect: "manual" },
      );
      expect(redirect.status).toBe(302);
      const callback = new URL(redirect.headers.get("location") ?? "");
      expect(callback.searchParams.get("state")).toBe("state-1");
      const code = callback.searchParams.get("code");
      if (!code) throw new Error("authorization code missing");
      const tokenBody = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: client.client_id,
        redirect_uri: "http://127.0.0.1/callback",
        code_verifier: verifier,
        resource: auth.resourceUrl.href,
      });
      const tokenResponse = await fetch(`${base}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: tokenBody,
      });
      expect(tokenResponse.status).toBe(200);
      const tokens = (await tokenResponse.json()) as {
        access_token: string;
        refresh_token: string;
        scope: string;
      };
      await expect(auth.verifyAccessToken(tokens.access_token)).resolves.toMatchObject({
        clientId: client.client_id,
        scopes: ["device:read", "filesystem:read"],
      });
      const refreshBody = new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
        client_id: client.client_id,
        resource: auth.resourceUrl.href,
      });
      const refreshed = await fetch(`${base}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: refreshBody,
      });
      expect(refreshed.status).toBe(200);
      const replay = await fetch(`${base}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: refreshBody,
      });
      expect(replay.status).toBe(400);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      store.close();
    }
  });
});
