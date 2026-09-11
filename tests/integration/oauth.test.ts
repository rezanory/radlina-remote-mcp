import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";

import express from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { AuthService } from "../../src/auth/service.js";
import { Store } from "../../src/persistence/store.js";
import { SERVER_VERSION } from "../../src/version.js";
import { testConfig } from "../helpers/config.js";

type TokenSet = {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: string;
};

type TokenReply = { response: Response; body: TokenSet | { error: string } };

async function listen(auth: AuthService): Promise<{ server: Server; base: string }> {
  const app = express();
  app.use(express.json({ limit: "32kb" }));
  auth.install(app);
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const address = server.address() as AddressInfo;
  return { server, base: `http://127.0.0.1:${address.port}` };
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

function isTokenSet(value: TokenSet | { error: string }): value is TokenSet {
  return "refresh_token" in value;
}

describe("internal OAuth resilience", () => {
  let root: string;
  let store: Store;
  let auth: AuthService;
  let server: Server;
  let base: string;

  beforeAll(async () => {
    root = await mkdtemp(path.join(os.tmpdir(), "radlina-oauth-"));
    const config = testConfig(root);
    store = new Store(config.storage.directory);
    auth = new AuthService(config, store);
    await auth.initialize();
    ({ server, base } = await listen(auth));
  });

  afterAll(async () => {
    await closeServer(server);
    store.close();
    await rm(root, { recursive: true, force: true });
  });

  async function registerClient(): Promise<string> {
    const response = await fetch(`${base}/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        redirect_uris: ["http://127.0.0.1/callback"],
        client_name: "oauth-resilience-test",
      }),
    });
    expect(response.status).toBe(201);
    return ((await response.json()) as { client_id: string }).client_id;
  }

  async function issue(
    requestedClientId?: string,
    scope = "device:read filesystem:read",
  ): Promise<{ clientId: string; tokens: TokenSet }> {
    const clientId = requestedClientId ?? (await registerClient());
    const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
    const authorize = new URL(`${base}/authorize`);
    authorize.search = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: "http://127.0.0.1/callback",
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
      code_challenge_method: "S256",
      resource: auth.resourceUrl.href,
      scope,
      state: "state-1",
    }).toString();
    const approvalResponse = await fetch(authorize);
    const approvalHtml = await approvalResponse.text();
    const requestId = /Request ID: <code>([0-9a-f-]+)<\/code>/u.exec(approvalHtml)?.[1];
    if (!requestId || !auth.approve(requestId, "oauth-test-user"))
      throw new Error("approval failed");
    const redirect = await fetch(`${base}/authorize?request_id=${encodeURIComponent(requestId)}`, {
      redirect: "manual",
    });
    expect(redirect.status).toBe(302);
    const callback = new URL(redirect.headers.get("location") ?? "");
    expect(callback.searchParams.get("state")).toBe("state-1");
    const code = callback.searchParams.get("code");
    if (!code) throw new Error("authorization code missing");
    const tokenResponse = await fetch(`${base}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: clientId,
        redirect_uri: "http://127.0.0.1/callback",
        code_verifier: verifier,
        resource: auth.resourceUrl.href,
      }),
    });
    expect(tokenResponse.status).toBe(200);
    return { clientId, tokens: (await tokenResponse.json()) as TokenSet };
  }

  async function refresh(
    refreshToken: string,
    clientId: string,
    resource = auth.resourceUrl.href,
  ): Promise<TokenReply> {
    const response = await fetch(`${base}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: clientId,
        resource,
      }),
    });
    return { response, body: (await response.json()) as TokenSet | { error: string } };
  }

  it("passes a normal authorization_code exchange", async () => {
    const { clientId, tokens } = await issue();
    expect(tokens).toMatchObject({ token_type: "Bearer", expires_in: 3600 });
    await expect(auth.verifyAccessToken(tokens.access_token)).resolves.toMatchObject({ clientId });
  });

  it("passes a normal refresh", async () => {
    const { clientId, tokens } = await issue();
    const rotated = await refresh(tokens.refresh_token, clientId);
    expect(rotated.response.status).toBe(200);
    expect(isTokenSet(rotated.body) && rotated.body.refresh_token).not.toBe(tokens.refresh_token);
  });

  it("advertises and preserves offline_access across refresh rotation", async () => {
    expect(auth.oauthMetadata().scopes_supported).toContain("offline_access");
    const { clientId, tokens } = await issue(
      undefined,
      "device:read filesystem:read offline_access",
    );
    expect(tokens.scope.split(" ")).toContain("offline_access");
    const rotated = await refresh(tokens.refresh_token, clientId);
    expect(rotated.response.status).toBe(200);
    expect(isTokenSet(rotated.body) && rotated.body.scope.split(" ")).toContain("offline_access");
  });

  it("auto-authorizes an exact previously approved owner relationship", async () => {
    const clientId = await registerClient();
    await issue(clientId, "device:read filesystem:read offline_access");
    const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
    const authorize = new URL(`${base}/authorize`);
    authorize.search = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: "http://127.0.0.1/callback",
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
      code_challenge_method: "S256",
      resource: auth.resourceUrl.href,
      scope: "device:read offline_access",
      state: "persistent-state",
    }).toString();
    const redirect = await fetch(authorize, { redirect: "manual" });
    expect(redirect.status).toBe(302);
    const callback = new URL(redirect.headers.get("location") ?? "");
    expect(callback.searchParams.get("state")).toBe("persistent-state");
    const code = callback.searchParams.get("code");
    expect(code).toBeTruthy();
    const tokenResponse = await fetch(`${base}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code ?? "",
        client_id: clientId,
        redirect_uri: "http://127.0.0.1/callback",
        code_verifier: verifier,
        resource: auth.resourceUrl.href,
      }),
    });
    expect(tokenResponse.status).toBe(200);
    expect((await tokenResponse.json()) as TokenSet).toMatchObject({
      scope: "device:read offline_access",
    });
  });

  it("restores persistent owner trust after a service and store restart", async () => {
    const restartRoot = await mkdtemp(path.join(os.tmpdir(), "radlina-owner-trust-restart-"));
    const restartConfig = testConfig(restartRoot);
    let restartStore = new Store(restartConfig.storage.directory);
    let restartAuth = new AuthService(restartConfig, restartStore);
    await restartAuth.initialize();
    let running = await listen(restartAuth);
    const originalBase = base;
    const originalAuth = auth;
    base = running.base;
    auth = restartAuth;
    try {
      const clientId = await registerClient();
      await issue(clientId, "device:read offline_access");
      await closeServer(running.server);
      restartStore.close();
      restartStore = new Store(restartConfig.storage.directory);
      restartAuth = new AuthService(restartConfig, restartStore);
      await restartAuth.initialize();
      running = await listen(restartAuth);
      base = running.base;
      auth = restartAuth;

      const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
      const authorize = new URL(`${base}/authorize`);
      authorize.search = new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: "http://127.0.0.1/callback",
        code_challenge: createHash("sha256").update(verifier).digest("base64url"),
        code_challenge_method: "S256",
        resource: auth.resourceUrl.href,
        scope: "device:read offline_access",
      }).toString();
      const redirect = await fetch(authorize, { redirect: "manual" });
      expect(redirect.status).toBe(302);
      expect(redirect.headers.get("cache-control")).toBe("no-store");
    } finally {
      await closeServer(running.server);
      restartStore.close();
      base = originalBase;
      auth = originalAuth;
      await rm(restartRoot, { recursive: true, force: true });
    }
  }, 40_000);

  it("requires local approval for new clients and scope escalation", async () => {
    const untrustedClient = await registerClient();
    const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
    const request = async (clientId: string, scope: string): Promise<Response> => {
      const authorize = new URL(`${base}/authorize`);
      authorize.search = new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: "http://127.0.0.1/callback",
        code_challenge: createHash("sha256").update(verifier).digest("base64url"),
        code_challenge_method: "S256",
        resource: auth.resourceUrl.href,
        scope,
      }).toString();
      return await fetch(authorize, { redirect: "manual" });
    };
    const newClientResponse = await request(untrustedClient, "device:read offline_access");
    expect(newClientResponse.status).toBe(200);
    expect(await newClientResponse.text()).toContain("Request ID:");

    const trustedClient = await registerClient();
    await issue(trustedClient, "device:read offline_access");
    const escalation = await request(trustedClient, "device:read filesystem:read offline_access");
    expect(escalation.status).toBe(200);
    expect(await escalation.text()).toContain("Request ID:");
  });

  it("revokes persistent owner trust and its refresh session", async () => {
    const clientId = await registerClient();
    const { tokens } = await issue(clientId, "device:read offline_access");
    const enrollment = store.db
      .prepare("SELECT enrollment_id FROM oauth_owner_enrollments WHERE client_id=?")
      .get(clientId) as { enrollment_id: string };
    expect(auth.revokeOwnerEnrollment(enrollment.enrollment_id)).toBe(true);
    expect(auth.revokeOwnerEnrollment(enrollment.enrollment_id)).toBe(false);
    expect((await refresh(tokens.refresh_token, clientId)).response.status).toBe(400);

    const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
    const authorize = new URL(`${base}/authorize`);
    authorize.search = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: "http://127.0.0.1/callback",
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
      code_challenge_method: "S256",
      resource: auth.resourceUrl.href,
      scope: "device:read offline_access",
    }).toString();
    const approval = await fetch(authorize, { redirect: "manual" });
    expect(approval.status).toBe(200);
    expect(await approval.text()).toContain("Request ID:");
  });

  it("collapses two simultaneous refreshes into the exact same replacement", async () => {
    const { clientId, tokens } = await issue();
    const [first, second] = await Promise.all([
      refresh(tokens.refresh_token, clientId),
      refresh(tokens.refresh_token, clientId),
    ]);
    expect([first.response.status, second.response.status]).toEqual([200, 200]);
    expect(second.body).toEqual(first.body);
  });

  it("makes ten concurrent same-token refreshes deterministic with one lineage", async () => {
    const { clientId, tokens } = await issue();
    const before = Number(
      (store.db.prepare("SELECT COUNT(*) AS count FROM oauth_refresh").get() as { count: number })
        .count,
    );
    const replies = await Promise.all(
      Array.from({ length: 10 }, () => refresh(tokens.refresh_token, clientId)),
    );
    expect(replies.every((reply) => reply.response.status === 200)).toBe(true);
    expect(new Set(replies.map((reply) => JSON.stringify(reply.body))).size).toBe(1);
    const after = Number(
      (store.db.prepare("SELECT COUNT(*) AS count FROM oauth_refresh").get() as { count: number })
        .count,
    );
    expect(after - before).toBe(1);
  });

  it("rejects a wrong client without consuming the valid refresh token", async () => {
    const { clientId, tokens } = await issue();
    const invalid = await refresh(tokens.refresh_token, `${clientId}-wrong`);
    expect(invalid.response.status).toBe(400);
    expect(invalid.body).toMatchObject({ error: "invalid_grant" });
    expect((await refresh(tokens.refresh_token, clientId)).response.status).toBe(200);
  });

  it("rejects a wrong resource without consuming the valid refresh token", async () => {
    const { clientId, tokens } = await issue();
    const invalid = await refresh(tokens.refresh_token, clientId, "https://wrong.invalid/mcp");
    expect(invalid.response.status).toBe(400);
    expect(invalid.body).toMatchObject({ error: "invalid_grant" });
    expect((await refresh(tokens.refresh_token, clientId)).response.status).toBe(200);
  });

  it("returns the exact same token set during replay grace", async () => {
    const { clientId, tokens } = await issue();
    const first = await refresh(tokens.refresh_token, clientId);
    const replay = await refresh(tokens.refresh_token, clientId);
    expect(replay.response.status).toBe(200);
    expect(replay.body).toEqual(first.body);
  });

  it("rejects the original token after replay grace", async () => {
    const { clientId, tokens } = await issue();
    expect((await refresh(tokens.refresh_token, clientId)).response.status).toBe(200);
    store.db
      .prepare("UPDATE oauth_refresh SET replacement_expires_at=? WHERE token_hash=?")
      .run(Date.now() - 1, createHash("sha256").update(tokens.refresh_token).digest("hex"));
    const expiredReplay = await refresh(tokens.refresh_token, clientId);
    expect(expiredReplay.response.status).toBe(400);
    expect(expiredReplay.body).toMatchObject({ error: "invalid_grant" });
  });

  it("allows the replacement refresh token to rotate normally", async () => {
    const { clientId, tokens } = await issue();
    const first = await refresh(tokens.refresh_token, clientId);
    if (!isTokenSet(first.body)) throw new Error("first rotation failed");
    const second = await refresh(first.body.refresh_token, clientId);
    expect(second.response.status).toBe(200);
    expect(isTokenSet(second.body) && second.body.refresh_token).not.toBe(first.body.refresh_token);
  });

  it("decrypts the same replay receipt after a service and store restart", async () => {
    const restartRoot = await mkdtemp(path.join(os.tmpdir(), "radlina-oauth-restart-"));
    const restartConfig = testConfig(restartRoot);
    let restartStore = new Store(restartConfig.storage.directory);
    let restartAuth = new AuthService(restartConfig, restartStore);
    await restartAuth.initialize();
    let running = await listen(restartAuth);
    const originalBase = base;
    const originalAuth = auth;
    base = running.base;
    auth = restartAuth;
    try {
      const { clientId, tokens } = await issue();
      const first = await refresh(tokens.refresh_token, clientId);
      await closeServer(running.server);
      restartStore.close();
      restartStore = new Store(restartConfig.storage.directory);
      restartAuth = new AuthService(restartConfig, restartStore);
      await restartAuth.initialize();
      running = await listen(restartAuth);
      base = running.base;
      auth = restartAuth;
      const replay = await refresh(tokens.refresh_token, clientId);
      expect(replay.response.status).toBe(200);
      expect(replay.body).toEqual(first.body);
    } finally {
      await closeServer(running.server);
      restartStore.close();
      base = originalBase;
      auth = originalAuth;
      await rm(restartRoot, { recursive: true, force: true });
    }
  }, 40_000);

  it("stores no raw access or refresh token strings in SQLite", async () => {
    const { clientId, tokens } = await issue();
    const rotated = await refresh(tokens.refresh_token, clientId);
    if (!isTokenSet(rotated.body)) throw new Error("rotation failed");
    const rows = store.db
      .prepare(
        "SELECT token_hash,client_id,scope,resource,subject,expires_at,consumed_at,replacement_protected,replacement_expires_at FROM oauth_refresh",
      )
      .all();
    const serialized = JSON.stringify(rows);
    for (const secret of [
      tokens.access_token,
      tokens.refresh_token,
      rotated.body.access_token,
      rotated.body.refresh_token,
    ]) {
      expect(serialized).not.toContain(secret);
    }
  });

  it("records only bounded non-secret OAuth event fields", async () => {
    const { clientId, tokens } = await issue();
    await refresh(tokens.refresh_token, `${clientId}-wrong`);
    const events = auth.recentOauthEvents(20) as Array<Record<string, unknown>>;
    expect(events.length).toBeGreaterThan(0);
    expect(Object.keys(events[0] ?? {}).sort()).toEqual(
      [
        "client_hash",
        "created_at",
        "error_code",
        "event_id",
        "grant_type",
        "latency_ms",
        "status",
      ].sort(),
    );
    const serialized = JSON.stringify(events);
    expect(serialized).not.toContain(clientId);
    expect(serialized).not.toContain(tokens.access_token);
    expect(serialized).not.toContain(tokens.refresh_token);
  });

  it("cleans expired refresh rows without removing live rows", async () => {
    const liveHash = createHash("sha256").update(randomUUID()).digest("hex");
    const expiredHash = createHash("sha256").update(randomUUID()).digest("hex");
    const values = ["client", "device:read", auth.resourceUrl.href, "subject"];
    store.db
      .prepare(
        "INSERT INTO oauth_refresh(token_hash,client_id,scope,resource,subject,expires_at) VALUES(?,?,?,?,?,?)",
      )
      .run(liveHash, ...values, Date.now() + 60_000);
    store.db
      .prepare(
        "INSERT INTO oauth_refresh(token_hash,client_id,scope,resource,subject,expires_at) VALUES(?,?,?,?,?,?)",
      )
      .run(expiredHash, ...values, Date.now() - 1);
    await fetch(`${base}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "unsupported" }),
    });
    expect(
      store.db.prepare("SELECT token_hash FROM oauth_refresh WHERE token_hash=?").get(expiredHash),
    ).toBeUndefined();
    expect(
      store.db.prepare("SELECT token_hash FROM oauth_refresh WHERE token_hash=?").get(liveHash),
    ).toBeTruthy();
  });

  it("preserves refresh and access-token revocation", async () => {
    const { clientId, tokens } = await issue();
    const revokeRefresh = await fetch(`${base}/revoke`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: tokens.refresh_token }),
    });
    expect(revokeRefresh.status).toBe(200);
    expect((await refresh(tokens.refresh_token, clientId)).response.status).toBe(400);
    await fetch(`${base}/revoke`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: tokens.access_token }),
    });
    await expect(auth.verifyAccessToken(tokens.access_token)).rejects.toThrow();
  });

  it("continues to verify an unrevoked access token", async () => {
    const { clientId, tokens } = await issue();
    await expect(auth.verifyAccessToken(tokens.access_token)).resolves.toMatchObject({
      clientId,
      scopes: ["device:read", "filesystem:read"],
    });
  });

  it("exposes only the five allowed non-secret auth-health fields", async () => {
    const response = await fetch(`${base}/auth-health`);
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const health = (await response.json()) as Record<string, unknown>;
    expect(Object.keys(health).sort()).toEqual(
      ["mode", "signingReady", "status", "tokenEndpointReady", "version"].sort(),
    );
    expect(health).toEqual({
      status: "healthy",
      mode: "internal",
      signingReady: true,
      tokenEndpointReady: true,
      version: SERVER_VERSION,
    });
  });
});
