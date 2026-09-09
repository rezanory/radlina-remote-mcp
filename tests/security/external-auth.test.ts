import { mkdtemp, rm } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";

import express from "express";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterEach, describe, expect, it } from "vitest";

import { AuthService } from "../../src/auth/service.js";
import { Store } from "../../src/persistence/store.js";
import { testConfig } from "../helpers/config.js";

const cleanup: string[] = [];

afterEach(async () => {
  for (const directory of cleanup.splice(0)) await rm(directory, { recursive: true, force: true });
});

describe("external OAuth verification", () => {
  it("validates signature, issuer, audience, expiration, and revocation inputs", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "radlina-external-auth-"));
    cleanup.push(root);
    const pair = await generateKeyPair("ES256");
    const jwk = { ...(await exportJWK(pair.publicKey)), kid: "test-key", alg: "ES256", use: "sig" };
    const issuerApp = express();
    let issuer = "";
    issuerApp.get("/.well-known/oauth-authorization-server/issuer", (_request, response) => {
      response.json({
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/../jwks`,
        response_types_supported: ["code"],
      });
    });
    issuerApp.get("/jwks", (_request, response) => response.json({ keys: [jwk] }));
    const issuerServer = issuerApp.listen(0, "127.0.0.1");
    await new Promise<void>((resolve, reject) => {
      issuerServer.once("listening", resolve);
      issuerServer.once("error", reject);
    });
    const address = issuerServer.address() as AddressInfo;
    const base = `http://127.0.0.1:${address.port}`;
    issuer = `${base}/issuer`;

    const config = testConfig(root);
    config.server.publicUrl = "https://mcp.example";
    config.auth.mode = "external";
    config.auth.externalIssuer = issuer;
    config.auth.externalJwksUrl = `${base}/jwks`;
    const store = new Store(config.storage.directory);
    const auth = new AuthService(config, store);
    await auth.initialize();
    const makeToken = async (claims: {
      issuer?: string;
      audience?: string;
      expiration?: number;
      key?: typeof pair.privateKey;
    }): Promise<string> =>
      new SignJWT({ scope: "device:read", client_id: "external-client" })
        .setProtectedHeader({ alg: "ES256", kid: "test-key", typ: "JWT" })
        .setIssuer(claims.issuer ?? issuer)
        .setSubject("external-user")
        .setAudience(claims.audience ?? auth.resourceUrl.href)
        .setJti(crypto.randomUUID())
        .setIssuedAt()
        .setExpirationTime(claims.expiration ?? Math.floor(Date.now() / 1000) + 60)
        .sign(claims.key ?? pair.privateKey);
    try {
      await expect(auth.verifyAccessToken(await makeToken({}))).resolves.toMatchObject({
        clientId: "external-client",
        scopes: ["device:read"],
      });
      await expect(
        auth.verifyAccessToken(await makeToken({ audience: "https://wrong.example/mcp" })),
      ).rejects.toThrow("invalid or expired access token");
      await expect(
        auth.verifyAccessToken(await makeToken({ issuer: `${base}/wrong` })),
      ).rejects.toThrow("invalid or expired access token");
      await expect(
        auth.verifyAccessToken(await makeToken({ expiration: Math.floor(Date.now() / 1000) - 60 })),
      ).rejects.toThrow("invalid or expired access token");
      const other = await generateKeyPair("ES256");
      await expect(
        auth.verifyAccessToken(await makeToken({ key: other.privateKey })),
      ).rejects.toThrow("invalid or expired access token");
      await expect(auth.verifyAccessToken("not-a-jwt")).rejects.toThrow(
        "invalid or expired access token",
      );
    } finally {
      await new Promise<void>((resolve) => issuerServer.close(() => resolve()));
      store.close();
    }
  });
});
