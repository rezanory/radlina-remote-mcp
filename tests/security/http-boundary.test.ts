import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";

import { stringify as stringifyYaml } from "yaml";
import { afterEach, describe, expect, it } from "vitest";

import { createHttpApp } from "../../src/http.js";
import { closeRuntime, createRuntime } from "../../src/runtime.js";
import { testConfig } from "../helpers/config.js";
import { issueToken } from "../helpers/oauth.js";

const cleanup: string[] = [];

afterEach(async () => {
  for (const directory of cleanup.splice(0)) await rm(directory, { recursive: true, force: true });
});

describe("HTTP security boundary", () => {
  it("rejects untrusted hosts, origins, anonymous calls, malformed input, and excess requests", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "radlina-http-boundary-"));
    cleanup.push(root);
    const config = testConfig(root);
    config.policy.rateLimitPerMinute = 2;
    const configFile = path.join(root, "config.yaml");
    await writeFile(configFile, stringifyYaml(config), "utf8");
    const runtime = await createRuntime(configFile);
    const server = createHttpApp(runtime).listen(0, "127.0.0.1");
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });
    try {
      const address = server.address() as AddressInfo;
      const base = `http://127.0.0.1:${address.port}`;
      const payload = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "unknown" });
      const badHost = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: { host: "evil.example", "content-type": "application/json" },
        body: payload,
      });
      expect(badHost.status).toBeGreaterThanOrEqual(400);

      const badOrigin = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: { origin: "https://evil.example", "content-type": "application/json" },
        body: payload,
      });
      expect(badOrigin.status).toBeGreaterThanOrEqual(400);

      const anonymous = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: payload,
      });
      expect(anonymous.status).toBe(401);
      expect(anonymous.headers.get("www-authenticate")).toContain("Bearer");

      const accessToken = await issueToken(base, runtime.auth);
      const malformed = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${accessToken}`,
          "content-type": "application/json",
        },
        body: "{",
      });
      expect(malformed.status).toBeGreaterThanOrEqual(400);

      const statuses: number[] = [];
      for (let index = 0; index < 3; index += 1) {
        const response = await fetch(`${base}/mcp`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${accessToken}`,
            "content-type": "application/json",
          },
          body: payload,
        });
        statuses.push(response.status);
      }
      expect(statuses[2]).toBe(429);

      const authHealth = await fetch(`${base}/auth-health`);
      expect(authHealth.status).toBe(200);
      expect(await authHealth.json()).toMatchObject({
        status: "healthy",
        signingReady: true,
        tokenEndpointReady: true,
      });
      const independentRegistration = await fetch(`${base}/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ redirect_uris: ["http://127.0.0.1/independent"] }),
      });
      expect(independentRegistration.status).toBe(201);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await closeRuntime(runtime);
    }
  }, 60_000);
});
