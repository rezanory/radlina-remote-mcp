import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { stringify as stringifyYaml } from "yaml";

import type { AuthService } from "../auth/service.js";
import type { AppConfig } from "../config/schema.js";
import { createHttpApp } from "../http.js";
import { closeRuntime, createRuntime } from "../runtime.js";

interface Measurement {
  samples: number;
  successes: number;
  failures: number;
  successRate: number;
  p50Ms: number;
  p95Ms: number;
}

function percentile(values: number[], fraction: number): number {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * fraction))] ?? 0;
}

function summarize(durations: number[], failures = 0): Measurement {
  const successes = durations.length;
  const samples = successes + failures;
  return {
    samples,
    successes,
    failures,
    successRate: samples === 0 ? 0 : successes / samples,
    p50Ms: Number(percentile(durations, 0.5).toFixed(3)),
    p95Ms: Number(percentile(durations, 0.95).toFixed(3)),
  };
}

async function measure(count: number, operation: () => Promise<void>): Promise<Measurement> {
  const durations: number[] = [];
  let failures = 0;
  for (let index = 0; index < count; index += 1) {
    const started = performance.now();
    try {
      await operation();
      durations.push(performance.now() - started);
    } catch {
      failures += 1;
    }
  }
  return summarize(durations, failures);
}

async function issueToken(base: string, auth: AuthService): Promise<string> {
  const registration = await fetch(`${base}/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      redirect_uris: ["http://127.0.0.1/callback"],
      client_name: "radlina-local-benchmark",
    }),
  });
  const registered = (await registration.json()) as { client_id?: unknown };
  if (typeof registered.client_id !== "string") throw new Error("benchmark registration failed");
  const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
  const authorize = new URL(`${base}/authorize`);
  authorize.search = new URLSearchParams({
    response_type: "code",
    client_id: registered.client_id,
    redirect_uri: "http://127.0.0.1/callback",
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
    resource: auth.resourceUrl.href,
    scope: "device:read filesystem:read filesystem:write process:read process:execute admin",
  }).toString();
  const approvalHtml = await (await fetch(authorize)).text();
  const requestId = /Request ID: <code>([0-9a-f-]+)<\/code>/u.exec(approvalHtml)?.[1];
  if (!requestId || !auth.approve(requestId, "local-benchmark")) {
    throw new Error("benchmark authorization approval failed");
  }
  const redirect = await fetch(`${base}/authorize?request_id=${requestId}`, { redirect: "manual" });
  const code = new URL(redirect.headers.get("location") ?? "").searchParams.get("code");
  if (!code) throw new Error("benchmark authorization code missing");
  const token = await fetch(`${base}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: registered.client_id,
      redirect_uri: "http://127.0.0.1/callback",
      code_verifier: verifier,
      resource: auth.resourceUrl.href,
    }),
  });
  const value = (await token.json()) as { access_token?: unknown };
  if (typeof value.access_token !== "string") throw new Error("benchmark token issuance failed");
  return value.access_token;
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("tool returned an unexpected result shape");
  }
  return value as Record<string, unknown>;
}

async function invoke(
  client: Client,
  name: string,
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const response = await client.callTool({ name, arguments: args });
  if (response.isError) throw new Error(`${name} returned an error`);
  return object(object(response.structuredContent)["result"]);
}

async function waitFor(
  read: () => Promise<Record<string, unknown>>,
  maximumAttempts = 200,
): Promise<Record<string, unknown>> {
  for (let attempt = 0; attempt < maximumAttempts; attempt += 1) {
    const value = await read();
    if (value["status"] !== "running") return value;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("benchmark session did not complete");
}

async function main(): Promise<void> {
  const root = await mkdtemp(path.join(os.tmpdir(), "radlina-benchmark-"));
  const configFile = path.join(root, "config.yaml");
  const sampleFile = path.join(root, "sample.txt");
  await writeFile(sampleFile, "benchmark needle\n", "utf8");
  const config: AppConfig = {
    server: {
      host: "127.0.0.1",
      port: 7337,
      publicUrl: "http://127.0.0.1:7337",
      allowedHosts: ["127.0.0.1", "localhost"],
      allowedOrigins: [],
      requestBodyBytes: 1_048_576,
      requestTimeoutMs: 30_000,
    },
    auth: {
      mode: "internal",
      accessTokenTtlSeconds: 600,
      refreshTokenTtlSeconds: 86_400,
      refreshReplayGraceSeconds: 30,
      pairingCodeTtlSeconds: 600,
      allowedRedirectHosts: ["127.0.0.1", "localhost"],
    },
    policy: {
      defaultProfile: "benchmark",
      emergencyReadOnly: false,
      killSwitch: false,
      maxConcurrentRequests: 8,
      rateLimitPerMinute: 10_000,
      maxFileBytes: 10 * 1024 * 1024,
      maxOutputBytes: 1024 * 1024,
      maxProcessRuntimeMs: 15_000,
      maxSearchRuntimeMs: 15_000,
      maxSessions: 16,
    },
    reliability: {
      enabled: true,
      probeIntervalMs: 30_000,
      failureThreshold: 3,
      auditVerifyIntervalMs: 300_000,
      eventRetention: 2_000,
    },
    dependencies: {
      ripgrepExecutable:
        "C:\\radlina-remote-mcp\\.runtime\\ripgrep-15.2.0-x86_64-pc-windows-msvc\\rg.exe",
    },
    profiles: {
      benchmark: {
        roots: [root],
        commands: [{ executable: process.execPath, argumentPatterns: ["^--version$"] }],
        allowShell: false,
        allowTrash: false,
        envAllowlist: [],
      },
    },
    storage: { directory: path.win32.join(root, ".state") },
    audit: {
      directory: path.win32.join(root, ".state", "audit"),
      rotateBytes: 1024 * 1024,
      userRedactionPatterns: [],
    },
  };
  await writeFile(configFile, stringifyYaml(config), "utf8");
  const runtime = await createRuntime(configFile);
  const server = createHttpApp(runtime).listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const client = new Client(
    { name: "radlina-local-benchmark", version: "1.0.0" },
    { versionNegotiation: { mode: "auto" } },
  );
  try {
    const address = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${address.port}`;
    const accessToken = await issueToken(base, runtime.auth);
    await client.connect(
      new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
        authProvider: { token: async () => accessToken },
      }),
    );

    const ping = await measure(100, async () => void (await invoke(client, "ping", {})));
    const listDirectory = await measure(
      25,
      async () => void (await invoke(client, "list_directory", { path: root, limit: 20 })),
    );
    const readFile = await measure(
      25,
      async () =>
        void (await invoke(client, "read_file", { path: sampleFile, offset: 0, length: 1024 })),
    );

    const concurrentDurations: number[] = [];
    let concurrentFailures = 0;
    for (let batch = 0; batch < 6; batch += 1) {
      await Promise.all(
        Array.from({ length: 8 }, async () => {
          const started = performance.now();
          try {
            await invoke(client, "ping", {});
            concurrentDurations.push(performance.now() - started);
          } catch {
            concurrentFailures += 1;
          }
        }),
      );
    }
    const boundedConcurrency = summarize(concurrentDurations, concurrentFailures);

    const searchStartDurations: number[] = [];
    const searchResultDurations: number[] = [];
    for (let index = 0; index < 10; index += 1) {
      let started = performance.now();
      const search = await invoke(client, "start_search", {
        mode: "content",
        path: root,
        pattern: "benchmark needle",
        literal: true,
        maxResults: 10,
      });
      searchStartDurations.push(performance.now() - started);
      if (typeof search["searchId"] !== "string") throw new Error("search id missing");
      const searchId = search["searchId"];
      await waitFor(() => invoke(client, "search_status", { searchId }));
      started = performance.now();
      await invoke(client, "search_results", { searchId, limit: 10 });
      searchResultDurations.push(performance.now() - started);
    }

    const processStartDurations: number[] = [];
    const processOutputDurations: number[] = [];
    for (let index = 0; index < 10; index += 1) {
      let started = performance.now();
      const processResult = await invoke(client, "start_process", {
        executable: process.execPath,
        args: ["--version"],
        cwd: root,
        idempotencyKey: randomUUID(),
      });
      processStartDurations.push(performance.now() - started);
      if (typeof processResult["sessionId"] !== "string") throw new Error("process id missing");
      const sessionId = processResult["sessionId"];
      await waitFor(() => invoke(client, "read_process_output", { sessionId, maxBytes: 4096 }));
      started = performance.now();
      await invoke(client, "read_process_output", { sessionId, maxBytes: 4096 });
      processOutputDurations.push(performance.now() - started);
    }

    const result = {
      conditions: {
        timestamp: new Date().toISOString(),
        hostname: os.hostname(),
        platform: `${process.platform}-${process.arch}`,
        node: process.version,
        protocol: client.getNegotiatedProtocolVersion(),
        transport: "loopback Streamable HTTP",
        sequentialReadOnlyRequests: 100,
        concurrency: 8,
        concurrentRequests: 48,
      },
      measurements: {
        ping,
        readFile,
        listDirectory,
        boundedConcurrency,
        searchStart: summarize(searchStartDurations),
        searchResults: summarize(searchResultDurations),
        shortProcessStart: summarize(processStartDurations),
        persistentProcessOutput: summarize(processOutputDurations),
      },
    };
    const totalFailures = Object.values(result.measurements).reduce(
      (sum, item) => sum + item.failures,
      0,
    );
    const totalSamples = Object.values(result.measurements).reduce(
      (sum, item) => sum + item.samples,
      0,
    );
    if (totalSamples === 0 || (totalSamples - totalFailures) / totalSamples < 0.99) {
      throw new Error("benchmark success rate was below 99%");
    }
    console.log(JSON.stringify(result));
  } finally {
    await client.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    closeRuntime(runtime);
    await rm(root, { recursive: true, force: true });
  }
}

void main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : "benchmark failed");
  process.exitCode = 1;
});
