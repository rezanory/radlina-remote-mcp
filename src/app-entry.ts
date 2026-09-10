import { confirmReleaseHealthy } from "./admin/release-state.js";
import { createHttpApp } from "./http.js";
import { closeRuntime, createRuntime } from "./runtime.js";

async function postBindReadiness(
  runtime: Awaited<ReturnType<typeof createRuntime>>,
  host: string,
  port: number,
): Promise<void> {
  const profile = runtime.config.profiles[runtime.config.policy.defaultProfile];
  if (!profile) throw new Error("DEFAULT_PROFILE_UNAVAILABLE");
  const audit = await runtime.audit.verify(await runtime.audit.files());
  if (!audit.valid) throw new Error("AUDIT_CHAIN_NOT_READY");
  const probeHost = host === "0.0.0.0" || host === "::" ? "127.0.0.1" : host;
  const selectedHost = probeHost.includes(":") ? `[${probeHost}]` : probeHost;
  const response = await fetch(`http://${selectedHost}:${port}/mcp`, {
    method: "GET",
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(5_000),
  });
  if (response.status !== 401) {
    throw new Error(`AUTH_BOUNDARY_SELF_PROBE_FAILED_${response.status}`);
  }
}

export async function runApp(): Promise<void> {
  const runtime = await createRuntime();
  const config = runtime.config;
  const app = createHttpApp(runtime);

  const server = app.listen(config.server.port, config.server.host);
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  try {
    await postBindReadiness(runtime, config.server.host, config.server.port);
    await confirmReleaseHealthy();
    console.error(`[server] listening on ${config.server.host}:${config.server.port}/mcp`);
  } catch (error) {
    console.error(
      "[upgrade] post-restart readiness confirmation failed",
      error instanceof Error ? error.message : "unknown error",
    );
    await new Promise<void>((resolve) => server.close(() => resolve()));
    closeRuntime(runtime);
    throw error;
  }
  let stopping = false;
  const shutdown = (signal: string): void => {
    if (stopping) return;
    stopping = true;
    console.error(`[server] shutting down after ${signal}`);
    server.close(() => {
      closeRuntime(runtime);
      process.exitCode = 0;
    });
    setTimeout(() => {
      console.error("[server] forced shutdown after grace period");
      process.exitCode = 1;
      server.closeAllConnections();
    }, 10_000).unref();
  };
  process.once("SIGINT", () => shutdown("SIGINT"));
  process.once("SIGTERM", () => shutdown("SIGTERM"));
}
