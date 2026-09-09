import { createHttpApp } from "./http.js";
import { closeRuntime, createRuntime } from "./runtime.js";

async function main(): Promise<void> {
  const runtime = await createRuntime();
  const config = runtime.config;
  const app = createHttpApp(runtime);

  const server = app.listen(config.server.port, config.server.host, () => {
    console.error(`[server] listening on ${config.server.host}:${config.server.port}/mcp`);
  });
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

void main().catch((error: unknown) => {
  console.error(
    "[server] startup failed",
    error instanceof Error ? error.message : "unknown error",
  );
  process.exitCode = 1;
});
