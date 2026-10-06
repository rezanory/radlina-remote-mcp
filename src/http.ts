import { createMcpExpressApp, requireBearerAuth } from "@modelcontextprotocol/express";
import { toNodeHandler } from "@modelcontextprotocol/node";
import { createMcpHandler } from "@modelcontextprotocol/server";
import type { Express, NextFunction, Request, Response } from "express";
import helmet from "helmet";

import { buildMcpServer } from "./mcp.js";
import type { AppRuntime } from "./runtime.js";
import { rateLimit } from "./transport/rate-limit.js";

const AUTH_CONTROL_PATHS = [
  "/.well-known/oauth-authorization-server",
  "/.well-known/oauth-protected-resource",
  "/.well-known/oauth-protected-resource/mcp",
  "/register",
  "/authorize",
  "/token",
  "/revoke",
  "/jwks",
  "/auth-health",
];

function concurrencyLimit(maximum: number) {
  let active = 0;
  return (_request: Request, response: Response, next: NextFunction): void => {
    if (active >= maximum) {
      response.setHeader("retry-after", "1");
      response.status(503).json({ error: "server_busy" });
      return;
    }
    active += 1;
    let released = false;
    const release = (): void => {
      if (released) return;
      released = true;
      active -= 1;
    };
    response.once("finish", release);
    response.once("close", release);
    next();
  };
}

export function createHttpApp(runtime: AppRuntime): Express {
  const config = runtime.config;
  const app = createMcpExpressApp({
    host: config.server.host,
    allowedHosts: config.server.allowedHosts,
    allowedOrigins: config.server.allowedOrigins,
    jsonLimit: `${config.server.requestBodyBytes}b`,
  });
  app.disable("x-powered-by");
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: { defaultSrc: ["'none'"], styleSrc: ["'unsafe-inline'"], baseUri: ["'none'"] },
      },
      crossOriginEmbedderPolicy: false,
    }),
  );
  app.use(
    AUTH_CONTROL_PATHS,
    rateLimit(Math.max(config.policy.rateLimitPerMinute * 5, 300)),
    concurrencyLimit(Math.max(config.policy.maxConcurrentRequests, 8)),
  );
  runtime.auth.install(app);

  let mcpHandler: ReturnType<typeof createMcpHandler>;
  mcpHandler = createMcpHandler(
    () => buildMcpServer(runtime, () => mcpHandler.notify.toolsChanged()),
    { legacy: "reject" },
  );
  const nodeHandler = toNodeHandler(mcpHandler);
  const bearer = requireBearerAuth({
    verifier: runtime.auth,
    resourceMetadataUrl: runtime.auth.resourceMetadataUrl(),
  });
  app.all(
    "/mcp",
    bearer,
    rateLimit(config.policy.rateLimitPerMinute),
    concurrencyLimit(config.policy.maxConcurrentRequests),
    (request, response) => {
      request.setTimeout(config.server.requestTimeoutMs);
      response.setTimeout(config.server.requestTimeoutMs);
      void nodeHandler(request, response, request.body);
    },
  );
  app.use((_request, response) => response.status(404).json({ error: "not_found" }));
  app.use((error: unknown, _request: Request, response: Response, _next: NextFunction) => {
    void _next;
    console.error(
      "[server] request failed",
      error instanceof Error ? error.message : "unknown error",
    );
    if (!response.headersSent) response.status(500).json({ error: "internal_error" });
  });
  return app;
}
