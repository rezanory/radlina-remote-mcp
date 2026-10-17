import path from "node:path";
import { mkdirSync } from "node:fs";
import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import helmet from "helmet";
import { createMcpExpressApp, requireBearerAuth } from "@modelcontextprotocol/express";
import { toNodeHandler } from "@modelcontextprotocol/node";
import {
  createMcpHandler,
  McpServer,
  OAuthError,
  OAuthErrorCode,
} from "@modelcontextprotocol/server";
import type { OAuthTokenVerifier } from "@modelcontextprotocol/express";
import * as z from "zod/v4";

import { AuthService } from "../../auth/service.js";
import type { AppConfig } from "../../config/schema.js";
import { configSchema } from "../../config/schema.js";
import { Store } from "../../persistence/store.js";
import { SqliteDeviceRegistry } from "../device/registry.js";
import {
  V3MacSignedHeartbeatIngress,
  effectiveTrustedDeviceHeartbeat,
  type P08HeartbeatPins,
} from "../device/mac-heartbeat-ingress.js";
import { V3WindowsScopedFiles } from "./windows-scoped-files.js";
import { registerV3FinalFourTools, registeredV3PhysicalToolNames, type V3FinalFourMcpPorts } from "../control-plane/final4-mcp-surface.js";
import { installV3PhysicalAgentRelayRoutes, type I01PhysicalRelayPorts } from "../integration/i01-agent-relay-http.js";
import type { V3FinalFourFactoryContext, V3ComposedPhysicalFinalFour } from "../control-plane/v3-physical-final4-runtime.js";

const V3_SCOPES = new Set(["device:read", "filesystem:read", "filesystem:write", "offline_access"]);
const WRITE_ANNOTATIONS = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};
const READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};

export type V3ReadOnlyGatewayOptions = {
  baseConfig: AppConfig;
  stateDirectory: string;
  publicUrl: string;
  port: number;
  windowsFileRoot?: string;
  macHeartbeatPins?: P08HeartbeatPins;
  /** Never inferred from environment: inject only after real physical adapters exist. */
  finalFour?: V3FinalFourMcpPorts;
  physicalRelay?: I01PhysicalRelayPorts;
  finalFourFactory?: (context: V3FinalFourFactoryContext) => Promise<V3ComposedPhysicalFinalFour>;
};

export type V3ReadOnlyGateway = {
  url: string;
  port: number;
  auth: AuthService;
  shutdown(): Promise<void>;
};

function independentState(stateDirectory: string, productionDirectory: string): string {
  if (!path.isAbsolute(stateDirectory)) throw new Error("V3 isolated state must be absolute");
  const requested = path.resolve(stateDirectory);
  const production = path.resolve(productionDirectory);
  const normalize = (value: string) => (process.platform === "win32" ? value.toLowerCase() : value);
  const a = normalize(requested);
  const b = normalize(production);
  if (a === b || a.startsWith(b + path.sep) || b.startsWith(a + path.sep)) {
    throw new Error("V3 state must not overlap V2 production state");
  }
  return requested;
}

class ScopedV3AuthService extends AuthService {
  constructor(config: AppConfig, store: Store, private readonly acceptedScopes: ReadonlySet<string>) {
    super(config, store, acceptedScopes);
  }
  override oauthMetadata() {
    return { ...super.oauthMetadata(), scopes_supported: [...this.acceptedScopes] };
  }
}

function verifiedScopedTokenVerifier(auth: AuthService, acceptedScopes: ReadonlySet<string>): OAuthTokenVerifier {
  return {
    verifyAccessToken: async (token: string) => {
      const info = await auth.verifyAccessToken(token);
      const scopes = info.scopes ?? [];
      if (!scopes.includes("device:read") || scopes.some((s) => !acceptedScopes.has(s))) {
        throw new OAuthError(OAuthErrorCode.InsufficientScope, "V3 OAuth scope is not allowed");
      }
      return info;
    },
  };
}

function buildScopedV3Server(
  registry: SqliteDeviceRegistry,
  windowsFiles?: V3WindowsScopedFiles,
  macIngress?: V3MacSignedHeartbeatIngress,
  finalFour?: V3FinalFourMcpPorts,
): McpServer {
  const server = new McpServer({
    name: "radlina-remote-mcp-v3-readonly",
    version: "3.0.0-alpha.1",
  });
  const success = (result: unknown) => ({
    content: [{ type: "text" as const, text: JSON.stringify({ result }) }],
    structuredContent: { result },
  });
  server.registerTool(
    "get_capabilities",
    {
      description: "Return strictly read-only V3 gateway capability metadata.",
      inputSchema: z.object({}),
      annotations: READ_ANNOTATIONS,
    },
    async () =>
      success({
        generation: "v3",
        mode: windowsFiles ? "oauth-scoped-local-windows" : "oauth-readonly-pre-enrollment",
        tools: [
          "get_capabilities",
          "list_devices",
          "get_device",
          "v3_admin_status",
          ...(windowsFiles ? ["v3_windows_write_text_file", "v3_windows_read_text_file"] : []),
          ...(finalFour ? registeredV3PhysicalToolNames(finalFour) : []),
        ],
      }),
  );
  server.registerTool(
    "list_devices",
    {
      description:
        "List devices actually enrolled in the isolated V3 registry; never invent registrations.",
      inputSchema: z.object({}),
      annotations: READ_ANNOTATIONS,
    },
    async () =>
      success({ devices: registry.list().map((d) => effectiveTrustedDeviceHeartbeat(d)) }),
  );
  server.registerTool(
    "get_device",
    {
      description: "Read a device by exact V3 logical ID.",
      inputSchema: z.object({ deviceId: z.string().min(1).max(128) }),
      annotations: READ_ANNOTATIONS,
    },
    async ({ deviceId }) =>
      success({
        device: registry.get(deviceId)
          ? effectiveTrustedDeviceHeartbeat(registry.require(deviceId))
          : null,
      }),
  );
  server.registerTool(
    "v3_admin_status",
    {
      description: "Return transparent V3 readiness; final-four operations need independent physical port injection.",
      inputSchema: z.object({}),
      annotations: READ_ANNOTATIONS,
    },
    async () =>
      success({
        generation: "v3",
        mode: windowsFiles ? "oauth-scoped-local-windows" : "oauth-readonly-pre-enrollment",
        productionReady: finalFour?.acceptance?.readiness().productionReady ?? false,
        remoteExecutionEnabled: Boolean(finalFour),
        deviceCount: registry.list().length,
        localWindowsFileOperationsEnabled: Boolean(windowsFiles),
        macSignedHeartbeatIngressEnabled: Boolean(macIngress),
        finalFourPortsBound: Boolean(finalFour?.fleet && finalFour?.acceptance),
        i01PortsBound: Boolean(finalFour),
      }),
  );
  if (windowsFiles) {
    server.registerTool(
      "v3_windows_write_text_file",
      {
        description:
          "Write UTF-8 through the native local Windows V3 adapter under an owner-approved root. Requires filesystem:write OAuth.",
        inputSchema: z.object({
          targetDeviceId: z.literal("windows-main"),
          relativePath: z.string().min(1).max(1024),
          content: z.string().max(65536),
          overwrite: z.boolean().default(false),
          idempotencyKey: z.string().uuid(),
        }),
        annotations: WRITE_ANNOTATIONS,
      },
      async (input, context) => success(await windowsFiles.write(input, context.http?.authInfo)),
    );
    server.registerTool(
      "v3_windows_read_text_file",
      {
        description:
          "Read bounded UTF-8 via native local Windows V3 adapter under an owner-approved root. Requires filesystem:read OAuth.",
        inputSchema: z.object({
          targetDeviceId: z.literal("windows-main"),
          relativePath: z.string().min(1).max(1024),
        }),
        annotations: READ_ANNOTATIONS,
      },
      async (input, context) => success(await windowsFiles.read(input, context.http?.authInfo)),
    );
  }
  if (finalFour) registerV3FinalFourTools(server, finalFour);
  return server;
}

export async function startV3ReadOnlyOAuthGateway(
  options: V3ReadOnlyGatewayOptions,
): Promise<V3ReadOnlyGateway> {
  const publicUrl = new URL(options.publicUrl);
  const allowedProtocol =
    publicUrl.protocol === "https:" ||
    (publicUrl.protocol === "http:" &&
      ["localhost", "127.0.0.1", "::1"].includes(publicUrl.hostname));
  if (
    !allowedProtocol ||
    publicUrl.pathname !== "/" ||
    publicUrl.search ||
    publicUrl.hash ||
    publicUrl.username ||
    publicUrl.password
  ) {
    throw new Error(
      "V3 public URL requires a clean HTTPS origin (HTTP allowed only for localhost tests)",
    );
  }
  if (publicUrl.origin === new URL(options.baseConfig.server.publicUrl).origin) {
    throw new Error("V3 requires a different OAuth issuer and host from V2");
  }
  if (
    !Number.isSafeInteger(options.port) ||
    options.port < 1024 ||
    options.port > 65535 ||
    [7337, 7343, 8765].includes(options.port)
  ) {
    throw new Error("V3 requires an independent non-production port");
  }
  const stateRoot = independentState(options.stateDirectory, options.baseConfig.storage.directory);
  mkdirSync(stateRoot, { recursive: true });
  const cfg = configSchema.parse({
    ...options.baseConfig,
    server: {
      ...options.baseConfig.server,
      host: "127.0.0.1",
      port: options.port,
      publicUrl: publicUrl.origin,
      allowedHosts: [...new Set(["127.0.0.1", "localhost", publicUrl.hostname])],
    },
    auth: { ...options.baseConfig.auth, mode: "internal" },
    storage: { directory: path.join(stateRoot, "oauth") },
    audit: { ...options.baseConfig.audit, directory: path.join(stateRoot, "audit") },
  });
  const store = new Store(cfg.storage.directory);
  const registry = new SqliteDeviceRegistry(path.join(stateRoot, "v3-devices.sqlite3"));
  let server: Server | undefined;
  let windowsFiles: V3WindowsScopedFiles | undefined;
  let macIngress: V3MacSignedHeartbeatIngress | undefined;
  let composed: V3ComposedPhysicalFinalFour | undefined;
  const acceptedScopes = new Set(V3_SCOPES);
  if (options.finalFour || options.finalFourFactory) {
    acceptedScopes.add("device:execute");
    acceptedScopes.add("fleet:control");
  }
  try {
    const auth = new ScopedV3AuthService(cfg, store, acceptedScopes);
    await auth.initialize();
    if (options.finalFourFactory) {
      composed = await options.finalFourFactory({config:cfg,store,registry,stateRoot,auth});
    }
    const finalFour = composed?.finalFour ?? options.finalFour;
    // Only real bound fleet authority may advertise its OAuth control scope.
    if(!finalFour?.fleet)acceptedScopes.delete("fleet:control");
    const physicalRelay = composed?.physicalRelay ?? options.physicalRelay;
    if (options.macHeartbeatPins) {
      macIngress = new V3MacSignedHeartbeatIngress(registry, options.macHeartbeatPins);
    }
    if (options.windowsFileRoot) {
      windowsFiles = new V3WindowsScopedFiles(
        cfg,
        store,
        registry,
        options.windowsFileRoot,
        stateRoot,
      );
    }
    const app = createMcpExpressApp({
      host: "127.0.0.1",
      allowedHosts: cfg.server.allowedHosts,
      allowedOrigins: cfg.server.allowedOrigins,
      jsonLimit: "1mb",
    });
    app.disable("x-powered-by");
    app.use(helmet({ crossOriginEmbedderPolicy: false }));
    // Reject privilege escalation before the reused OAuth provider sees authorization requests.
    app.use("/authorize", (request, response, next) => {
      const raw = request.query["scope"];
      if (
        typeof raw === "string" &&
        raw.trim() &&
        raw
          .trim()
          .split(/\s+/u)
          .some((scope) => !acceptedScopes.has(scope))
      ) {
        response
          .status(400)
          .json({ error: "invalid_scope", error_description: "V3 scope is not allowed" });
        return;
      }
      next();
    });
    auth.install(app);
    if (physicalRelay) installV3PhysicalAgentRelayRoutes(app, physicalRelay);
    if (macIngress) {
      let recentAt = 0;
      const ingress = macIngress;
      app.post("/v3/agent/heartbeat", express.json({ limit: "8kb" }), (request, response) => {
        const now = Date.now();
        if (now - recentAt < 1500) {
          response.status(429).json({ error: "rate_limited" });
          return;
        }
        recentAt = now;
        try {
          if (Buffer.byteLength(JSON.stringify(request.body ?? null), "utf8") > 8192) {
            response.status(413).json({ error: "bounded_heartbeat_required" });
            return;
          }
          const receipt = ingress.receive(request.body);
          response.status(200).json(receipt);
        } catch {
          response.status(403).json({ error: "signed_mac_identity_required" });
        }
      });
    }
    const mcpHandler = createMcpHandler(
      () => buildScopedV3Server(registry, windowsFiles, macIngress, finalFour),
      {
        legacy: "reject",
      },
    );
    const nodeHandler = toNodeHandler(mcpHandler);
    const bearer = requireBearerAuth({
      verifier: verifiedScopedTokenVerifier(auth, acceptedScopes),
      resourceMetadataUrl: auth.resourceMetadataUrl(),
    });
    app.all("/mcp", bearer, (request, response) => {
      void nodeHandler(request, response, request.body);
    });
    app.use((_request, response) => response.status(404).json({ error: "not_found" }));
    server = app.listen(options.port, "127.0.0.1");
    const active = server;
    await new Promise<void>((resolve, reject) => {
      active.once("listening", resolve);
      active.once("error", reject);
    });
    const address = active.address() as AddressInfo;
    return {
      url: "http://127.0.0.1:" + address.port + "/mcp",
      port: address.port,
      auth,
      shutdown: async () => {
        try {
          active.closeIdleConnections();
          await new Promise<void>((resolve, reject) =>
            active.close((err) => (err ? reject(err) : resolve())),
          );
        } finally {
          await composed?.close();
          await windowsFiles?.close();
          registry.close();
          store.close();
        }
      },
    };
  } catch (error) {
    if (server?.listening) await new Promise<void>((resolve) => server!.close(() => resolve()));
    await composed?.close();
    await windowsFiles?.close();
    registry.close();
    store.close();
    throw error;
  }
}
