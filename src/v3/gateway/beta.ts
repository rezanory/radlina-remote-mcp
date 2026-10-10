import { timingSafeEqual } from "node:crypto";
import { mkdirSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";

import { createMcpExpressApp } from "@modelcontextprotocol/express";
import { toNodeHandler } from "@modelcontextprotocol/node";
import { createMcpHandler } from "@modelcontextprotocol/server";

import { AppError } from "../../errors.js";
import { buildV3ControlPlaneServer, type V3ControlPlanePorts } from "../control-plane/mcp.js";
import { SqliteDeviceRegistry } from "../device/registry.js";

/**
 * Side-by-side V3 transport and P03 registry smoke boundary.
 * NOT a production multi-device router, an enrollment authority, or OAuth.
 * It deliberately refuses all operator/device mutation and all non-loopback access.
 */
export const V3_LOCAL_BETA_MODE = "isolated-readonly-pre-enrollment" as const;

const READ_TOOLS = new Set([
  "get_capabilities",
  "list_devices",
  "get_device",
  "list_capabilities",
  "v3_admin_status",
]);

export type LocalV3BetaGatewayOptions = {
  stateDirectory: string;
  port: number;
  bearerToken: string;
};

export type LocalV3BetaGateway = {
  url: string;
  healthUrl: string;
  port: number;
  shutdown(): Promise<void>;
};

function authorized(header: string | undefined, expectedToken: string): boolean {
  if (!header?.startsWith("Bearer ")) return false;
  const supplied = Buffer.from(header.slice("Bearer ".length), "utf8");
  const expected = Buffer.from(expectedToken, "utf8");
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

export async function startLocalV3BetaGateway(
  options: LocalV3BetaGatewayOptions,
): Promise<LocalV3BetaGateway> {
  const stateRoot = path.resolve(options.stateDirectory);
  if (!path.isAbsolute(options.stateDirectory) || !options.stateDirectory.trim()) {
    throw new Error("V3 beta requires an independent absolute state directory");
  }
  if (stateRoot.toLowerCase().endsWith(path.sep + ".state")) {
    throw new Error("V3 beta cannot reuse an existing production .state directory");
  }
  if (
    !Number.isSafeInteger(options.port) ||
    (options.port !== 0 && (options.port < 1024 || options.port > 65535)) ||
    [443, 7337, 8765].includes(options.port)
  ) {
    throw new Error("V3 beta port is invalid or reserved");
  }
  if (Buffer.byteLength(options.bearerToken, "utf8") < 32) {
    throw new Error("V3 beta bearer token must contain at least 32 bytes");
  }

  mkdirSync(stateRoot, { recursive: true });
  const registry = new SqliteDeviceRegistry(path.join(stateRoot, "v3-beta-devices.sqlite3"));
  const ports: V3ControlPlanePorts = {
    guard: {
      run: async (input, handler) => {
        if (!READ_TOOLS.has(input.tool)) {
          throw new AppError(
            "POLICY_DENIED",
            "V3 beta blocks operator execution and changes until real-device acceptance",
          );
        }
        return await handler();
      },
    },
    identity: {
      subject: () => {
        throw new AppError("POLICY_DENIED", "local V3 beta does not grant user OAuth identity");
      },
    },
    devices: {
      list: () => registry.list(),
      get: (deviceId) => registry.get(deviceId),
    },
    capabilities: { list: () => [] },
    operator: {
      submit: async () => {
        throw new AppError("POLICY_DENIED", "V3 beta operator execution disabled");
      },
      status: async () => {
        throw new AppError("POLICY_DENIED", "V3 beta operator status disabled");
      },
      resume: async () => {
        throw new AppError("POLICY_DENIED", "V3 beta operator resume disabled");
      },
      cancel: async () => {
        throw new AppError("POLICY_DENIED", "V3 beta operator cancel disabled");
      },
    },
    admin: {
      status: async () => ({
        generation: "v3-multidevice-agent-os",
        mode: V3_LOCAL_BETA_MODE,
        productionReady: false,
        ready: false,
        enrolledDeviceCount: registry.list().length,
        acceptedImplementationNodes: 24,
        totalImplementationNodes: 28,
        reason: "awaiting real Mac enrollment and P08/F01/I01/AC01 operational acceptance",
      }),
    },
  };

  const app = createMcpExpressApp({
    host: "127.0.0.1",
    allowedHosts: ["127.0.0.1", "localhost"],
    allowedOrigins: [],
    jsonLimit: "1mb",
  });
  app.use((req, res, next) => {
    if (!authorized(req.headers.authorization, options.bearerToken)) {
      res.status(401).json({ error: "V3_BETA_UNAUTHORIZED" });
      return;
    }
    next();
  });
  app.get("/v3-beta-health", (_req, res) => {
    res.json({
      mode: V3_LOCAL_BETA_MODE,
      status: "local-testing-only",
      productionReady: false,
      enrolledDeviceCount: registry.list().length,
    });
  });

  const handler = createMcpHandler(() => buildV3ControlPlaneServer(ports), {
    legacy: "reject",
  });
  const nodeHandler = toNodeHandler(handler);
  app.all("/mcp", (req, res) => {
    void nodeHandler(req, res, req.body);
  });

  let server: Server | undefined;
  try {
    server = app.listen(options.port, "127.0.0.1");
    const active = server;
    await new Promise<void>((resolve, reject) => {
      active.once("listening", resolve);
      active.once("error", reject);
    });
    const address = active.address() as AddressInfo;
    return {
      port: address.port,
      url: `http://127.0.0.1:${address.port}/mcp`,
      healthUrl: `http://127.0.0.1:${address.port}/v3-beta-health`,
      shutdown: async () => {
        try {
          active.closeIdleConnections();
          await new Promise<void>((resolve, reject) => {
            active.close((error) => (error ? reject(error) : resolve()));
          });
        } finally {
          registry.close();
        }
      },
    };
  } catch (error) {
    if (server?.listening) {
      await new Promise<void>((resolve) => server!.close(() => resolve()));
    }
    registry.close();
    throw error;
  }
}
