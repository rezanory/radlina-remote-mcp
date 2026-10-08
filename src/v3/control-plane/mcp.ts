import { McpServer, type AuthInfo, type CallToolResult } from "@modelcontextprotocol/server";
import * as z from "zod/v4";

import { AppError, errorPayload } from "../../errors.js";
import type { OperatorPlan } from "../../operator/types.js";
import type { Risk } from "../../policy/engine.js";
import type { DeviceDescriptor } from "../device/identity.js";

type ToolContext = { http?: { authInfo?: AuthInfo }; signal?: AbortSignal };

export interface V3McpExecutionGuard {
  run<T>(
    input: {
      auth: AuthInfo | undefined;
      tool: string;
      scope: string;
      risk: Risk;
      args: unknown;
      idempotencyKey?: string;
      signal?: AbortSignal;
    },
    handler: () => Promise<T>,
  ): Promise<T>;
}

export interface V3McpIdentityPort {
  subject(auth: AuthInfo | undefined): string;
}

export interface V3McpDevicePort {
  list(): DeviceDescriptor[];
  get(deviceId: string): DeviceDescriptor | undefined;
}

export interface V3McpCapabilityPort {
  list(): unknown[];
}

export interface V3McpOperatorPort {
  submit(
    auth: AuthInfo | undefined,
    subject: string,
    profile: string,
    plan: OperatorPlan,
  ): Promise<{ jobId: string; status: string; steps: number }>;
  status(subject: string, jobId: string): Promise<unknown>;
  resume(
    auth: AuthInfo | undefined,
    subject: string,
    jobId: string,
  ): Promise<{ jobId: string; status: string }>;
  cancel(
    subject: string,
    jobId: string,
  ): Promise<{ jobId: string; status: string; requested: boolean }>;
}

export interface V3McpAdminPort {
  status(): Promise<unknown>;
}

export type V3ControlPlanePorts = {
  guard: V3McpExecutionGuard;
  identity: V3McpIdentityPort;
  devices: V3McpDevicePort;
  capabilities: V3McpCapabilityPort;
  operator: V3McpOperatorPort;
  admin: V3McpAdminPort;
};

const readAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};

const writeAnnotations = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};

const destructiveAnnotations = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: true,
  openWorldHint: false,
};

const idempotencyInput = z.string().uuid();
const operatorStepInput = z.object({
  id: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[A-Za-z][A-Za-z0-9._-]{0,63}$/u),
  capability: z.string().min(1).max(128),
  input: z.record(z.string(), z.unknown()).default({}),
  maxAttempts: z.number().int().min(1).max(3).default(1),
});

function ok(result: unknown): CallToolResult {
  const envelope: Record<string, unknown> = { result };
  return {
    content: [{ type: "text", text: JSON.stringify(envelope) }],
    structuredContent: envelope,
  };
}

function authInfo(context: ToolContext): AuthInfo | undefined {
  return context.http?.authInfo;
}

async function execute<T>(
  ports: V3ControlPlanePorts,
  context: ToolContext,
  input: {
    tool: string;
    scope: string;
    risk?: Risk;
    args: unknown;
    idempotencyKey?: string;
  },
  handler: () => Promise<T>,
): Promise<CallToolResult> {
  try {
    const result = await ports.guard.run(
      {
        auth: authInfo(context),
        tool: input.tool,
        scope: input.scope,
        risk: input.risk ?? "low",
        args: input.args,
        ...(input.idempotencyKey === undefined ? {} : { idempotencyKey: input.idempotencyKey }),
        ...(context.signal === undefined ? {} : { signal: context.signal }),
      },
      handler,
    );
    return ok(result);
  } catch (error) {
    return errorPayload(error);
  }
}

export function buildV3ControlPlaneServer(ports: V3ControlPlanePorts): McpServer {
  const server = new McpServer({
    name: "radlina-remote-mcp-v3-control-plane",
    version: "3.0.0-alpha.1",
  });

  server.registerTool(
    "who_am_i",
    {
      description: "Return the authenticated V3 control-plane subject and granted scopes.",
      inputSchema: z.object({}),
      annotations: readAnnotations,
    },
    (_args, context) =>
      execute(ports, context, { tool: "who_am_i", scope: "device:read", args: {} }, async () => ({
        subject: ports.identity.subject(authInfo(context)),
        clientId: authInfo(context)?.clientId,
        scopes: authInfo(context)?.scopes ?? [],
      })),
  );

  server.registerTool(
    "get_capabilities",
    {
      description: "Return V3 control-plane capability groups and live registry counts.",
      inputSchema: z.object({}),
      annotations: readAnnotations,
    },
    (_args, context) =>
      execute(
        ports,
        context,
        { tool: "get_capabilities", scope: "device:read", args: {} },
        async () => ({
          generation: "v3-multidevice-agent-os",
          protocol: "2026-07-28",
          transport: "streamable-http",
          compatibility: "v2-operator-compatible",
          capabilities: ["operator", "devices", "capabilities", "admin"],
          deviceCount: ports.devices.list().length,
          capabilityCount: ports.capabilities.list().length,
        }),
      ),
  );

  server.registerTool(
    "list_devices",
    {
      description: "List enrolled V3 devices from the authoritative device registry.",
      inputSchema: z.object({}),
      annotations: readAnnotations,
    },
    (_args, context) =>
      execute(
        ports,
        context,
        { tool: "list_devices", scope: "device:read", args: {} },
        async () => ({ devices: ports.devices.list() }),
      ),
  );

  server.registerTool(
    "get_device",
    {
      description: "Return one enrolled V3 device by logical device id.",
      inputSchema: z.object({ deviceId: z.string().min(1).max(128) }),
      annotations: readAnnotations,
    },
    ({ deviceId }, context) =>
      execute(
        ports,
        context,
        { tool: "get_device", scope: "device:read", args: { deviceId } },
        async () => {
          const device = ports.devices.get(deviceId);
          if (!device) throw new AppError("NOT_FOUND", "device was not found");
          return device;
        },
      ),
  );

  server.registerTool(
    "list_capabilities",
    {
      description: "List V3 executable capability metadata.",
      inputSchema: z.object({}),
      annotations: readAnnotations,
    },
    (_args, context) =>
      execute(
        ports,
        context,
        { tool: "list_capabilities", scope: "device:read", args: {} },
        async () => ({ capabilities: ports.capabilities.list() }),
      ),
  );

  server.registerTool(
    "operator_submit",
    {
      description:
        "Submit a V2-compatible Smart Operator plan through the V3 Smart Operator adapter.",
      inputSchema: z.object({
        title: z.string().min(1).max(128),
        profile: z.string().min(1).max(100).default("radlina"),
        steps: z.array(operatorStepInput).min(1).max(16),
        idempotencyKey: idempotencyInput,
      }),
      annotations: writeAnnotations,
    },
    ({ title, profile, steps, idempotencyKey }, context) =>
      execute(
        ports,
        context,
        {
          tool: "operator_submit",
          scope: "admin",
          risk: "high",
          args: {
            title,
            profile,
            steps: steps.map((step) => ({
              id: step.id,
              capability: step.capability,
              maxAttempts: step.maxAttempts,
              input: "[redacted]",
            })),
          },
          idempotencyKey,
        },
        () =>
          ports.operator.submit(
            authInfo(context),
            ports.identity.subject(authInfo(context)),
            profile,
            { title, steps },
          ),
      ),
  );

  server.registerTool(
    "operator_status",
    {
      description: "Return one caller-owned canonical workflow through the V2 operator shape.",
      inputSchema: z.object({ jobId: z.string().uuid() }),
      annotations: readAnnotations,
    },
    ({ jobId }, context) =>
      execute(ports, context, { tool: "operator_status", scope: "admin", args: { jobId } }, () =>
        ports.operator.status(ports.identity.subject(authInfo(context)), jobId),
      ),
  );

  server.registerTool(
    "operator_resume",
    {
      description: "Resume one failed/interrupted V3 operator workflow.",
      inputSchema: z.object({ jobId: z.string().uuid(), idempotencyKey: idempotencyInput }),
      annotations: writeAnnotations,
    },
    ({ jobId, idempotencyKey }, context) =>
      execute(
        ports,
        context,
        {
          tool: "operator_resume",
          scope: "admin",
          risk: "high",
          args: { jobId },
          idempotencyKey,
        },
        () =>
          ports.operator.resume(
            authInfo(context),
            ports.identity.subject(authInfo(context)),
            jobId,
          ),
      ),
  );

  server.registerTool(
    "operator_cancel",
    {
      description: "Cancel one caller-owned V3 operator workflow.",
      inputSchema: z.object({ jobId: z.string().uuid(), idempotencyKey: idempotencyInput }),
      annotations: destructiveAnnotations,
    },
    ({ jobId, idempotencyKey }, context) =>
      execute(
        ports,
        context,
        {
          tool: "operator_cancel",
          scope: "admin",
          risk: "high",
          args: { jobId },
          idempotencyKey,
        },
        () => ports.operator.cancel(ports.identity.subject(authInfo(context)), jobId),
      ),
  );

  server.registerTool(
    "v3_admin_status",
    {
      description: "Return bounded V3 control-plane readiness and governance status.",
      inputSchema: z.object({}),
      annotations: readAnnotations,
    },
    (_args, context) =>
      execute(ports, context, { tool: "v3_admin_status", scope: "admin", args: {} }, () =>
        ports.admin.status(),
      ),
  );

  return server;
}
