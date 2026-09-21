import { setTimeout as delay } from "node:timers/promises";

import * as z from "zod/v4";

import type { AppConfig } from "../config/schema.js";
import { AppError } from "../errors.js";
import type { FilesystemService } from "../tools/filesystem/service.js";
import type { ProcessManager } from "../tools/process/manager.js";
import type { RadlinaComponent } from "./contracts.js";

const filesystemInfoInput = z.object({
  path: z.string().min(1).max(32_768),
  expectedType: z.enum(["file", "directory", "symlink", "other"]).optional(),
});

const processExecInput = z.object({
  executable: z.string().min(1).max(32_768),
  args: z.array(z.string().max(4096)).max(128).default([]),
  cwd: z.string().min(1).max(32_768),
  env: z.record(z.string(), z.string().max(4096)).optional(),
  timeoutMs: z.number().int().min(100).max(86_400_000).optional(),
  successExitCodes: z.array(z.number().int()).min(1).max(16).default([0]),
});

type BuiltinDependencies = {
  config: AppConfig;
  filesystems: Map<string, FilesystemService>;
  processes: ProcessManager;
  startedAt: number;
};

function profileServices(dependencies: BuiltinDependencies, profileName: string) {
  const profile = dependencies.config.profiles[profileName];
  const filesystem = dependencies.filesystems.get(profileName);
  if (!profile || !filesystem) {
    throw new AppError("POLICY_DENIED", `workspace profile ${profileName} does not exist`);
  }
  return { profile, filesystem };
}

export function createBuiltinComponents(dependencies: BuiltinDependencies): RadlinaComponent[] {
  const device: RadlinaComponent = {
    id: "radlina.device",
    version: "1.0.0",
    description: "Built-in local device inspection capabilities.",
    capabilities: [
      {
        id: "device.health",
        version: "1.0.0",
        description: "Return deterministic local service health for an operator plan.",
        requiredScope: "device:read",
        risk: "low",
        readOnly: true,
        idempotent: true,
        execute: async (_context, input) => {
          z.object({}).parse(input ?? {});
          return {
            status: "healthy",
            uptimeSeconds: Math.max(0, Math.floor((Date.now() - dependencies.startedAt) / 1000)),
          };
        },
      },
    ],
  };

  const filesystem: RadlinaComponent = {
    id: "radlina.filesystem",
    version: "1.0.0",
    description: "Built-in policy-bounded filesystem capabilities.",
    capabilities: [
      {
        id: "filesystem.info",
        version: "1.0.0",
        description: "Inspect and optionally verify the type of one policy-approved path.",
        requiredScope: "filesystem:read",
        risk: "low",
        readOnly: true,
        idempotent: true,
        execute: async (context, rawInput) => {
          const input = filesystemInfoInput.parse(rawInput);
          const selected = profileServices(dependencies, context.profile);
          const result = (await selected.filesystem.getFileInfo(input.path)) as Record<
            string,
            unknown
          >;
          if (input.expectedType && result["type"] !== input.expectedType) {
            throw new AppError(
              "CONFLICT",
              `filesystem verification failed: expected ${input.expectedType}`,
            );
          }
          return { ...result, verified: input.expectedType ? true : undefined };
        },
      },
    ],
  };

  const process: RadlinaComponent = {
    id: "radlina.process",
    version: "1.0.0",
    description: "Built-in policy-bounded process execution capabilities.",
    capabilities: [
      {
        id: "process.exec",
        version: "1.0.0",
        description: "Execute one policy-approved process and verify its terminal exit code.",
        requiredScope: "process:execute",
        risk: "high",
        readOnly: false,
        idempotent: false,
        execute: async (context, rawInput) => {
          const input = processExecInput.parse(rawInput);
          const selected = profileServices(dependencies, context.profile);
          const started = (await dependencies.processes.start(
            context.subject,
            context.profile,
            selected.profile,
            selected.filesystem.resolver,
            {
              executable: input.executable,
              args: input.args,
              cwd: input.cwd,
              ...(input.env === undefined ? {} : { env: input.env }),
              ...(input.timeoutMs === undefined ? {} : { timeoutMs: input.timeoutMs }),
            },
          )) as { sessionId?: string };
          const sessionId = started.sessionId;
          if (!sessionId)
            throw new AppError("INTERNAL_ERROR", "process session id was not returned");
          const deadline =
            Date.now() +
            Math.min(
              input.timeoutMs ?? dependencies.config.policy.maxProcessRuntimeMs,
              dependencies.config.policy.maxProcessRuntimeMs,
            ) +
            5_000;
          while (Date.now() <= deadline) {
            if (context.isCancelled()) {
              await dependencies.processes
                .terminate(sessionId, context.subject, false)
                .catch(() => undefined);
              throw new AppError("CONFLICT", "operator job was cancelled");
            }
            const snapshot = (await dependencies.processes.readOutput(
              sessionId,
              context.subject,
              undefined,
              1,
            )) as { status?: string; exitCode?: number | null };
            if (snapshot.status !== "running") {
              if (
                snapshot.status !== "complete" ||
                snapshot.exitCode === null ||
                snapshot.exitCode === undefined ||
                !input.successExitCodes.includes(snapshot.exitCode)
              ) {
                throw new AppError(
                  "CONFLICT",
                  `process verification failed with status ${String(snapshot.status)} and exit code ${String(snapshot.exitCode)}`,
                );
              }
              return {
                sessionId,
                status: snapshot.status,
                exitCode: snapshot.exitCode,
                verified: true,
              };
            }
            await delay(100);
          }
          await dependencies.processes
            .terminate(sessionId, context.subject, false)
            .catch(() => undefined);
          throw new AppError("CONFLICT", "process verification deadline exceeded");
        },
      },
    ],
  };

  return [device, filesystem, process];
}
