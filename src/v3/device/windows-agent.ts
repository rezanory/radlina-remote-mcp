import os from "node:os";

import type { AuthInfo } from "@modelcontextprotocol/server";

import { protectBytes, unprotectBytes } from "../../auth/dpapi.js";
import type { CapabilityRegistry } from "../../components/registry.js";
import type { WorkspaceProfile } from "../../config/schema.js";
import type { FilesystemService } from "../../tools/filesystem/service.js";
import type { ProcessManager } from "../../tools/process/manager.js";
import type { SearchManager } from "../../tools/search/manager.js";
import type {
  LifecycleReadiness,
  PlatformAdapter,
  PlatformDeviceInfo,
  PlatformFileInfo,
  ProcessSnapshot,
  SearchSnapshot,
} from "../platform/contracts.js";
import type { V3CapabilityRuntime } from "../capability/runtime.js";
import { assertAgentHello, type AgentExecutionReceipt } from "./agent-protocol.js";
import {
  parseAgentIdentityClaim,
  parseDeviceDescriptor,
  type AgentIdentityClaim,
  type DeviceDescriptor,
} from "./identity.js";

export type WindowsAdapterBindings = {
  subject: string;
  profileName: string;
  profile: WorkspaceProfile;
  filesystem: FilesystemService;
  processes: ProcessManager;
  searches: SearchManager;
  agentVersion: string;
  readiness: () => Promise<LifecycleReadiness>;
  scheduleRestart: (reason: string) => Promise<void>;
};

export type WindowsAgentEnrollment = {
  deviceId: string;
  tags: string[];
  trustState: DeviceDescriptor["trustState"];
  identity: AgentIdentityClaim;
};

export type WindowsAgentExecuteContext = {
  auth: AuthInfo | undefined;
  subject: string;
  profile: string;
  isCancelled: () => boolean;
};

export class WindowsDeviceAgent {
  constructor(
    readonly adapter: PlatformAdapter,
    private readonly capabilities: CapabilityRegistry,
    private readonly runtime: V3CapabilityRuntime,
    private readonly enrollment: WindowsAgentEnrollment,
  ) {
    if (adapter.platform !== "windows")
      throw new Error("WindowsDeviceAgent requires windows adapter");
    parseAgentIdentityClaim(enrollment.identity);
  }

  async descriptor(): Promise<DeviceDescriptor> {
    const info = await this.adapter.deviceInfo.getDeviceInfo();
    return parseDeviceDescriptor({
      deviceId: this.enrollment.deviceId,
      hostname: info.hostname,
      platform: "windows",
      architecture: info.architecture,
      agentVersion: info.agentVersion,
      status: info.health === "healthy" ? "online" : "degraded",
      lastSeen: new Date().toISOString(),
      capabilities: this.capabilities.listCapabilities().map((capability) => capability.id),
      tags: this.enrollment.tags,
      trustState: this.enrollment.trustState,
      health: info.health,
    });
  }

  async hello() {
    const descriptor = await this.descriptor();
    return assertAgentHello({
      protocolVersion: "1.0.0",
      descriptor,
      identity: this.enrollment.identity,
    });
  }

  async execute(
    request: unknown,
    context: WindowsAgentExecuteContext,
  ): Promise<{
    ok: boolean;
    receipt: AgentExecutionReceipt;
    result?: unknown;
    error?: { code: string; message: string };
  }> {
    const descriptor = await this.descriptor();
    const outcome = await this.runtime.execute(request, {
      auth: context.auth,
      subject: context.subject,
      profile: context.profile,
      device: descriptor,
      agentInstanceId: this.enrollment.identity.agentInstanceId,
      isCancelled: context.isCancelled,
    });
    return outcome;
  }
}

export function createWindowsPlatformAdapter(bindings: WindowsAdapterBindings): PlatformAdapter {
  if (process.platform !== "win32" && process.env["NODE_ENV"] !== "test") {
    throw new Error("Windows platform adapter can only run on Windows");
  }

  return {
    id: "windows-native",
    platform: "windows",
    secrets: {
      protect: async (value) => Buffer.from(await protectBytes(value), "utf8"),
      unprotect: async (value) => await unprotectBytes(Buffer.from(value).toString("utf8")),
    },
    filesystem: {
      getFileInfo: async (inputPath): Promise<PlatformFileInfo> => {
        const result = (await bindings.filesystem.getFileInfo(inputPath)) as {
          path: string;
          type: PlatformFileInfo["kind"];
          size: number;
          modifiedAt: string;
        };
        return {
          path: result.path,
          kind: result.type,
          size: result.size,
          modifiedAt: result.modifiedAt,
        };
      },
      readFile: async (inputPath, offset, length) => {
        const result = (await bindings.filesystem.readFile(inputPath, offset, length)) as {
          content: string;
          encoding: "utf8" | "utf16le" | "base64";
        };
        if (result.encoding === "base64") return Buffer.from(result.content, "base64");
        if (result.encoding === "utf16le") return Buffer.from(result.content, "utf16le");
        return Buffer.from(result.content, "utf8");
      },
      writeFile: async (inputPath, value, overwrite) => {
        await bindings.filesystem.writeFile(
          inputPath,
          Buffer.from(value).toString("base64"),
          "base64",
          overwrite,
        );
      },
      listDirectory: async (inputPath) => {
        const result = (await bindings.filesystem.listDirectory(inputPath)) as {
          entries: Array<{ name: string }>;
        };
        return result.entries.map((entry) => entry.name);
      },
    },
    process: {
      start: async (request) => {
        const result = (await bindings.processes.start(
          bindings.subject,
          bindings.profileName,
          bindings.profile,
          bindings.filesystem.resolver,
          request,
        )) as { sessionId: string; pid?: number | null };
        return { sessionId: result.sessionId, pid: result.pid ?? null };
      },
      read: async (sessionId, cursor) => {
        const result = (await bindings.processes.readOutput(
          sessionId,
          bindings.subject,
          cursor,
          64 * 1024,
        )) as {
          status: string;
          exitCode: number | null;
          nextCursor?: string;
        };
        return {
          sessionId,
          status: normalizeProcessStatus(result.status),
          exitCode: result.exitCode,
          ...(result.nextCursor === undefined ? {} : { outputCursor: result.nextCursor }),
        } satisfies ProcessSnapshot;
      },
      interact: async (sessionId, input) => {
        bindings.processes.interact(sessionId, bindings.subject, input);
      },
      terminate: async (sessionId, force) => {
        await bindings.processes.terminate(sessionId, bindings.subject, force);
      },
    },
    search: {
      start: async (request) => {
        const result = (await bindings.searches.start(
          bindings.subject,
          bindings.profileName,
          bindings.filesystem.resolver,
          {
            path: request.root,
            pattern: request.pattern,
            mode: request.mode,
            caseSensitive: request.caseSensitive,
            literal: request.literal,
            maxResults: request.maxResults,
          },
        )) as { searchId: string };
        return { searchId: result.searchId };
      },
      status: async (searchId) => {
        const result = bindings.searches.status(searchId, bindings.subject) as {
          status: string;
          resultCount: number;
        };
        return {
          searchId,
          status: normalizeSearchStatus(result.status),
          resultCount: result.resultCount,
        } satisfies SearchSnapshot;
      },
      results: async (searchId, cursor) => {
        const result = (await bindings.searches.results(
          searchId,
          bindings.subject,
          cursor,
          500,
        )) as { results: unknown[] };
        return result.results;
      },
      cancel: async (searchId) => {
        bindings.searches.cancel(searchId, bindings.subject);
      },
    },
    lifecycle: {
      readiness: bindings.readiness,
      scheduleRestart: bindings.scheduleRestart,
    },
    deviceInfo: {
      getDeviceInfo: async (): Promise<PlatformDeviceInfo> => {
        const readiness = await bindings.readiness();
        return {
          hostname: os.hostname(),
          platform: "windows",
          architecture: normalizeArchitecture(process.arch),
          agentVersion: bindings.agentVersion,
          health: readiness.ready ? "healthy" : "degraded",
        };
      },
    },
  };
}

function normalizeArchitecture(value: string): PlatformDeviceInfo["architecture"] {
  if (value === "x64" || value === "arm64") return value;
  return "unknown";
}

function normalizeProcessStatus(value: string): ProcessSnapshot["status"] {
  if (value === "running") return "running";
  if (value === "complete") return "complete";
  if (value === "terminated") return "terminated";
  return "failed";
}

function normalizeSearchStatus(value: string): SearchSnapshot["status"] {
  if (value === "running") return "running";
  if (value === "complete") return "complete";
  if (value === "cancelled" || value === "cancelling") return "cancelled";
  if (value === "queued") return "queued";
  return "failed";
}
