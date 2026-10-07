import { execFile as execFileCallback } from "node:child_process";
import { randomUUID } from "node:crypto";
import os from "node:os";
import { promisify } from "node:util";

import type { AuthInfo } from "@modelcontextprotocol/server";

import type { CapabilityRegistry } from "../../components/registry.js";
import type { V3CapabilityRuntime } from "../capability/runtime.js";
import type {
  FilesystemPort,
  LifecycleReadiness,
  PlatformAdapter,
  PlatformDeviceInfo,
  ProcessPort,
  SearchPort,
  SecretProtectorPort,
} from "../platform/contracts.js";
import { assertAgentHello, type AgentExecutionReceipt } from "./agent-protocol.js";
import {
  parseAgentIdentityClaim,
  parseDeviceDescriptor,
  type AgentIdentityClaim,
  type DeviceDescriptor,
} from "./identity.js";

const execFile = promisify(execFileCallback);

export type SecurityCommandRunner = (args: string[]) => Promise<string>;

async function runSecurityCommand(args: string[]): Promise<string> {
  const { stdout } = await execFile("security", args, {
    timeout: 10_000,
    maxBuffer: 1024 * 1024,
  });
  return stdout.trim();
}

export class MacOSKeychainSecretProtector implements SecretProtectorPort {
  constructor(
    private readonly service = "com.radlina.remote-mcp.v3",
    private readonly run: SecurityCommandRunner = runSecurityCommand,
    private readonly tokenFactory: () => string = () => randomUUID(),
  ) {}

  async protect(value: Uint8Array): Promise<Uint8Array> {
    const token = this.tokenFactory();
    if (!token.trim()) throw new Error("keychain token is required");
    await this.run([
      "add-generic-password",
      "-U",
      "-s",
      this.service,
      "-a",
      token,
      "-w",
      Buffer.from(value).toString("base64"),
    ]);
    return Buffer.from(`keychain:${token}`, "utf8");
  }

  async unprotect(reference: Uint8Array): Promise<Uint8Array> {
    const value = Buffer.from(reference).toString("utf8");
    if (!value.startsWith("keychain:")) throw new Error("invalid keychain secret reference");
    const token = value.slice("keychain:".length);
    if (!token.trim()) throw new Error("invalid keychain secret reference");
    const encoded = await this.run([
      "find-generic-password",
      "-s",
      this.service,
      "-a",
      token,
      "-w",
    ]);
    return Buffer.from(encoded.trim(), "base64");
  }

  async delete(reference: Uint8Array): Promise<void> {
    const value = Buffer.from(reference).toString("utf8");
    if (!value.startsWith("keychain:")) throw new Error("invalid keychain secret reference");
    const token = value.slice("keychain:".length);
    await this.run(["delete-generic-password", "-s", this.service, "-a", token]);
  }
}

export type MacOSAdapterBindings = {
  filesystem: FilesystemPort;
  process: ProcessPort;
  search: SearchPort;
  secrets?: SecretProtectorPort;
  agentVersion: string;
  readiness: () => Promise<LifecycleReadiness>;
  scheduleRestart: (reason: string) => Promise<void>;
  hostname?: () => string;
  architecture?: () => PlatformDeviceInfo["architecture"];
};

export type MacOSAgentEnrollment = {
  deviceId: string;
  tags: string[];
  trustState: DeviceDescriptor["trustState"];
  identity: AgentIdentityClaim;
};

export type MacOSAgentExecuteContext = {
  auth: AuthInfo | undefined;
  subject: string;
  profile: string;
  isCancelled: () => boolean;
};

export class MacOSDeviceAgent {
  constructor(
    readonly adapter: PlatformAdapter,
    private readonly capabilities: CapabilityRegistry,
    private readonly runtime: V3CapabilityRuntime,
    private readonly enrollment: MacOSAgentEnrollment,
  ) {
    if (adapter.platform !== "macos") {
      throw new Error("MacOSDeviceAgent requires macos adapter");
    }
    parseAgentIdentityClaim(enrollment.identity);
  }

  async descriptor(): Promise<DeviceDescriptor> {
    const info = await this.adapter.deviceInfo.getDeviceInfo();
    return parseDeviceDescriptor({
      deviceId: this.enrollment.deviceId,
      hostname: info.hostname,
      platform: "macos",
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
    context: MacOSAgentExecuteContext,
  ): Promise<{
    ok: boolean;
    receipt: AgentExecutionReceipt;
    result?: unknown;
    error?: { code: string; message: string };
  }> {
    const descriptor = await this.descriptor();
    return await this.runtime.execute(request, {
      auth: context.auth,
      subject: context.subject,
      profile: context.profile,
      device: descriptor,
      agentInstanceId: this.enrollment.identity.agentInstanceId,
      isCancelled: context.isCancelled,
    });
  }
}

export function createMacOSPlatformAdapter(bindings: MacOSAdapterBindings): PlatformAdapter {
  if (process.platform !== "darwin" && process.env["NODE_ENV"] !== "test") {
    throw new Error("macOS platform adapter can only run on macOS");
  }

  return {
    id: "macos-native",
    platform: "macos",
    secrets: bindings.secrets ?? new MacOSKeychainSecretProtector(),
    filesystem: bindings.filesystem,
    process: bindings.process,
    search: bindings.search,
    lifecycle: {
      readiness: bindings.readiness,
      scheduleRestart: bindings.scheduleRestart,
    },
    deviceInfo: {
      getDeviceInfo: async (): Promise<PlatformDeviceInfo> => {
        const readiness = await bindings.readiness();
        return {
          hostname: bindings.hostname?.() ?? os.hostname(),
          platform: "macos",
          architecture: bindings.architecture?.() ?? normalizeArchitecture(process.arch),
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
