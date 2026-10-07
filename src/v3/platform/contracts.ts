export const PLATFORM_CONTRACT_VERSION = "1.0.0" as const;

export type PlatformKind = "windows" | "macos";
export type CpuArchitecture = "x64" | "arm64" | "unknown";
export type DeviceHealth = "healthy" | "degraded" | "unhealthy" | "unknown";

export type PlatformDeviceInfo = {
  hostname: string;
  platform: PlatformKind;
  architecture: CpuArchitecture;
  agentVersion: string;
  health: DeviceHealth;
};

export interface SecretProtectorPort {
  protect(value: Uint8Array): Promise<Uint8Array>;
  unprotect(value: Uint8Array): Promise<Uint8Array>;
}

export type ProcessStartRequest = {
  executable: string;
  args: string[];
  cwd: string;
  env?: Record<string, string>;
  timeoutMs?: number;
};

export type ProcessHandle = {
  sessionId: string;
  pid: number | null;
};

export type ProcessSnapshot = {
  sessionId: string;
  status: "running" | "complete" | "failed" | "terminated";
  exitCode: number | null;
  outputCursor?: string;
};

export interface ProcessPort {
  start(request: ProcessStartRequest): Promise<ProcessHandle>;
  read(sessionId: string, cursor?: string): Promise<ProcessSnapshot>;
  interact(sessionId: string, input: string): Promise<void>;
  terminate(sessionId: string, force: boolean): Promise<void>;
}

export type PlatformFileKind = "file" | "directory" | "symlink" | "other";

export type PlatformFileInfo = {
  path: string;
  kind: PlatformFileKind;
  size: number | null;
  modifiedAt: string | null;
};

export interface FilesystemPort {
  getFileInfo(path: string): Promise<PlatformFileInfo>;
  readFile(path: string, offset: number, length: number): Promise<Uint8Array>;
  writeFile(path: string, value: Uint8Array, overwrite: boolean): Promise<void>;
  listDirectory(path: string): Promise<string[]>;
}

export type SearchRequest = {
  root: string;
  pattern: string;
  mode: "content" | "files";
  caseSensitive: boolean;
  literal: boolean;
  maxResults: number;
};

export type SearchHandle = {
  searchId: string;
};

export type SearchSnapshot = {
  searchId: string;
  status: "queued" | "running" | "complete" | "failed" | "cancelled";
  resultCount: number;
};

export interface SearchPort {
  start(request: SearchRequest): Promise<SearchHandle>;
  status(searchId: string): Promise<SearchSnapshot>;
  results(searchId: string, cursor?: string): Promise<unknown[]>;
  cancel(searchId: string): Promise<void>;
}

export type LifecycleReadiness = {
  ready: boolean;
  detail?: string;
};

export interface ServiceLifecyclePort {
  readiness(): Promise<LifecycleReadiness>;
  scheduleRestart(reason: string): Promise<void>;
}

export interface DeviceInfoPort {
  getDeviceInfo(): Promise<PlatformDeviceInfo>;
}

export type PlatformAdapter = {
  id: string;
  platform: PlatformKind;
  secrets: SecretProtectorPort;
  process: ProcessPort;
  filesystem: FilesystemPort;
  search: SearchPort;
  lifecycle: ServiceLifecyclePort;
  deviceInfo: DeviceInfoPort;
};

export const REQUIRED_PLATFORM_PORTS = [
  "secrets",
  "process",
  "filesystem",
  "search",
  "lifecycle",
  "deviceInfo",
] as const satisfies readonly (keyof PlatformAdapter)[];

export async function assertPlatformAdapterConformance(
  adapter: PlatformAdapter,
): Promise<PlatformDeviceInfo> {
  if (!adapter.id.trim()) throw new Error("platform adapter id is required");

  for (const port of REQUIRED_PLATFORM_PORTS) {
    if (adapter[port] === undefined || adapter[port] === null) {
      throw new Error(`platform adapter is missing required port: ${port}`);
    }
  }

  const info = await adapter.deviceInfo.getDeviceInfo();
  if (!info.hostname.trim()) throw new Error("device hostname is required");
  if (!info.agentVersion.trim()) throw new Error("agent version is required");
  if (info.platform !== adapter.platform) {
    throw new Error(
      `platform adapter mismatch: adapter=${adapter.platform} device=${info.platform}`,
    );
  }
  return info;
}
