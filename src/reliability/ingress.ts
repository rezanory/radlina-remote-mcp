import { execFile as execFileCallback } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";

import type { AppConfig } from "../config/schema.js";
import { resolveWindowsExecutable } from "../utils/windows-executable.js";

const execFile = promisify(execFileCallback);

type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

type TailscaleStatusProvider = () => Promise<unknown>;

export type EndpointTelemetry = {
  required: boolean;
  ready: boolean | null;
  lastAttemptAt: string | null;
  lastSuccessAt: string | null;
  lastFailureAt: string | null;
  latencyMs: number | null;
  consecutiveFailures: number;
  statusCode: number | null;
  detail: string;
};

export type TailscaleTelemetry = EndpointTelemetry & {
  backendState: string | null;
  selfOnline: boolean | null;
  relay: string | null;
  healthIssueCount: number | null;
};

export type IngressSnapshot = {
  enabled: boolean;
  localReady: boolean | null;
  publicReady: boolean | null;
  tailscaleReady: boolean | null;
  local: EndpointTelemetry;
  public: EndpointTelemetry;
  tailscale: TailscaleTelemetry;
};

export type IngressWatchdogDependencies = {
  fetch?: FetchLike;
  tailscaleStatus?: TailscaleStatusProvider;
};

function loopback(hostname: string): boolean {
  return ["127.0.0.1", "localhost", "::1", "[::1]"].includes(hostname.toLowerCase());
}

function initialEndpoint(required: boolean, detail: string): EndpointTelemetry {
  return {
    required,
    ready: null,
    lastAttemptAt: null,
    lastSuccessAt: null,
    lastFailureAt: null,
    latencyMs: null,
    consecutiveFailures: 0,
    statusCode: null,
    detail,
  };
}

function initialTailscale(required: boolean): TailscaleTelemetry {
  return {
    ...initialEndpoint(required, required ? "not probed yet" : "not required for this public URL"),
    backendState: null,
    selfOnline: null,
    relay: null,
    healthIssueCount: null,
  };
}

function boundedDetail(value: unknown): string {
  return (value instanceof Error ? value.message : String(value)).slice(0, 256);
}

function mcpUrl(base: string): URL {
  const url = new URL(base);
  const trimmed = url.pathname.replace(/\/+$/u, "");
  url.pathname = trimmed.endsWith("/mcp") ? trimmed : `${trimmed}/mcp`;
  url.search = "";
  url.hash = "";
  return url;
}

function localMcpUrl(config: AppConfig): URL {
  const rawHost = config.server.host;
  const host = rawHost.includes(":") && !rawHost.startsWith("[") ? `[${rawHost}]` : rawHost;
  return new URL(`http://${host}:${config.server.port}/mcp`);
}

export class IngressWatchdog {
  private enabled = false;
  private localState = initialEndpoint(
    true,
    "ingress checks are not enabled until HTTP bind completes",
  );
  private publicState: EndpointTelemetry;
  private tailscaleState: TailscaleTelemetry;
  private readonly publicRequired: boolean;
  private readonly tailscaleRequired: boolean;
  private readonly fetcher: FetchLike;
  private readonly tailscaleStatusProvider: TailscaleStatusProvider;

  constructor(
    private readonly config: AppConfig,
    dependencies: IngressWatchdogDependencies = {},
  ) {
    const publicUrl = new URL(config.server.publicUrl);
    this.publicRequired = !loopback(publicUrl.hostname);
    this.tailscaleRequired =
      this.publicRequired && publicUrl.hostname.toLowerCase().endsWith(".ts.net");
    this.publicState = initialEndpoint(
      this.publicRequired,
      this.publicRequired
        ? "not probed yet"
        : "loopback public URL does not require an external ingress probe",
    );
    this.tailscaleState = initialTailscale(this.tailscaleRequired);
    this.fetcher = dependencies.fetch ?? fetch;
    this.tailscaleStatusProvider =
      dependencies.tailscaleStatus ?? (() => this.readTailscaleStatus());
  }

  enable(): void {
    this.enabled = true;
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  snapshot(): IngressSnapshot {
    return {
      enabled: this.enabled,
      localReady: this.enabled ? this.localState.ready === true : null,
      publicReady: this.enabled
        ? this.publicRequired
          ? this.publicState.ready === true
          : true
        : null,
      tailscaleReady: this.enabled
        ? this.tailscaleRequired
          ? this.tailscaleState.ready === true
          : true
        : null,
      local: structuredClone(this.localState),
      public: structuredClone(this.publicState),
      tailscale: structuredClone(this.tailscaleState),
    };
  }

  async probe(): Promise<IngressSnapshot> {
    if (!this.enabled) return this.snapshot();
    await this.probeEndpoint("local", localMcpUrl(this.config));
    if (this.publicRequired)
      await this.probeEndpoint("public", mcpUrl(this.config.server.publicUrl));
    if (this.tailscaleRequired) await this.probeTailscale();
    return this.snapshot();
  }

  private async probeEndpoint(target: "local" | "public", url: URL): Promise<void> {
    const state = target === "local" ? this.localState : this.publicState;
    const attemptedAt = new Date().toISOString();
    const started = performance.now();
    const maxAttempts = target === "public" ? 3 : 1;
    let lastStatusCode: number | null = null;
    let lastDetail = "probe failed";

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        const response = await this.fetcher(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
          redirect: "manual",
          signal: AbortSignal.timeout(5_000),
        });
        lastStatusCode = response.status;

        if (response.status === 401) {
          state.ready = true;
          state.lastAttemptAt = attemptedAt;
          state.lastSuccessAt = attemptedAt;
          state.latencyMs = Math.max(0, Math.round(performance.now() - started));
          state.statusCode = response.status;
          state.detail =
            attempt === 1
              ? "auth boundary reachable (401)"
              : `auth boundary reachable (401) after ${attempt} attempts`;
          state.consecutiveFailures = 0;
          return;
        }

        lastDetail = `unexpected HTTP status ${response.status}`;
      } catch (error) {
        lastStatusCode = null;
        lastDetail = boundedDetail(error);
      }

      if (attempt < maxAttempts) {
        await new Promise<void>((resolve) => {
          setTimeout(resolve, 150);
        });
      }
    }

    state.ready = false;
    state.lastAttemptAt = attemptedAt;
    state.lastFailureAt = attemptedAt;
    state.latencyMs = Math.max(0, Math.round(performance.now() - started));
    state.statusCode = lastStatusCode;
    state.detail = maxAttempts === 1 ? lastDetail : `${lastDetail}; attempts=${maxAttempts}`;
    state.consecutiveFailures += 1;
  }

  private async probeTailscale(): Promise<void> {
    const attemptedAt = new Date().toISOString();
    const started = performance.now();
    try {
      const raw = (await this.tailscaleStatusProvider()) as {
        BackendState?: unknown;
        Health?: unknown;
        Self?: { Online?: unknown; Relay?: unknown };
      };
      const backendState = typeof raw.BackendState === "string" ? raw.BackendState : null;
      const selfOnline = typeof raw.Self?.Online === "boolean" ? raw.Self.Online : null;
      const relay = typeof raw.Self?.Relay === "string" ? raw.Self.Relay : null;
      const healthIssueCount = Array.isArray(raw.Health) ? raw.Health.length : null;
      const ready =
        backendState === "Running" && selfOnline === true && (healthIssueCount ?? 0) === 0;
      this.tailscaleState.ready = ready;
      this.tailscaleState.lastAttemptAt = attemptedAt;
      this.tailscaleState.latencyMs = Math.max(0, Math.round(performance.now() - started));
      this.tailscaleState.statusCode = null;
      this.tailscaleState.backendState = backendState;
      this.tailscaleState.selfOnline = selfOnline;
      this.tailscaleState.relay = relay;
      this.tailscaleState.healthIssueCount = healthIssueCount;
      this.tailscaleState.detail = `backend=${backendState ?? "unknown"};selfOnline=${String(selfOnline)};healthIssues=${String(healthIssueCount ?? "unknown")};relay=${relay ?? "unknown"}`;
      if (ready) {
        this.tailscaleState.lastSuccessAt = attemptedAt;
        this.tailscaleState.consecutiveFailures = 0;
      } else {
        this.tailscaleState.lastFailureAt = attemptedAt;
        this.tailscaleState.consecutiveFailures += 1;
      }
    } catch (error) {
      this.tailscaleState.ready = false;
      this.tailscaleState.lastAttemptAt = attemptedAt;
      this.tailscaleState.lastFailureAt = attemptedAt;
      this.tailscaleState.latencyMs = Math.max(0, Math.round(performance.now() - started));
      this.tailscaleState.detail = boundedDetail(error);
      this.tailscaleState.consecutiveFailures += 1;
    }
  }

  private async readTailscaleStatus(): Promise<unknown> {
    const programFiles = process.env["ProgramFiles"] ?? "C:\\Program Files";
    const knownPath = path.win32.join(programFiles, "Tailscale", "tailscale.exe");
    const executable =
      (await resolveWindowsExecutable(knownPath)) ??
      (await resolveWindowsExecutable("tailscale.exe"));
    if (!executable) throw new Error("tailscale executable was not found");
    const { stdout } = await execFile(executable, ["status", "--json"], {
      windowsHide: true,
      timeout: 5_000,
      maxBuffer: 1024 * 1024,
    });
    return JSON.parse(stdout) as unknown;
  }
}
