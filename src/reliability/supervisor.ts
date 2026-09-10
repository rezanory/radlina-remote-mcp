import { randomUUID } from "node:crypto";
import { stat } from "node:fs/promises";

import type { AuditChain } from "../audit/chain.js";
import type { AuthService } from "../auth/service.js";
import type { AppConfig } from "../config/schema.js";
import type { Store } from "../persistence/store.js";
import type { ProcessManager } from "../tools/process/manager.js";
import type { SearchManager } from "../tools/search/manager.js";

type ReliabilityStatus = "healthy" | "degraded" | "unhealthy";
type CheckName = "storage" | "auth" | "ripgrep" | "audit" | "sessions" | "supervisor";

type CheckResult = {
  ok: boolean;
  detail: string;
  checkedAt: string;
  durationMs: number;
};

export type ReliabilitySnapshot = {
  status: ReliabilityStatus;
  ready: boolean;
  lastProbeAt: string | null;
  lastProbeReason: string | null;
  consecutiveFailures: number;
  recoveryCount: number;
  lastRecoveryAt: string | null;
  checks: Partial<Record<CheckName, CheckResult>>;
};

type ReliabilityEventRow = {
  event_id: string;
  created_at: number;
  kind: string;
  status: string;
  details_json: string;
};

export class ReliabilitySupervisor {
  private timer: NodeJS.Timeout | undefined;
  private inFlight: Promise<ReliabilitySnapshot> | undefined;
  private consecutiveFailures = 0;
  private recoveryCount = 0;
  private lastRecoveryAt: string | null = null;
  private lastAuditCheckAt = 0;
  private cachedAuditCheck: CheckResult | undefined;
  private snapshotValue: ReliabilitySnapshot = {
    status: "unhealthy",
    ready: false,
    lastProbeAt: null,
    lastProbeReason: null,
    consecutiveFailures: 0,
    recoveryCount: 0,
    lastRecoveryAt: null,
    checks: {},
  };

  constructor(
    private readonly config: AppConfig,
    private readonly store: Store,
    private readonly audit: AuditChain,
    private readonly auth: AuthService,
    private readonly searches: SearchManager,
    private readonly processes: ProcessManager,
  ) {}

  async start(recoverOnStartup = true): Promise<void> {
    await this.probe("startup", recoverOnStartup);
    if (!this.config.reliability.enabled) return;
    this.timer = setInterval(() => {
      void this.probe("interval").catch(() => undefined);
    }, this.config.reliability.probeIntervalMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  snapshot(): ReliabilitySnapshot {
    return structuredClone(this.snapshotValue);
  }

  recentEvents(limit = 50): unknown[] {
    const bounded = Math.min(Math.max(Math.trunc(limit), 1), 200);
    const rows = this.store.db
      .prepare(
        "SELECT event_id,created_at,kind,status,details_json FROM reliability_events ORDER BY created_at DESC,event_id DESC LIMIT ?",
      )
      .all(bounded) as ReliabilityEventRow[];
    return rows.map((row) => ({
      eventId: row.event_id,
      createdAt: new Date(row.created_at).toISOString(),
      kind: row.kind,
      status: row.status,
      details: JSON.parse(row.details_json) as unknown,
    }));
  }

  probe(reason = "manual", recover = true): Promise<ReliabilitySnapshot> {
    if (this.inFlight) return this.inFlight;
    const probe = this.runProbe(reason, recover).catch((error: unknown) =>
      this.failProbe(reason, error),
    );
    this.inFlight = probe;
    const release = () => {
      if (this.inFlight === probe) this.inFlight = undefined;
    };
    void probe.then(release, release);
    return probe;
  }

  private failProbe(reason: string, error: unknown): ReliabilitySnapshot {
    this.consecutiveFailures += 1;
    const now = new Date().toISOString();
    const detail = (error instanceof Error ? error.message : "unknown supervisor failure").slice(
      0,
      256,
    );
    this.snapshotValue = {
      status: "unhealthy",
      ready: false,
      lastProbeAt: now,
      lastProbeReason: reason.slice(0, 64),
      consecutiveFailures: this.consecutiveFailures,
      recoveryCount: this.recoveryCount,
      lastRecoveryAt: this.lastRecoveryAt,
      checks: {
        supervisor: { ok: false, detail, checkedAt: now, durationMs: 0 },
      },
    };
    this.recordEvent("supervisor-failure", "unhealthy", {
      reason: reason.slice(0, 64),
      detail,
      consecutiveFailures: this.consecutiveFailures,
    });
    return this.snapshot();
  }

  private async runProbe(reason: string, recover: boolean): Promise<ReliabilitySnapshot> {
    const previousStatus = this.snapshotValue.status;
    const checks: Partial<Record<CheckName, CheckResult>> = {};
    const recovery = recover
      ? await this.reconcileRecoverableState()
      : { total: 0, oauthExpired: 0, interruptedProcesses: 0, interruptedSearches: 0 };

    checks.storage = await this.check(async () => {
      const row = this.store.db.prepare("SELECT 1 AS ok").get() as { ok?: number } | undefined;
      if (row?.ok !== 1) throw new Error("SQLite probe failed");
      return "sqlite=ok";
    });

    checks.auth = await this.check(async () => {
      const health = this.auth.health();
      if (health.status !== "healthy" || !health.signingReady || !health.tokenEndpointReady) {
        throw new Error(
          `auth=${health.status};signing=${String(health.signingReady)};token=${String(health.tokenEndpointReady)}`,
        );
      }
      return `auth=${health.status};mode=${health.mode}`;
    });

    checks.ripgrep = await this.check(async () => {
      const info = await stat(this.config.dependencies.ripgrepExecutable);
      if (!info.isFile()) throw new Error("ripgrep dependency is not a regular file");
      return "ripgrep=ok";
    });

    checks.audit = await this.auditCheck();

    checks.sessions = await this.check(async () => {
      const processRow = this.store.db
        .prepare("SELECT COUNT(*) AS count FROM process_sessions WHERE status='running'")
        .get() as { count: number };
      const searchRow = this.store.db
        .prepare("SELECT COUNT(*) AS count FROM search_sessions WHERE status='running'")
        .get() as { count: number };
      if (
        processRow.count > this.config.policy.maxSessions ||
        searchRow.count > this.config.policy.maxSessions
      ) {
        throw new Error("active session count exceeds configured maximum");
      }
      return `processes=${processRow.count};searches=${searchRow.count}`;
    });

    const allHealthy = Object.values(checks).every((check) => check?.ok === true);
    if (allHealthy) this.consecutiveFailures = 0;
    else this.consecutiveFailures += 1;

    const status: ReliabilityStatus = allHealthy
      ? "healthy"
      : this.consecutiveFailures >= this.config.reliability.failureThreshold
        ? "unhealthy"
        : "degraded";
    const now = new Date().toISOString();
    this.snapshotValue = {
      status,
      ready: allHealthy,
      lastProbeAt: now,
      lastProbeReason: reason.slice(0, 64),
      consecutiveFailures: this.consecutiveFailures,
      recoveryCount: this.recoveryCount,
      lastRecoveryAt: this.lastRecoveryAt,
      checks,
    };

    if (!allHealthy || previousStatus !== status) {
      this.recordEvent("health-transition", status, {
        previousStatus,
        reason: reason.slice(0, 64),
        consecutiveFailures: this.consecutiveFailures,
        failedChecks: Object.entries(checks)
          .filter(([, value]) => value?.ok === false)
          .map(([name]) => name),
      });
    }
    if (recovery.total > 0) {
      this.recordEvent("recovery", "applied", recovery);
    }
    return this.snapshot();
  }

  private async reconcileRecoverableState(): Promise<{
    total: number;
    oauthExpired: number;
    interruptedProcesses: number;
    interruptedSearches: number;
  }> {
    const oauth = this.auth.reconcileExpiredState();
    const processRecovery = await this.processes.reconcile();
    const searchRecovery = this.searches.reconcileStale();
    const oauthExpired = oauth.approvals + oauth.codes + oauth.refreshTokens;
    const total = oauthExpired + processRecovery.interrupted + searchRecovery.interrupted;
    if (total > 0) {
      this.recoveryCount += total;
      this.lastRecoveryAt = new Date().toISOString();
    }
    return {
      total,
      oauthExpired,
      interruptedProcesses: processRecovery.interrupted,
      interruptedSearches: searchRecovery.interrupted,
    };
  }

  private async auditCheck(): Promise<CheckResult> {
    const now = Date.now();
    if (
      this.cachedAuditCheck &&
      now - this.lastAuditCheckAt < this.config.reliability.auditVerifyIntervalMs
    ) {
      return this.cachedAuditCheck;
    }
    const result = await this.check(async () => {
      const verification = await this.audit.verify(await this.audit.files());
      if (!verification.valid) {
        throw new Error(
          `audit chain invalid at sequence ${String(verification.firstInvalidSequence ?? "unknown")}`,
        );
      }
      return `audit=ok;records=${verification.records}`;
    });
    this.cachedAuditCheck = result;
    this.lastAuditCheckAt = now;
    return result;
  }

  private async check(action: () => Promise<string>): Promise<CheckResult> {
    const started = performance.now();
    const checkedAt = new Date().toISOString();
    try {
      const detail = await action();
      return {
        ok: true,
        detail: detail.slice(0, 256),
        checkedAt,
        durationMs: Math.max(0, Math.round(performance.now() - started)),
      };
    } catch (error) {
      return {
        ok: false,
        detail: (error instanceof Error ? error.message : "unknown reliability failure").slice(
          0,
          256,
        ),
        checkedAt,
        durationMs: Math.max(0, Math.round(performance.now() - started)),
      };
    }
  }

  private recordEvent(kind: string, status: string, details: unknown): void {
    try {
      this.store.db.exec("BEGIN IMMEDIATE");
      this.store.db
        .prepare(
          "INSERT INTO reliability_events(event_id,created_at,kind,status,details_json) VALUES(?,?,?,?,?)",
        )
        .run(
          randomUUID(),
          Date.now(),
          kind.slice(0, 64),
          status.slice(0, 64),
          JSON.stringify(details),
        );
      this.store.db
        .prepare(
          "DELETE FROM reliability_events WHERE event_id NOT IN (SELECT event_id FROM reliability_events ORDER BY created_at DESC,event_id DESC LIMIT ?)",
        )
        .run(this.config.reliability.eventRetention);
      this.store.db.exec("COMMIT");
    } catch {
      try {
        this.store.db.exec("ROLLBACK");
      } catch {
        // Reliability telemetry is best-effort and must not destabilize the service.
      }
    }
  }
}
