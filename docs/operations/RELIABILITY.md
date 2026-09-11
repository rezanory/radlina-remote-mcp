# Reliability and Self-Healing (0.3)

Radlina 0.3 introduces an in-process reliability supervisor. The supervisor is deliberately fail-closed: user-facing health and readiness are derived from real component probes instead of unconditional `healthy` / `ready` constants.

## Current supervisor checks

- SQLite storage query succeeds.
- OAuth signing material and token endpoint are ready.
- The configured ripgrep dependency exists as a regular file.
- The tamper-evident audit chain verifies on startup and at the configured bounded interval.
- Running process/search session counts remain within policy limits.
- After HTTP bind, the loopback MCP authentication boundary is reachable and returns the expected unauthenticated `401`.
- When `server.publicUrl` is non-loopback, the public MCP URL is probed independently; `LOCAL_READY` and `PUBLIC_READY` are never conflated.
- For `*.ts.net` public URLs, Tailscale `BackendState`, `Self.Online`, relay, and health issue count are sampled without persisting node keys or other credential material.

## Safe automatic reconciliation

Each scheduled probe may perform only low-risk, deterministic state repair:

- delete already-expired OAuth approvals, authorization codes, and refresh-token replay receipts;
- mark process sessions `interrupted` when their PID identity no longer matches;
- mark search sessions `interrupted` only when the current server no longer owns a live child for that session.

The supervisor does **not** restart the Windows service, change configuration, activate/rollback releases, modify credentials, or run arbitrary recovery shell commands. Those actions remain explicit operational steps until a later 0.3 component adds reviewed guardrails.

## Health states

- `healthy`: every current probe passed; readiness may be true subject to the kill switch.
- `degraded`: at least one probe failed, but the configured consecutive-failure threshold has not been reached.
- `unhealthy`: the configured consecutive-failure threshold has been reached.

Any failed current probe sets supervisor `ready=false`. The MCP `readiness` result also becomes false when the kill switch is enabled.

## Telemetry

`reliability_status` returns the latest supervisor snapshot, including `localReady`, `publicReady`, `tailscaleReady`, last public success/failure timestamps, probe latency, consecutive failures, and sanitized Tailscale state.

`health`, `readiness`, CLI diagnostics, and service status expose the same split readiness model so a healthy loopback process cannot mask a broken public path.

`recent_reliability_events` returns bounded persistent transition/recovery events and requires `admin` scope.

Reliability event persistence is best-effort. Failure to write telemetry must not crash the service or weaken policy enforcement.

## Configuration

```yaml
reliability:
  enabled: true
  probeIntervalMs: 30000
  failureThreshold: 3
  auditVerifyIntervalMs: 300000
  eventRetention: 2000
```

The probe timer is unreferenced and is stopped by `closeRuntime` in tests and controlled shutdowns.

## Planned 0.3 follow-up gates

1. Windows-service/Tailscale automatic restart policy with an explicit restart budget, cooldown, and operator-visible escalation; the current watchdog is observation/fail-closed only.
2. Restart/rebind chaos tests and sustained Tailscale interruption drills.
3. SLO windows, availability counters, and production soak evidence.
4. Recovery escalation policy that distinguishes safe automatic action from operator approval.
