# Radlina v0.3 M01 — Reliability Supervisor Acceptance

Generated: 2026-09-10T23:20Z

## Source identity

- Baseline production SHA: `75a13f06d66c0979260b574c546119f4dc8e80b7`
- Implementation branch: `feat/v0.3-reliability-self-healing-v1`
- Implementation SHA under acceptance: `f2fa42a26fa8e15873c2b67a3ba8011c8bc6f011`
- Implementation Git tree: `226a0be8c75d185bb3511d389df36c7bf0eafb35`
- Development version: `0.3.0-dev.1`
- Production activation: **NOT PERFORMED**

## Stable production archive

The production baseline was archived before v0.3 development at:

`C:\radlina-remote-mcp-archives\production-0.2.2-75a13f06-20260911T0045CEST`

Archive identity:

- production source SHA: `75a13f06d66c0979260b574c546119f4dc8e80b7`
- active production release manifest: `50ab342bd660eb32ba370af2f28cb429158eac018657df886249a61c4a242e13`
- source ZIP SHA-256: `9255C04305C1C646C385644866D008A44D0BEBC16AC753AB9CD8E3911AB96D39`
- Git bundle SHA-256: `3A0B21BF85E707998D75C099019C23DA5B6512B561B1FD30B920559BC60BC2C1`
- Git bundle verification: PASS, complete history

The previously dirty root working tree was preserved rather than discarded in stash:
`radlina-pre-archive-clean-20260911-0043`.

## M01 scope

M01 converts health/readiness from unconditional constants into real fail-closed runtime state and adds bounded self-healing for already-recoverable local state.

Implemented:

- periodic in-process reliability supervisor;
- health states: `healthy`, `degraded`, `unhealthy`;
- readiness derived from real component probes plus kill-switch state;
- SQLite storage probe;
- OAuth signing/token-endpoint probe;
- ripgrep dependency probe;
- bounded audit-chain verification probe;
- active process/search session-limit probe;
- safe cleanup of expired OAuth approvals/codes/refresh replay state;
- safe reconciliation of orphaned process sessions;
- safe reconciliation of stale search sessions;
- persistent bounded reliability transition/recovery telemetry;
- MCP tools `reliability_status` and `recent_reliability_events`;
- `self-healing`, `reliabilitySupervisor`, and `healthHistory` capability advertisement;
- dynamic auth-health status;
- shutdown-race hardening so process/search callbacks do not write to a closed Store;
- Windows SafePath test corrected to compare canonical paths case-insensitively without weakening containment enforcement;
- version metadata aligned to `0.3.0-dev.1` for the development line.

The supervisor intentionally does **not** restart the Windows service, change credentials/configuration, or activate/rollback releases. Those higher-impact remediations remain explicit until reviewed restart-budget/circuit-breaker controls are implemented.

## Acceptance evidence

Canonical implementation receipt:
`evidence/V03-M01/IMPLEMENTATION_VALIDATION_RECEIPT.json`

Receipt SHA-256 before copy:
`e02d70914bf010b4f4296f770428be2c48d8b975c489ad41a02b589b62ad0d23`

All closure gates passed on the exact implementation SHA and tree, with the worktree clean and source identity unchanged:

- clean-install: PASS
- format: PASS
- lint: PASS
- typecheck: PASS
- unit: PASS
- integration: PASS
- security: PASS
- resilience: PASS
- full: PASS
- build: PASS
- dependency-audit: PASS
- release-builder syntax: PASS
- upgrade-drill syntax: PASS
- release-verifier syntax: PASS
- secret-scan: PASS
- git-diff-check: PASS

Additional observed acceptance results before the canonical closure run:

- final full Vitest run: **14 test files, 66 tests, 66 passed, 0 failed**;
- targeted SafePath + process lifecycle + self-healing run: **12/12 passed** before the final supervisor test was added;
- self-healing suite after final hardening: **3/3 passed** within the full run;
- dependency audit: **0 vulnerabilities**;
- secret scan: PASS;
- production service remained `healthy`, `ready=true`, OAuth signing ready, token endpoint ready, and active version `0.2.2` throughout development checks.

## Failures found and fixed-forward

1. Windows canonical-path casing caused an existing SafePath test to compare `C:\WINDOWS\TEMP` with `C:\Windows\Temp`. Security containment was already case-insensitive; the test was corrected to assert equivalent canonical Windows paths without weakening policy.
2. Under parallel full-suite load, trusted-owner executable parity could exceed an artificial 2.5-second polling window. The bounded polling window was raised to 10 seconds while retaining the test-level timeout.
3. The same timeout exposed a real process-finalization shutdown race: an output-stream completion callback could attempt a SQLite write after Store close. Store lifecycle state plus process/search callback guards now fail safely; a dedicated regression test covers the race.
4. A supervisor-internal persistence failure could reject the probe promise. The supervisor now catches its own probe failure, records best-effort telemetry when possible, and returns `unhealthy / ready=false` instead of surfacing an unhandled rejection.

## Remaining v0.3 roadmap

M01 is not the complete v0.3 release. Next reviewed components are:

1. external transport reachability history and bounded circuit-breaker state;
2. Windows-service watchdog with restart budget, cooldown, and anti-loop protection;
3. restart/rebind chaos tests plus Tailscale interruption drills;
4. SLO/availability windows and production soak evidence;
5. recovery escalation policy separating safe automatic actions from operator-approved actions.

## Remote status at this checkpoint

A GitHub push was attempted after the implementation commit, but the workstation Git Credential Manager entered credential retrieval without a usable noninteractive credential. `gh auth status` reported no logged-in GitHub host, and a prompt-disabled `ls-remote` confirmed that the private repository requires authentication. No credential changes were made automatically. Local implementation and validation evidence remain complete and recoverable.
