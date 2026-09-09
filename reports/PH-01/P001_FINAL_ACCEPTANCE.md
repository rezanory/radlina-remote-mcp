# P001 final acceptance status

Generated: 2026-09-09 (Europe/Istanbul)

## Verdict

**Local release candidate: PASS. Overall deployment: `BLOCKED_FANIN_OR_ACCEPTANCE_INCOMPLETE`.**

The source, protocol, security, packaging, audit, recovery, and local performance gates are green. Overall acceptance is not PASS because the Windows service, firewall rule, Tailscale HTTPS ingress, live ChatGPT OAuth flow, crash restart, and sleep/resume checks have not yet been executed on the deployed system.

Unblock condition: install the service under the low-privilege `Radlina` identity, verify restart/recovery, enable the selected Tailscale mode, confirm HTTPS/auth denial externally, connect ChatGPT, and append those exact results to a successor evidence record.

## Exact source identity

- Source commit: `91dd2f21908b51cb5b4b99c7c451b166dbd7a7a0`
- Source tree: `ca1578d91c318f40799c05792ffd1486871479e7`
- Initial worktree state recorded by the validation runner: clean
- MCP baseline: `2026-07-28`
- MCP SDK packages: `2.0.0`
- Node runtime: `24.20.0` portable LTS

Exact gate commands, UTC timestamps, durations, exit codes, sanitized output paths, output hashes, and artifact hashes are in `evidence/PH-01/P001/validation-summary.json`.

## Scope and architecture

The server is a TypeScript/Node application built directly on the official MCP v2 SDK. It provides a sessionless Streamable HTTP `/mcp` endpoint, internal OAuth with DCR/PKCE/local approval or external OIDC/JWKS verification, default-deny workspace policy, safe filesystem/search/process services, SQLite durable state, DPAPI key protection, tamper-evident redacted audit records, WinSW service packaging, and Tailscale Serve/Funnel orchestration.

The implementation registers 33 tools across device, filesystem, search, process, configuration, policy simulation, diagnostics, sessions, and readiness. `docs/CAPABILITY-MATRIX.md` records every tool, scope, mutation rule, and server-side control.

## Effective non-secret defaults

- Bind: `127.0.0.1:7337`
- Local MCP URL: `http://127.0.0.1:7337/mcp`
- Default workspace root: `C:\radlina-remote-mcp`
- Command allowlist: empty
- Shell execution: disabled
- Trash/quarantine: disabled
- Request body: 1 MiB; file: 10 MiB; output: 1 MiB
- Request timeout: 30 s; process timeout: 15 min; search timeout: 2 min
- Concurrency: 8; rate: 60 requests/minute; durable sessions: 12
- OAuth access token: 10 min; refresh token: 24 h

## Security and resilience controls

- Exact issuer, audience, signature, expiry, client, resource, and scope verification.
- Dynamic registration redirect allowlist; HTTPS for non-loopback redirects; PKCE S256; one-time codes; refresh rotation; revocation.
- Host and Origin validation, secure headers, request-size/time/concurrency/rate bounds, sanitized failures.
- Canonical path containment with traversal, UNC/device path, ADS, reserved-name, symlink, and junction defenses.
- Atomic file writes, exact-match edits, link-tree rejection, no permanent-delete tool.
- Exact executable/argv/env policy, `shell:false`, PID/start-time/path identity checks, tree termination, runtime and output caps.
- Owner-bound durable search/process sessions and deterministic cursors.
- Durable idempotency claims: completed retries replay the stored result; crash-uncertain retries fail closed until local review.
- Serialized hash-linked audit JSONL with startup verification, rotation, correlation IDs, and secret redaction.
- Local kill switch and emergency read-only mode override remote authorization.
- Backup archive manifests contain SHA-256 for every payload file; restore verifies all hashes and retains pre-restore state.

## Verification results

All 12 recorded local release gates passed:

- clean install, format check, type-aware lint, strict TypeScript check
- 9 test files / 19 tests
- production build and package dry-run
- dependency audit: 0 high-or-greater vulnerabilities
- CycloneDX 1.6 SBOM and license inventory
- repository secret scan
- reproducible loopback benchmark

The integration suite uses both the official MCP v2 client and MCP Inspector 2.5.0 in `modern` + `--strict` mode. It negotiates protocol `2026-07-28`, discovers all 33 tools, tests invocation, missing-scope denial, reconnect, anonymous denial, malformed requests, Host/Origin defenses, and rate limiting. Security tests cover internal/external OAuth failures, traversal/link escapes, redaction, tamper detection, concurrent and crash-uncertain idempotency, process timeout/output limits/orphan recovery, and search cancellation races.

Manual built-artifact smoke test:

- Listener: only `127.0.0.1:7337`
- Anonymous MCP request: `401` with OAuth protected-resource discovery challenge
- Graceful SIGINT shutdown message observed; listener stopped afterward

## Local benchmark

Conditions: Windows x64 on `LAPTOP-13QINEIF`, Node 24.20.0, loopback Streamable HTTP, MCP `2026-07-28`, concurrency 8. All 238 measured operations succeeded (100%).

| Operation                   | Samples |  p50 ms |  p95 ms |
| --------------------------- | ------: | ------: | ------: |
| Ping                        |     100 |  29.982 |  49.932 |
| Small file read             |      25 |  32.160 |  47.413 |
| Directory list              |      25 |  33.815 |  50.827 |
| Ping at bounded concurrency |      48 | 144.722 | 201.888 |
| Search start                |      10 | 103.088 | 121.319 |
| Search results              |      10 |  31.949 |  36.200 |
| Short process start         |      10 | 537.370 | 557.589 |
| Persistent process output   |      10 |  30.463 |  36.709 |

These are local measurements, not claims about Internet, Funnel, or ChatGPT latency.

## Installed and deployment state

- Portable Node 24.20.0: present under ignored `.runtime`
- Portable ripgrep 15.2.0: present under ignored `.runtime`
- WinSW 2.12.0 release asset: present under ignored `.runtime`; service not installed
- Tailscale 1.102.3: present; no Serve/Funnel configuration
- `RadlinaRemoteMCP` Windows service: not installed
- Radlina direct-inbound firewall rule: not configured
- ChatGPT connector: not configured

## Rollback

1. Activate the local kill switch.
2. Restore the previous Tailscale config with `scripts/operations/restore-tailscale.ps1`.
3. Restore a verified config/state archive with `scripts/operations/restore.ps1 -Archive <path>`.
4. Select the reviewed prior Git commit and run `scripts/operations/update-service.ps1`.
5. Uninstall with `scripts/operations/uninstall-service.ps1`; state is retained unless `-PurgeState` is explicitly supplied.

## Residual risks and limitations

- The official WinSW 2.12.0 upstream asset is not Authenticode-signed and upstream publishes no checksum. The project pins the observed official-release SHA-256 `05b82d46ad331cc16bdc00de5c6332c1ef818df8ceefcd49c726553209b3a0da`; independent publisher authenticity remains a residual risk.
- Node's built-in SQLite API may emit an experimental warning despite the pinned LTS runtime.
- Interactive stdin cannot be reconstructed after a service restart; persisted output remains readable and orphan state is reconciled.
- Crash-uncertain mutation claims require local outcome inspection and explicit claim clearing; this is a deliberate at-most-once safety choice.
- One canonical `*.ts.net` hostname is required. Tailscale already supplies multi-edge/DNS addresses. Multi-device active/passive service requires state replication, fencing, and audit fan-in and is outside this release scope.
- Reboot was not initiated. No public endpoint was enabled during local validation.
