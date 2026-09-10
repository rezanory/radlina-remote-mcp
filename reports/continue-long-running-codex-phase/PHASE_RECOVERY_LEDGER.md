# Phase Recovery Ledger

- Reconciled at: `2026-09-10T17:18:50.3250345Z`
- Authoritative writer: `C:/radlina-remote-mcp-integration/controller-full-control-v1`
- Branch: `production/controller-full-control-v1`
- Starting commit: `deba1724ac82a329cafc27b67c073f61aaeb80ab`
- Starting tree: `d15c951560de537f616d54e597ecf35657c82d35`
- Reconciled dirty-tree fingerprint: `71f64fdcc804ef80b2603bf9c7c18cd2bca694f0c522a251240ce52f867ebfd7`
- Accepted immutable baseline: `C:/radlina-remote-mcp-baselines/baseline-production-precutover-20260910T0958Z/BASELINE.json`
- Live production fallback: service `RadlinaRemoteMCP`, `LocalSystem`, version `0.1.0` with independently verified trusted-owner/full-control bootstrap.

## Recovered completed work

- Production config backup and trusted-owner effective config verification exist.
- Production service identity and service ACL bootstrap verification exist.
- SYSTEM-level explicit Git `safe.directory` verification exists with no wildcard.
- Partial 0.2.0 source changes were reconciled file-by-file; no source mutation was performed during recovery.

## Remaining mandatory boundary

1. Complete the strict release manifest, ROOT-aware state machine, mutation lock, readiness confirmation, and restart behavior.
2. Complete service migration scripts, trusted-owner restart scheduling, tests, documentation, and deterministic release builder.
3. Run all required validation gates and bind receipts to exact source identity.
4. Commit once, add the separate `github` remote, publish non-force, and prove local/remote identity.
5. Build and verify an exact immutable candidate; deploy without disturbing config/state/workspace.
6. Run Radlina-only post-deploy smoke, benchmark, rollback, re-promotion, restart/reconnect, audit, security, and resource checks.
7. Emit the final closure receipt and skill result only when every mandatory gate is exact PASS.

## Current blocker classification

- Classification: `BLOCKED_PARTIAL_GREEN_REQUIRED_VALIDATION_INCOMPLETE`
- Parent family: `EVIDENCE_GAP`
- Subreason: release/rollback implementation and full required validation are incomplete.
- Scope: production closure admission only; the live production fallback remains healthy.
- Unblock condition: implementation complete plus exact green validation, publication, deployment, rollback/re-promotion, and evidence closure.
- Authority fence: no production promotion before the pre-promotion gate is green.

## Fix-forward incidents

- `BLOCKED_QA_DEPENDENCY_COUPLING`: running the separate suites and the aggregate suite concurrently exhausted local test capacity and caused bounded HTTP timeouts. The tests were given an explicit 60-second network-test ceiling and the complete gate matrix was rerun sequentially: unit 21/21, integration 8/8, security 7/7, resilience 5/5, aggregate 41/41.
- Process-output correctness: Windows PowerShell produced no captured stdout when launched with `detached:true`. The process manager now launches with `shell:false` and `detached:false`, flushes output before publishing a terminal session state, and the direct executable parity integration test proves Git, Node, Python, PowerShell, cmd, npm, and npx with an empty command allowlist.
