# Radlina Remote MCP V3 — final-four code-only progress ledger
Date: 2026-10-12
Repository: rezanory/radlina-remote-mcp
Worktree: E:\radlina-remote-mcp-worktrees\v3-final4-composition-20261012
Branch: feature/v3-final4-composition-20261012
Draft PR: https://github.com/rezanory/radlina-remote-mcp/pull/15

## Immutable measurement rules
- These are **source remediation milestones in this tracked completion round**, not a verified inventory of all historical code and NOT the formal acceptance score.
- Stage weight times the stage's completed subtask shares is its contribution to the overall **code-only workstream**. Round at reporting only; no rounding while summing.
- Existing source that has not yet been checked against a specific subtask stays at zero in this ledger, which does not mean that feature is absent from the repository.
- A subtask may reach 100% here on authored/linked source and exact Git receipt alone; it does NOT assert compiling, testing, installation or operating acceptance.
- All test, build, typecheck, lint, actual migration, Canary, Rollback, deployment and reviewer/owner acceptance activities are DEFERRED by explicit current scope.
- Official gates frozen at **24 / 28 = 85.7142857%** until separately authorized and independently evidenced.
- Do not use Codex; do not touch V2, Tailscale, VPN, peers, or untracked cloudflare/; never reset, clean, prune or force push.

## 12 stages: 100 weighted points
| Stage | Weight | Source subtask shares (sum 100 per stage) | Current stage % | Weighted points |
|---|---:|---|---:|---:|
| 01 Branch/isolation | 5 | Branch and PR checkpoint 35/35; E-worktree and peer isolation 35/35; source branch comparison 30/30 | 100% | 5.00 |
| 02 Bootstrap lifecycle | 10 | Single factory 25/25; shared P03 registry 20/20; construction rollback 30/30; idempotent close and zeroization 15/15; gateway close order 10/10 | 100% | 10.00 |
| 03 Trusted configuration | 8 | Immutable hash and schema 30/30; owner-signed Mac policy 25/25; physical live Tailnet pins 25/25; SQLite schema-version binding 20/20 | 100% | 8.00 |
| 04 P08 Mac persistence | 9 | Signed heartbeat / keychain 25/0; LaunchAgent startup/shutdown 25/0; capability and P03 lifetime 25/0; retry and durable receipt recovery 25/0 | 0% | 0.00 |
| 05 Windows local agent | 8 | Interactive owner cycle 25/0; protected signer 25/0; recipient execution 25/0; restart and duplicate prevention 25/0 | 0% | 0.00 |
| 06 I01 physical routing | 12 | Two-way native routing 25/0; S02E local grant 25/0; sealed signed dispatch 25/0; terminal receipt and unknown outcome 25/0 | 0% | 0.00 |
| 07 Durable idempotency | 9 | Persistent queues 30/0; exact deduplication 25/0; restart recovery 25/0; evidence/receipt reconciliation 20/0 | 0% | 0.00 |
| 08 S03 independent audit | 8 | Witness endpoint/protocol 25/0; independent keys 25/0; signed envelope 25/0; strict ACK and outage status 25/0 | 0% | 0.00 |
| 09 F01 release and rollback | 12 | Mac full LaunchAgent release pointer 30/30; Windows stable task release entrypoint 30/30; durable uncertain-state journal 25/0; rollback/recovery contract 15/0 | 60% | 7.20 |
| 10 AC01 / OAuth surface | 8 | Native client and subject 25/0; permission-scoped tools 25/0; physical target authorization 25/0; final-gate evidence surface 25/0 | 0% | 0.00 |
| 11 Migration and installers | 8 | 11 SQLite store v1 contracts 30/30; non-destructive v0->v1 adoption 20/20; Windows release-safe installer 15/15; macOS upgrade lifecycle 20/0; owner-authorized existing-task migration 15/0 | 65% | 5.20 |
| 12 Technical handoff | 3 | This detailed ledger 25/25; per-component coverage reconciliation 25/0; complete evidence/runbook 25/0; source-complete handoff closure 25/0 | 25% | 0.75 |
| **Total** | **100** | **Scoped remediation tracking only** | | **36.15 / 100** |

## Source receipts
- 14f429f: original integrated V3 physical code and P03 bootstrap, [skip ci].
- 37d989b: one active composition path; duplicate registry implementation removed, [skip ci].
- 5819fc4: 11 owned SQLite handles are closed on failed composition; idempotent close; zeroized S03 HMAC, [skip ci].
- 5017eb0: both physical Tailnet hashes require exact live+owner-pinned identity, [skip ci].
- 7952afb: all three Mac LaunchAgent release strings switch as a single release contract, [skip ci].
- d5be156: verified baseline schema-version adoption for 11 V3-owned SQLite stores, [skip ci].
- 5bb3443: V3-only Windows task launcher resolves the service's verified active release; new installer points at stable launcher, [skip ci].

## Non-claims / pending gaps
- The stable Windows launcher is only installed by a **new** authorized install. Existing scheduled tasks are deliberately not replaced; a separate owner-approved migration workflow is still required.
- Installer / task service state was not inspected or changed. The Windows/macOS release drivers have no actual Canary or Rollback execution receipts.
- Version-1 SQLite stamping was written in source but NOT executed. Future version-2+ migrations must use independently reviewed contracts.
- No tests, build, TypeScript checking, lint, audit/review acceptance, device execution, production deployment or final 4-gate acceptance was performed.
- Do not treat 36.15% remediation accounting as 36.15% of the V3 repository or operational production readiness.

## Next code-only work order
1. Stage 09: persist native supervisor switch phases and exact rollback recovery without implicit retry after unknown outcome.
2. Stage 11: owner-explicit upgrade of pre-existing V3 scheduled tasks; lifecycle-safe macOS release upgrades.
3. Stage 04/05: reconcile both native agents with the shared P03/signing/heartbeat contract.
4. Stage 06/07/08: close all I01, S02E, durable result and independent S03 witness contract holes.
5. Stage 10 and 12: map all published native MCP tools to physical ports and complete the source-only handoff.

Every completed subtask must update the percentage and cite a new immutable [skip ci] Git receipt. Never auto-increase official gate counts.
