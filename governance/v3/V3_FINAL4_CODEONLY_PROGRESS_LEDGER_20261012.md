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
| 04 P08 Mac persistence | 9 | Signed heartbeat / Keychain 25/25; LaunchAgent startup/shutdown source 25/25; capability and P03 lifetime source 25/25; independently recoverable signed receipt 25/25 | 100% | 9.00 |
| 05 Windows local agent | 8 | Interactive owner cycle 25/25; protected signer 25/25; recipient native execution 25/25; complete restart/reconcile contract 25/0 | 75% | 6.00 |
| 06 I01 physical routing | 12 | Two-way native source 25/25; S02E local grant 25/25; sealed signed dispatch 25/25; signed terminal signed reply/reconciliation 25/10 (durable local receipt; external re-anchoring pending) | 85% | 10.20 |
| 07 Durable idempotency | 9 | SQLite queues 30/30; exact deduplication 25/25; persistent restart/unknown blocking 25/25; signed receipt reconciliation 20/10 (local signed persistence; external proof still pending) | 90% | 8.10 |
| 08 S03 independent audit | 8 | Witness endpoint/protocol 25/25; independent Keychain/provisioning 25/25; HMAC/Ed25519 signed envelope 25/25; full cross-system lost-ACK reconciliation 25/0 | 75% | 6.00 |
| 09 F01 release and rollback | 12 | Mac operator all three release references 30/30; Windows stable active release pointer 30/30; SQLite uncertain native journal 25/25; read-only unknown snapshot 5/5; signed owner+reviewer repair 10/0 | 90% | 10.80 |
| 10 AC01 / OAuth surface | 8 | Native owner OAuth client/subject 25/25; permission-scoped MCP tools 25/25; physical target binding 25/25; all-gates production contract reconciliation 25/0 | 75% | 6.00 |
| 11 Migration and installers | 8 | 11 SQLite store v1 contracts 30/30; non-destructive v0->v1 source 20/20; Windows new installer 15/15; macOS owner-initiated upgrade source 20/20; existing Windows task owner migration source 15/15 | 100% | 8.00 |
| 12 Technical handoff | 3 | Detailed ledger 25/25; nine-stage exact source coverage map 25/25; future physical acceptance runbook 25/25; all-source closure 25/0 | 75% | 2.25 |
| **Total** | **100** | **Source-only remediation estimate: mapped existing code + new commits** | | **89.35 / 100** |

## Source receipts
- 14f429f: original integrated V3 physical code and P03 bootstrap, [skip ci].
- 37d989b: one active composition path; duplicate registry implementation removed, [skip ci].
- 5819fc4: 11 owned SQLite handles are closed on failed composition; idempotent close; zeroized S03 HMAC, [skip ci].
- 5017eb0: both physical Tailnet hashes require exact live+owner-pinned identity, [skip ci].
- 7952afb: all three Mac LaunchAgent release strings switch as a single release contract, [skip ci].
- d5be156: verified baseline schema-version adoption for 11 V3-owned SQLite stores, [skip ci].
- 5bb3443: V3-only Windows task launcher resolves the service's verified active release; new installer points at stable launcher, [skip ci].
- 15bdd2a: native F01 switch journal + fail-closed unknown phases; preserve LF shell checkout, [skip ci].
- f286167: owner-pinned existing Windows task migration and Mac operator/fleet/witness upgrade source, [skip ci].
- eb8eb72: durable signed Mac heartbeat ACK verified against unchanged physical P03 Keychain identity, [skip ci].
- 67b196b: exact target I01/F01 signed replies stored in SQLite before HTTP reporting; no native re-execution on lost ACK, [skip ci].
- Source-only handoff: V3_FINAL4_NINE_STAGE_SOURCE_COVERAGE_20261012.md and V3_FINAL4_DEFERRED_PHYSICAL_VALIDATION_RUNBOOK_20261012.md; physical tests are still forbidden in this phase.

## Non-claims / pending gaps
- The stable Windows launcher is installed by a new authorized install; existing scheduled tasks are deliberately not replaced automatically. Explicit owner-pinned migration source is available in scripts/operations/v3-final4-windows-task-migrate.ps1, but has not been executed.
- Installer / task service state was not inspected or changed. The Windows/macOS release drivers have no actual Canary or Rollback execution receipts.
- Version-1 SQLite stamping was written in source but NOT executed. Future version-2+ migrations must use independently reviewed contracts.
- No tests, build, TypeScript checking, lint, audit/review acceptance, device execution, production deployment or final 4-gate acceptance was performed.
- The updated 84.25% source accounting includes reclassified previously existing P08/I01/S03/OAuth code after source inspection. It is not 84.25% production readiness or an acceptance decision.

## Next code-only work order
1. Stage 09: owner/reviewer signed reconciliation of an independently verified unknown native switch; no auto-retry or blind rollback.
2. Stages 06/07: recipient-signed result storage now exists, but a verified owner/reviewer-authorized manual export/re-anchor protocol is still required for lost external ACK.
3. Stage 04: signed heartbeat evidence now stored as bounded durable signed envelope and verified against unchanged enrolled Mac P03 key; physical receipt transmission still needs later authorized E2E test.
4. Stage 08: lost ACK reconciliation between Mac witness, gateway and protected requester without minting fake receipts.
5. Stage 05/10/12: reconcile remaining Windows owner lifecycle, exact ChatGPT OAuth delivery contract and final source-only handoff.

Every completed subtask must update the percentage and cite a new immutable [skip ci] Git receipt. Never auto-increase official gate counts.
