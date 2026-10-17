# Final-four V3 code-only coverage: stages 04–12

Repository: rezanory/radlina-remote-mcp
Draft PR #15; source-only development, no runtime tests/build/typecheck or official acceptance.
All source paths relative to the repository root. Evidence denotes a source implementation, **not** a successful physical operation.

## Stage 04 — P08 persisted macOS agent
- **Signed heartbeat / existing Keychain:** `scripts/operations/v3-mac-heartbeat-sender.ts`, `src/v3/device/macos-p03-signer.ts`, `src/v3/device/mac-heartbeat-ingress.ts`.
- **Agent lifecycle:** `scripts/operations/v3-mac-launchagent-install.sh`, `scripts/operations/v3-final4-mac-install.sh`. `.gitattributes` now enforces LF on operations Shell sources.
- **Capability / identity:** `src/v3/device/p08-mac-operator-policy.ts`, `src/v3/integration/i01-macos-operator.ts`.
- **Retry and receipts:** sender writes `heartbeat-events.jsonl`; outbound polling is launchd-owned. Signed post/receipt is fail-closed; physical acknowledgment not verified during this code-only turn.
- **P08 signed receipt persistence source completed:** `v3-mac-heartbeat-sender.ts` saves the exact signed envelope plus accepted TLS gateway response to `heartbeat-latest-ack.json`; `i01-macos-operator.ts` independently verifies enrolled-Keychain Ed25519 signature, agent instance and 120-second freshness before work. Runtime acceptance remains deferred; physical architecture pin x64 must still match the enrolled Mac.

## Stage 05 — Windows owner agent
- **Owner-only signing:** `src/v3/security/windows-owner-signer.ts`, `src/v3/security/windows-owner-broker.ts`, `scripts/operations/v3-owner-interactive-cycle.ts`.
- **P03 identity/heartbeat:** `scripts/operations/v3-windows-signed-heartbeat.ts`, `src/v3/device/windows-protected-identity.ts`.
- **Recipient:** `scripts/operations/v3-windows-operator-cycle.ts`, `src/v3/integration/i01-windows-operator.ts`, `src/v3/integration/i01-native-files.ts`.
- **Persistence / restart:** `scripts/operations/v3-final4-windows-task-launch.ps1`, `scripts/operations/v3-final4-windows-task-migrate.ps1`.
- **Source lifecycle complete:** interactive owner signer/recipient and stable release Task migration exist; `src/v3/integration/i01-windows-operator.ts` now persists exact lease and retransmits only an originally signed SQLite reply after lost network ACK, before claiming new work. Executing those tasks and verifying real owner dialogs remains the future separate acceptance gate.

## Stage 06 — I01 secure two-way execution
- **Two recipients:** `src/v3/integration/i01-macos-operator.ts`, `src/v3/integration/i01-windows-operator.ts`.
- **Target-local grant:** `src/v3/integration/i01-s02e-consent.ts`, `src/v3/security/device-consent.ts`, `src/v3/integration/i01-local-consent-mailbox.ts`.
- **Sealed owner dispatch:** `src/v3/integration/i01-secured-dispatch.ts`, `src/v3/integration/i01-sealed-outbox.ts`, `src/v3/integration/i01-agent-relay-http.ts`.
- **Native file execution / protected receipts:** `src/v3/integration/i01-native-files.ts`, `src/v3/integration/i01-recipient-agent.ts`.
- **Source path to independent completion:** `i01-recipient-agent.ts` persists original signed reply, `i01-sealed-outbox.ts` accepts original late signed result and exposes exact encrypted historical evidence. `i01-secured-dispatch.ts`'s `reconcileUnknown` owner-validates that reply and requests a real signed S03 witness ACK, then atomically completes the uncertain journal. V3-only MCP `v3_exact_device_reconcile` is bound to original OAuth workflow. No native replay.

## Stage 07 — persistent idempotency and manual unknown outcome
- SQLite command and recipient replay ledgers: `src/v3/integration/i01-secured-dispatch.ts`, `src/v3/integration/i01-recipient-agent.ts`, `src/v3/integration/i01-sealed-outbox.ts`, `src/v3/fleet/f01-sealed-transport.ts`, `src/v3/fleet/local-release-agent.ts`.
- These sources use unique exact-request keys, compare-and-swap transitions, `unknown`/`uncertain` states and no automatic remote retry.
- **Source recovery is wired:** I01 and F01 original owner command / P03-signed target reply / original lease persist in separate V3 SQLite tables. Mac and Windows agents attempt only signed reply re-delivery before polling new work. Gateway accepts late original results with exact signature+lease and exposes owner-authorized I01/F01 historical re-anchoring via independently signed S03. Unknown native release state remains blocked until separately signed owner/reviewer healthy-state reconciliation.

## Stage 08 — S03 independent audit witness
- `src/v3/audit/s03-independent-witness.ts`: exact HTTPS witness URL, HMAC bearer, bounded append, pinned Ed25519 signed ACK.
- `src/v3/audit/s03-mac-wire.ts`, `src/v3/audit/s03-mac-witness.ts`, `scripts/operations/v3-s03-mac-witness-daemon.ts`: separate Mac signer and independent receipt chain.
- `scripts/operations/v3-final4-s03-mac-secret-stage.sh`, `scripts/operations/v3-s03-cloudflare-mac-install.sh`: independent provisioning source, no credentials fabricated.
- **Source contract closed:** `s03-independent-witness.ts` now supplies exact F01 `radlina.v3.f01.audit-witness-request/v1` Schema required by the Mac witness and hashes identical canonical evidence. `s03-mac-wire.ts` stores signed ACK durably, exposes MAC/bearer authenticated read-only `lookup`, and reconciles a chain entry that previously committed without its wire ACK. Client retries only original ACK lookup after lost POST or ambiguous HTTP 5xx. Real cross-system witness acceptance remains deferred.

## Stage 09 — F01 fleet canary, rollback and native release
- `src/v3/fleet/native-v3-release-host.ts`: pin exact manifest and active Mac/Windows V3 native services, not V2.
- `src/v3/fleet/native-switch-journal.ts`: persisted prepared/stopped/pointer-changed/restart/uncertain native switch phases, with future switch blocked when unknown.
- `scripts/operations/v3-final4-native-switch-status.ts`: read-only native switch snapshot, not authorized repair.
- `scripts/operations/v3-final4-windows-task-launch.ps1`: Windows scheduled tasks use verified active release.
- `scripts/operations/v3-final4-mac-upgrade.sh`: separate owner-authorized Mac upgrade for operator/fleet/witness LaunchAgents.
- **Owner/reviewer repair source complete:** `src/v3/fleet/native-switch-journal.ts` persists unique, append-only native unknown-state reconciliation signed by separate owner/reviewer Ed25519 keys. `scripts/operations/v3-final4-native-switch-reconcile.ts` requires a live healthy exact V3 release observation before applying clearance; no implicit restart/rollback. `v3_fleet_reconcile` anchors previously signed fleet receipts but leaves a stopped fleet plan stopped. Actual Canary/Rollback still deferred.

## Stage 10 — native OAuth, MCP and AC01
- `src/v3/gateway/oauth-readonly.ts` verifies OAuth scope and binds final four physical tools.
- `src/v3/control-plane/final4-mcp-surface.ts` includes exact device execution, consent, fleet plan/run and acceptance read-only status.
- `src/v3/integration/i01-owner-bindings.ts` pins real OAuth client, owner subject, source device, P03 key and Tailnet.
- `src/v3/acceptance/ac01-final-gates.ts`: independent owner/reviewer acceptance evidence. Official 24/28 unchanged.
- **Source contract mapped:** `i01-owner-bindings.ts` pins native ChatGPT V3 OAuth client ID, owner subject and fresh P03 source. `i01-s02e-consent.ts` binds `workflowExecutionId` and `consentRequestId` to exact owner/target/capability/input SHA; `v3_exact_device_execute` requires the same binding and scoped `device:execute`; `v3_exact_device_reconcile` and `v3_fleet_reconcile` require original owner/scopes and use signed historical evidence only. `v3_release_acceptance_status` remains read-only, formal 24/28 unchanged. Real issuer/client verification belongs to later authorized physical acceptance.

## Stage 11 — installers and schema versions
- `src/v3/integration/final4-schema-migrations.ts`: eleven V3-only SQLite stores and version-1 structural adoption; NOT EXECUTED.
- `scripts/operations/v3-final4-windows-install.ps1`: new Windows owner schedule installer.
- `scripts/operations/v3-final4-windows-task-migrate.ps1`: pinned owner-initiated migration for existing V3 tasks.
- `scripts/operations/v3-final4-mac-install.sh`: new Mac install.
- `scripts/operations/v3-final4-mac-upgrade.sh`: Mac upgrade across the three release-coupled LaunchAgents.
- **Source deliverables present**; all application/upgrade execution and installer acceptance deferred.

## Stage 12 — delivery and independent test handoff
- `governance/v3/V3_FINAL4_CODEONLY_PROGRESS_LEDGER_20261012.md` defines weighted source-only progress and exact Git receipts.
- This document maps stages 04–12 to source and unresolved precise work.
- **Source handoff written:** `governance/v3/V3_FINAL4_CODE_COMPLETE_SOURCE_HANDOFF_20261012.md` documents the exact source-to-port/MCP map, immutable trust requirements, original-receipt recovery and pending validation; `governance/v3/V3_FINAL4_DEFERRED_PHYSICAL_VALIDATION_RUNBOOK_20261012.md` defines the future independent input→runtime→execution→output→acceptance matrix. A compiled validated Release Manifest is deliberately NOT created because build/test/deployment are forbidden by this code-only gate.

## Critical accounting rule
These source findings are a reassessment of previously unexamined code, NOT new commits claiming implementation from scratch. No steps may promote 24/28 or claim a tested production result without real end-to-end independent evidence.
