# Radlina Remote MCP V3 — code-only final-four handoff (12-stage source checklist)

**Date:** 2026-10-12
**Repository:** rezanory/radlina-remote-mcp
**Development branch:** `feature/v3-final4-composition-20261012`
**Draft PR:** https://github.com/rezanory/radlina-remote-mcp/pull/15
**Canonical Windows worktree:** `E:\radlina-remote-mcp-worktrees\v3-final4-composition-20261012`

## Precise status

**Source checklist coverage: 100/100 weighted points, code-only**, meaning the remaining
declared P08/I01/F01/AC01/S03 pathways have authored implementations and exact Git commits.
**Validation status: UNVERIFIED.** No TypeScript compilation, build, test, lint,
code audit, live credential invocation, real Windows/Mac execution, rollout,
Canary, Rollback or operational installation is implied. Actual `CODE COMPLETE`
engineering certification requires the next independently authorized validation
gate. Formal operational acceptance remains **24/28 = 85.71%**, with all four
P08/I01/F01/AC01 gates PENDING until physical reviewer-signed evidence exists.

## Final-four exact physical wiring map

| Lane | Source/driver | Trust and lifecycle contract | Native or remote action |
|---|---|---|---|
| P08 Mac signed heartbeat | `scripts/operations/v3-mac-heartbeat-sender.ts`; `src/v3/device/macos-p03-signer.ts`; `src/v3/device/mac-heartbeat-ingress.ts` | Original enrolled Keychain public key, signed heartbeat, pinned Mac Tailnet node, HTTPS V3 gateway ACK and durable signed-envelope verification | Mac LaunchAgent runs bounded heartbeat; never exports signing keys |
| Windows owner P03 | `scripts/operations/v3-windows-signed-heartbeat.ts`; `src/v3/security/windows-owner-broker.ts`; `src/v3/device/windows-protected-identity.ts` | Real interactive owner, Windows DPAPI-protected signer and pinned P03 device identity | Owner-local operator/signer cycles only |
| I01 native two-way execution | `src/v3/integration/i01-macos-operator.ts`; `i01-windows-operator.ts`; `i01-recipient-agent.ts`; `i01-native-files.ts` | Exact owner Ed25519 command, local human consent, live source peer, target P03 key, bounded allowlisted filesystem action | One exactly named file read/write in approved native root; no shell |
| S02E one-time authorization | `src/v3/integration/i01-s02e-consent.ts`; `src/v3/security/device-consent.ts`; `src/v3/control-plane/final4-mcp-surface.ts` | OAuth `workflowExecutionId`, exact `consentRequestId`, approved source, target, capability and `inputSha256` all match | Consent is checked before execution; not inferred from caller metadata |
| I01 durable relay/reconciliation | `src/v3/integration/i01-sealed-outbox.ts`; `i01-secured-dispatch.ts`; `i01-physical-session.ts`; `i01-recipient-agent.ts` | One-time leased signed request; original signed target response committed to SQLite before network reporting | Lost ACK re-delivers stored signed response only; `v3_exact_device_reconcile` S03-anchors old receipt, never reruns file operation |
| F01 native protected switch | `src/v3/fleet/native-v3-release-host.ts`; `native-switch-journal.ts`; `local-release-agent.ts`; `physical-adapters.ts` | Exact SHA-pinned manifests, owner command, recipient human approval, local persisted switch phases and P03-signed receipt | Windows V3-only WinSW and Mac V3-only LaunchAgent; never V2 |
| F01 late receipt/manual recovery | `src/v3/fleet/f01-sealed-transport.ts`; `mac-fleet-operator.ts`; `windows-fleet-operator.ts`; `physical-composition.ts` | Local signed response and lease stored before HTTP; independent Mac S03 anchor; separate owner/reviewer signature for unknown native state | `v3_fleet_reconcile` re-anchors only historical signed receipt, DOES NOT resume Canary; owner CLI `v3-final4-native-switch-reconcile.ts` records two-party signed native observation |
| S03 independently signed witness | `src/v3/audit/s03-independent-witness.ts`; `s03-mac-wire.ts`; `s03-mac-witness.ts`; `scripts/operations/v3-s03-mac-witness-daemon.ts` | Dedicated macOS Keychain witness Ed25519 key, distinct HMAC/bearer, pinned witness URL, exact `recordHash`, append-only chain | POST `/api/v1/anchor`; read-only original signed ACK recovery `/api/v1/anchor/lookup`; no fake anchor or arbitrary shell |
| AC01 native OAuth MCP | `src/v3/control-plane/final4-mcp-surface.ts`; `src/v3/integration/i01-owner-bindings.ts`; `src/v3/gateway/oauth-readonly.ts`; `src/v3/acceptance/ac01-final-gates.ts` | Separately pinned ChatGPT V3 OAuth client_id, owner `sub`, consent/execution/fleet scopes, physical target and independent reviewer | Read-only status + expressly owner-scoped mutation/reconciliation tools; formal acceptance cannot be set by code presence |
| V3 config, registry and lifecycle | `src/v3/control-plane/v3-environment-factory.ts`; `src/v3/integration/final4-physical-bootstrap.ts`; `final4-schema-migrations.ts` | Immutable SHA-pinned owner binding, P03 shared registry, signed Mac policy, independent S03 credentials, non-destructive V3 schema-version adoption | Single physical factory and full cleanup, never V2 |

## User-facing V3 MCP tool contracts

- `v3_consent_request`: owner OAuth scope `device:execute`; exact source, target,
  capability, input, `workflowExecutionId` and idempotency key.
- `v3_consent_status`: `device:read`, same owner workflow.
- `v3_exact_device_execute`: `device:execute` + **same** approved
  `workflowExecutionId` and `consentRequestId`, exact source/target/input,
  bounded max attempts = 1, `idempotencyKey` creates an exact unique node.
- `v3_exact_device_reconcile`: owner `device:execute`; same owner-bound
  workflow and idempotency key; independently re-anchors original signed
  response via S03; does not execute or submit a new native command.
- `v3_fleet_plan`, `v3_fleet_run`: `fleet:control`; separate approved
  release manifests, two enrolled devices, original owner plan and local
  exact target human consent.
- `v3_fleet_reconcile`: `fleet:control`; original signed F01 receipt and
  S03 ACK for one `planId`/`operationId`; leaves fleet plan blocked and
  never resumes Canaries.
- `v3_release_acceptance_status`: `device:read`; only reads independent
  reviewer/owner gate status, does not approve gates.

## Native/reconciliation side conditions

- Original I01/F01 request leases may expire. Their already-executed
  response can be delivered again **only** when the original target P03
  Ed25519 signature, original sealed owner command and target identity match.
- Stale or unknown original proof cannot be replaced with a new operation;
  all statuses stay `unknown` until independent proof is produced.
- Native F01 release uncertainty requires independently observed **healthy**
  V3 release and two separate Ed25519 owner/reviewer signatures. Recording
  a clearance is NOT fleet acceptance, Rollback or rollout authorization.
- The independent S03 witness only returns an original signed ACK with the
  exact `recordHash`. Time-expired original release commands may be **recovered**,
  but never re-executed.
- No owner private key, S03 bearer, DPAPI key or actual witness token is in
  source-generated handoff materials.

## Source receipts for the most recent completion lane

- `b405f64`: exact F01 S03 schema and original signed ACK lookup.
- `4ef4830`: workflow-bound S02E grant + original S03 5xx ACK lookup.
- `cd645de`: dual-signed healthy unknown native F01 switch reconciliation.
- `2da0a18`: original I01 target P03 signed reply retried without native work.
- `046e226`: original F01 P03 signed fleet receipt redelivery, no release replay.
- `474675a`: OAuth-owner I01/F01 S03 re-anchoring from original signed evidence.

All these commits use `[skip ci]`, were pushed to the Draft PR branch, and
do not reflect builds/tests. The final documentation commit will update the
progress ledger.

## Separately authorized next phase — no part of source checklist

See `governance/v3/V3_FINAL4_DEFERRED_PHYSICAL_VALIDATION_RUNBOOK_20261012.md`.

In that next gate, independently review/compile/typecheck/build/test the
source (including security and API compatibility), then install only V3,
validate both devices' physical identity and network, S03 real witness,
two-way user-approved file operations, duplicate/no-replay evidence, Canary
and Rollback, and obtain two-party formal gate acceptance.
Until those receipts exist: **DO NOT call V3 Production Ready, 28/28, or
formally 100% accepted.**
