# Radlina Remote MCP V3 — final four gates, source-only handoff

Date: 2026-10-12
Repository: rezanory/radlina-remote-mcp
Branch: feature/v3-final4-codeonly-20261012
Base: 3413282 (P08 signed-heartbeat ingress)

**OWNER INSTRUCTION: CODE ONLY. NO TESTS, TYPECHECK, LINT, BUILD, PHYSICAL CANARY/ROLLBACK, LIVE DEPLOYMENT OR ACCEPTANCE IN THIS ITERATION.**

## Safety boundaries

- V2 2.0.0-alpha.2 untouched; no edits to main, active services, existing OAuth keys, Tailscale or VPN.
- All new files are in an isolated E: Worktree and inactive until reviewed and explicitly composed.
- Remote operations require independently verified owner OAuth and source identity, exact trusted P03 target, local recipient approval, durable once-only journal and external S03 audit.
- Formal accepted baseline: 24 of 28 (85.71%). Four final official gates remain open.

## P08: permanent Mac agent, code only

- scripts/operations/v3-mac-heartbeat-sender.ts: bounded signed P03 heartbeat from immutable pinned real Mac source revision de625477, existing dedicated V3 Keychain, secure HTTPS origin.
- scripts/operations/v3-mac-launchagent-install.sh: private per-user LaunchAgent; 45-second interval; no inbound socket and no remote-shell features.
- .github/workflows/v3-p08-install-persistent-mac.yml: workflow_dispatch manual installation path; NOT RUN.
- Future: install and observe real periodic signed P03 heartbeats, durable recovery and availability.

## I01: cross-device dispatch, code only

- src/v3/integration/i01-secured-dispatch.ts: exact target, authenticated origin, separately protected owner signer, S02E consent and target-local Ed25519 approval; durable idempotency, signed receipt and mandatory S03 external anchor.
- src/v3/integration/i01-recipient-agent.ts: target verifies exact owner command and local user grant before executing only an explicitly allowlisted capability port. No generic command fallback.
- src/v3/integration/i01-sealed-outbox.ts: sealed durable no-retry queue for outbound Mac/Windows execution, physical signed device lease and return receipt. A real encryption implementation and bound HTTP endpoint are still required.
- Future: bind real transport and target-local approval UI; obtain real two-host execution receipts.

## F01: canary / rollback, code only

- src/v3/fleet/physical-adapters.ts: two-device plan, protected owner signer, target local consent, P03 signed receipts and separate journal preventing duplicate fleet switches.
- src/v3/fleet/local-release-agent.ts: target-side manifest verification, V3-only reversible release-port operations, durable signed audit.
- src/v3/fleet/physical-composition.ts: per-plan V3FleetController composition.
- Future: wire concrete Windows/Mac V3-only service switch drivers, then real canary, rollback and health evidence.

## AC01: independent acceptance, code only

- src/v3/acceptance/ac01-final-gates.ts: four signed acceptance gates, independently controlled owner and reviewer Ed25519 keys, traceable input/runtime/execution/output receipts.
- src/v3/control-plane/final4-mcp-surface.ts: opt-in native V3 tools with authenticated client provenance and distinct execute/fleet OAuth scopes.
- src/v3/gateway/oauth-readonly.ts: final-four capabilities and OAuth scopes appear ONLY if real physical ports are injected; the active service injects none.
- AC01 refuses read-only discovery as a successful ChatGPT-native write/execute action.
- Future: native ChatGPT V3 tool list refresh, authenticated execution on both devices, independent reviewer receipts.

## Remaining operational gates — deferred without running tests

| Gate | Evidence required later |
|---|---|
| P08 | Mac permanent agent, periodic signed heartbeat, Keychain durability/recovery |
| I01 | Two-host live signed execution, recipient consent, S03 external anchor |
| F01 | Real two-device canary, rollback and health from exact manifests |
| AC01 | Real native ChatGPT plugin call, Windows + Mac outputs, owner/reviewer acceptance |

**Status: SOURCE CODE PREPARED. NOT BUILT. NOT TESTED. NOT DEPLOYED. NOT ACCEPTED.**
