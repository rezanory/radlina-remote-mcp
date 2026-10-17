# Radlina Remote MCP V3 — Four final components, code-only handoff

Date: 2026-10-12
Repository: rezanory/radlina-remote-mcp
Branch: feature/v3-final4-composition-20261012

Owner authorization: CODE ONLY. No tests, build, lint, security review, live deployment, physical Canary/Rollback or final acceptance are authorized in this stage.

## Core execution model

V3 OAuth issuer: https://v3-mcp.radlina.com, independent from V2.
Primary factory: src/v3/integration/final4-physical-bootstrap.ts.
Disabled by default; exact owner-pinned P03 device, native OAuth client, S02E, protected signing and separate S03 witness credentials are required before exposing execution tools.
Preserve V2 2.0.0-alpha.2, its state, ports and credentials.

## P08: physical Mac persistent agent

- scripts/operations/v3-mac-heartbeat-sender.ts and v3-mac-launchagent-install.sh: per-user signed heartbeat using existing physical Mac Keychain identity.
- src/v3/device/macos-p03-signer.ts: strict P03 per-schema signatures, no key rotation, no private key export.
- scripts/operations/v3-final4-mac-install.sh: isolated I01 operator, F01 fleet operator and Mac S03 witness LaunchAgents; staged immutable release and private policy files required.
- scripts/operations/v3-s03-cloudflare-mac-install.sh: optional Mac independent S03 Cloudflare tunnel, token-file only, no VPN/V2 changes.

## I01: bounded two-way physical device execution

- i01-owner-bindings.ts, i01-tailnet-observer.ts, i01-physical-session.ts: immutable OAuth client/owner/source, fresh P03 signed device identity, nonce replay rejection.
- i01-sealed-outbox.ts: exact target, DPAPI encrypted durable queue, unknown outcome requires manual reconcile.
- i01-local-consent-mailbox.ts, i01-s02e-consent.ts, i01-agent-relay-http.ts: local interactive recipient approval, independent signed decision, HTTP claim/report.
- i01-macos-operator.ts and i01-windows-operator.ts: outbound-only signed device cycles, local operator approval.
- i01-native-files.ts: device health and scoped text read/write; no shell or unrestricted disk paths.
- v3-windows-operator-cycle.ts and v3-owner-interactive-cycle.ts: interactive Windows owner agent, never SYSTEM impersonation.
- v3-final4-windows-install.ps1: per-user Windows-only scheduled tasks; no changes to V2.

## F01: physical reversible canary and rollback

- src/v3/fleet/physical-adapters.ts, physical-composition.ts, f01-sealed-transport.ts and f01-release-consent.ts: physical exact-device signed fleet messages, consent and durable unknown-result journal.
- src/v3/fleet/native-v3-release-host.ts: Windows switches RadlinaV3OAuthBeta only; Mac switches the V3 Mac operator LaunchAgent only; old release remains for owner-approved rollback.
- src/v3/fleet/mac-fleet-operator.ts and windows-fleet-operator.ts: local approval and actual device-side signed reply.
- scripts/operations/v3-mac-fleet-cycle.ts and v3-windows-fleet-cycle.ts: one bounded operation per owner-authorized cycle.

## AC01: final native ChatGPT V3 acceptance

- src/v3/control-plane/final4-mcp-surface.ts: explicit OAuth and trusted client; exact device execution, fleet planning/running, consent requests and read-only acceptance status.
- src/v3/acceptance/ac01-final-gates.ts: independent owner and reviewer signatures over physical input/runtime/execution/output receipts; no automatic acceptance.
- src/auth/service.ts: optional V3-only device:execute and fleet:control OAuth scopes, V2 default scopes unchanged.
- scripts/operations/v3-final4-owner-policies.ts: prepare signed policies using existing physical Windows owner CurrentUser DPAPI, physical P03 keys, actual ChatGPT OAuth client IDs and independent reviewer/Mac witness PUBLIC keys; no credentials invented.

## S03 separate Mac witness dependency

- src/v3/audit/s03-independent-witness.ts, s03-mac-witness.ts, s03-mac-wire.ts and s03-macos-signer.ts: exact wire protocol, device/owner Ed25519 validation, durable chained receipts and independent witness signature.
- scripts/operations/v3-s03-mac-keychain-prepare.ts: explicit new S03 witness identity generation (different from existing Mac P03) and public key receipt.
- scripts/operations/v3-s03-mac-witness-daemon.ts: separate Mac loopback service 127.0.0.1:7444, secured POST /api/v1/anchor, independent TLS ingress v3-audit.radlina.com.
- Witness bearer token, HMAC key, tunnel token and independent reviewer key must be pre-provisioned securely before final activation.

## Deliberately deferred final acceptance

P08: install Mac permanent agents, real signed heartbeats and failure recovery.
I01: authenticated two-host native commands, real target-local consent and independent S03 receipt.
F01: physical staged releases, Canary and Rollback on Windows plus Mac, health after rollback.
AC01: actual native ChatGPT V3 OAuth scopes and tool calls, independent owner/reviewer signatures.

Current work is source-level only, not compiled/tested/reviewed/deployed. The official four release gates remain open; the accepted baseline remains 24 of 28 (85.71%). No claims of production readiness follow from file creation.
