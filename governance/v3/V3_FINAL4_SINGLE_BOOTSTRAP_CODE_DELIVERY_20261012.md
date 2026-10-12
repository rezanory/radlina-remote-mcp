# Radlina Remote MCP V3 — Final Four, single-bootstrap code-only handoff

**Date:** 2026-10-12  
**Repository:** `rezanory/radlina-remote-mcp`  
**Branch:** `feature/v3-final4-composition-20261012`  
**Mode:** code editing ONLY. No test, typecheck, build, lint, live service change, Canary, Rollback, independent audit or acceptance was performed.

## Canonical activation / dependency ownership

- Production daemon: `scripts/operations/v3-oauth-readonly-daemon.ts`.
- Only opt-in environment entry: `finalFourFactoryFromOwnerEnvironment` in `src/v3/control-plane/v3-environment-factory.ts`.
- The factory calls **one** active physical composition, `createV3FinalFourPhysicalComposition` in `src/v3/integration/final4-physical-bootstrap.ts`.
- `v3-physical-final4-runtime.ts` exports shared factory types **only**. The previously unused conflicting composition was removed from executable source after preserving its entire original implementation in commit `14f429f`; no second runtime/bootstrap entry remains.
- Gateway-owned `SqliteDeviceRegistry` is now injected into the physical composition. No duplicate physical P03 registry is allocated or closed by this route. The OAuth gateway closes it after closing composed ports.
- I01's durable dispatch journal is included in physical composition shutdown.

## Fail-closed binding before physical-port allocation

For `RADLINA_V3_FINAL4_ENABLE=1`, the factory requires existing immutable V3 binding, signed Mac capability policy, machine-DPAPI HMAC and independent witness writer-token file. The pre-composition guard enforces:

1. Bounded raw binding bytes matching pinned SHA-256 and exact schema discriminator.
2. Signed Mac policy bytes matching a separate pinned SHA-256; owner Ed25519 signature, expiry, exact machine fingerprint and capability scope are verified by the P08 policy validator.
3. Identical owner public-key identity, macOS device fingerprint, and approved Windows Tailnet node ID between the two policies.
4. V3-only absolute owner OAuth client policy path.
5. The canonical physical composition's strict Zod schema, P03 pins, separate S03 witness public key, OAuth owner-client binding and independent reviewer public key. Any missing dependency rejects activation.

## Existing code modules retained without replacement

| Gate | Source components present | Operational acceptance |
| --- | --- | --- |
| P08 | Mac signed heartbeat sender; existing P03 Keychain signer; per-user LaunchAgent install script and separate Mac operator policy | OPEN |
| I01 | Owner/client bind, S02E and target-local consent, protected owner signer, sealed queue, result/unknown-state ledger, Mac/Windows native file-capability operators, exact physical relay routes | OPEN |
| F01 | Windows/Mac release hosts and interactive supervisors, sealed transport, exact target-local approval, signed fleet receipt, explicit manifest/rollback operations | OPEN |
| AC01 | Native MCP tool handlers, V3 OAuth scopes, independent S03 Mac witness, owner/reviewer acceptance ledger | OPEN |

All items above are **source presence only**. This document does not assert compilation, runtime correctness, successful installation or code completion of all integrations.

## Files with parallel uncommitted changes

The worktree includes uncommitted and untracked changes from multiple contributors. Use exact-path staging; do NOT run `git add -A`, reset/clean, prune, force-push, or overwrite shared changes. The inactive alternate composition source was preserved in commit `14f429f` before reducing the runtime module to types only. Do not overwrite other contributors' future changes; the physical bootstrap is now uniquely injected by the V3 environment factory.

## Deferred final-release evidence (explicitly NOT executed)

1. TypeScript typecheck/build/lint and any missing configuration or migration corrections.
2. P08 launchd installation, macOS Keychain signed heartbeat continuity and cold-start/recovery receipts.
3. Two-way Windows ↔ Mac physical execution with signed S02E consent, allowed capability, exact lease, replay protection, unknown-outcome manual reconciliation and independent S03 signed ACK.
4. F01 manifest hash verification and independent two-device Canary and reversible Rollback with health outcomes.
5. ChatGPT V3 OAuth device:execute/fleet:control authorization, tool invocation, and isolation from V2.
6. Security review, independent reviewer acceptance, official 28-component signoff and production release.

## Official metrics

The accepted baseline remains **24/28 = 85.71%**. Four gates (P08, I01, F01, AC01) remain **OPEN**. No acceptance-gate or CI verdict was changed in this coding-only turn.
