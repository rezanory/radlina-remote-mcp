# V3 continuation — actual Windows trust, remaining two-host acceptance

Windows `windows-main` was admitted in the actual SQLite registry consumed by the connected independent ChatGPT V3 plugin. P03 verified two Ed25519 signatures over the same fresh challenge: a dedicated Windows device key protected with LocalMachine DPAPI and private SYSTEM/Administrators ACLs, and an independent owner key protected with CurrentUser DPAPI under the existing authenticated local Radlina account.

The authenticated V2 MCP subject was matched to the actual interactive Windows account and its SID. Owner bootstrap and signing ran using that account's existing interactive token, without collecting credentials. The SYSTEM-context owner-signer negative check failed as required. The two temporary signing tasks finished with result 0 and were removed. The owner private key remains in the owner's protected profile; the service never exported or logged it.

Windows trust is **Trusted**, but health is **Unknown**, status **Degraded**. A newly signed degraded heartbeat was accepted and replay denied. The P03 local hash-chain audit verified. No healthy transport, target execution consent, or external distributed-audit anchor is implied by enrollment.

## Reproducible checks

From the isolated E: worktree, use Node 24.20.0 and the installed locked dependencies:

- Typecheck: `node node_modules/typescript/bin/tsc -p tsconfig.json --noEmit`
- V3 unit and MCP integration: `node node_modules/vitest/vitest.mjs run tests/unit/v3 tests/integration/v3`
- Disposable-key real DPAPI/ACL negative checks: `node --import tsx scripts/acceptance/v3-windows-identity-negatives.ts` (use a new receipt output filename for repeated evidence runs).
- Fleet isolated exercise: `node --import tsx scripts/acceptance/v3-f01-fleet-local.ts`. Device ports and consent in this exercise are **synthetic**, never a real two-device rollout.
- Native ChatGPT V3 `list_devices` confirms the authoritative trust and degraded status; `v3_admin_status` still reports productionReady=false and remoteExecutionEnabled=false.

The preliminary storage-negative receipt predates the disposable-key reproducer; the isolated-key receipt is the recommended reproducible check. Do not copy a production identity ciphertext for ACL fault tests.

## Existing F01 hardening reused

PR #5 source commit `11789c06d2924132c00014e05e25e4c0dd07ff0e` is cherry-picked into this isolated candidate. Unknown activation outcome, missing signed switch receipt, and invalid receipt hold the target for reconciliation instead of automatically retrying or rolling back. The actual two-host rollout remains prohibited until trusted identities, valid S02E target consent, and S03 audit are available.

## Remaining acceptance

1. The actual Mac runner `radlina-macbook-main`, ID 21, was repeatedly observed Offline. A fresh Mac challenge response cannot be obtained through that runner while offline. Existing historical signatures do not substitute for a fresh challenge.
2. Obtain the real Mac response, use the independent owner signer and Windows-observed live peer pin, admit Mac through P03, and apply a fresh signed heartbeat.
3. Connect persistent native Windows/macOS agents and authenticated transport; prove real health and exact destination routing.
4. Enforce target-local S02E and externally anchored S03 for operations.
5. Execute real signed V3 manifest staging, Mac canary, Windows rollout, two-host isolated V3 rollback and recovery.
6. Integrate executable OAuth capabilities and verify them through the separate ChatGPT V3 plugin; close AC01 only after genuine operational and security acceptance.

Official accepted components remain **24/28 = 85.71%**. P08, F01, I01, AC01 remain OPEN. V2 `2.0.0-alpha.2`, manifest `6dde7ef6d4d56ff81f630432a4b70171beaf780bdffe5525fa85973fe255aa1e`, stays active and unchanged. No change was made to main or the canonical V3 branch.
