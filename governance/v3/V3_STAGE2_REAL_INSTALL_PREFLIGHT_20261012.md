# Radlina Remote MCP V3 — Stage 02 physical installation and configuration

Date: 2026-10-12
Repository: rezanory/radlina-remote-mcp
Source base: dd9727d2146fe4079b3709ad449c1ae497d02e92
Draft PR: https://github.com/rezanory/radlina-remote-mcp/pull/15
Scope: independently installed V3 Windows+Mac with V2 untouched.

## Physical preflight evidence (actual, non-secret)

| Check | Actual input → runtime → observation | Verdict |
|---|---|---|
| Windows management | Authenticated Radlina Remote Full MCP, LAPTOP-13QINEIF; ping and readiness returned OK; no kill switch | CONNECTED |
| Operating identity | Actual remote PowerShell Windows identity NT AUTHORITY\\SYSTEM, not LAPTOP-13QINEIF\\Radlina; privileged administrator=true | OWNER INSTALL PRECONDITION NOT MET |
| Existing service | SCM RadlinaV3OAuthBeta = Running and RadlinaV3Tunnel = Running | LEGACY V3 ONLINE, NOT FINAL FOUR |
| Existing V2 | SCM RadlinaRemoteMCP = Running | UNTOUCHED |
| Active V3 release | Windows WinSW workingdirectory E:\\radlina-v3-runtime\\releases\\p08-heartbeat-20261012, not a 64-char release hash; no Release Manifest and no new agent entrypoints | REQUIRES UPGRADE |
| Windows agents | Three exact new scheduled tasks RadlinaV3OwnerSigning, RadlinaV3WindowsRecipient, RadlinaV3WindowsFleet absent | NOT INSTALLED |
| Owner final-four binding | No owner-approved production binding located in expected E:\\radlina-v3-oauth-standalone path; only oauth, P03 ingress and registry found | MISSING APPROVED INPUT |
| Mac GitHub runner | `gh api repos/rezanory/radlina-remote-mcp/actions/runners` returned radlina-macbook-main macOS offline | OFFLINE |
| Mac RDC | amirs-MacBook-Pro.local offline, last seen 19h ago | OFFLINE |
| Mac Tailscale | rezanory.github online on Windows, Mac amirs-macbook-pro.taile17c9e.ts.net = offline | OFFLINE |
| Mac SSH | Explicit BatchMode ssh to amirs-MacBook-Pro.local could not resolve hostname | UNAVAILABLE |

## Source/payload preparation actually performed

- Created additional isolated **E-drive-only** Git worktree at `E:\radlina-remote-mcp-worktrees\v3-stage2-release-20261012`, with an isolated local branch `release/v3-stage2-candidate-20261012`, exact source commit `dd9727d`. No clean/reset/prune/force-push.
- `npm ci --ignore-scripts --no-audit --no-fund --prefer-offline` completed with exitCode=0, 487 packages.
- Compiled clean release snapshot via `tsc -p tsconfig.json`: exitCode=0.
- Official source-only `build-release.mjs` generated and independently verified a 418-file release candidate at `E:\radlina-v3-runtime\stage2-candidate-dd9727d`. Manifest SHA256: `64a550666d3764f08c027ce20ac450cc4d56fa5979b1e8478fafd7f2d7dc2f8a`.
- The default builder deliberately lacked compiled `dist/scripts` and `node_modules`, so the candidate is **not installable** as the new physical final-four V3 agent. A new V3-only Windows staging program `scripts/operations/v3-final4-stage-windows-release.ts` was authored to add both trees, regenerate the strict release-manifest binding and verify the complete output before atomically parking it under `E:\radlina-v3-runtime\releases\<manifest_sha>`. This is a Windows package only; it does not claim Mac runtime-compatibility or physical installation.

## Strict safety / stop reasons

1. Do **not** bypass the Windows task installer's true owner-interactive security precondition by running as SYSTEM/NETWORK SERVICE. Existing signed commands and local human consent rely on the owner token.
2. Do **not** invent the approved final-four V3 config SHA, S03 writer bearer/HMAC keys, Mac Keychain identity, signer fingerprints or reviewer signatures.
3. Do **not** run `-Install`, `-Migrate` or macOS `--upgrade` without an actual verified 64-character active/staged V3 Release Manifest and source-appropriate preconditions.
4. Mac host and GitHub self-hosted runner are offline; workflow dispatch would only queue, not execute. No automatic future installation is scheduled.
5. Do **not** touch active V3 or V2 services while the two-device install cannot complete or an independent health rollback receipt is missing.

## Scoped Stage-02 completion measurement

| Subtask | Weight | Evidence requirement |
|---|---:|---|
| Independent dual-device/readiness preflight | 15% | recorded above |
| Clean pinned build and verified base Manifest | 15% | generated candidate above |
| Complete/verify dedicated Windows runtime package | 20% | exact new all-file Manifest SHA and verifier PASS |
| Actually register three Windows owner tasks and activate final-four V3 service | 20% | true interactive owner and healthy running versioned service |
| Actually install/upgrade Mac operator, fleet, S03 witness and heartbeat | 25% | Mac online; launchctl + validated exact release |
| Re-read both service/LaunchAgent/task state after install | 5% | independently observed version hashes |
| **Total** | **100%** | **DO NOT MARK COMPLETE WITHOUT MACHINE RECEIPTS** |

## Real Windows runtime release package — VERIFIED

The first sequential 16,195-file Windows dependency hashing attempt exceeded its 300-second bounded execution window. It was reported as **TIMEOUT**, not as PASS. The original staging folder remained intact and contained all 16,195 runtime dependency files (212,507,678 bytes), with the original 418-file manifest unchanged. No native service was modified.

The independent V3-only stage tool was repaired to:
- re-check the original immutable 418-file candidate content/hash before resuming,
- reject staging changes, path escapes, reparse points or mismatched file sets,
- reuse only the exact original incomplete V3 staging folder without re-copy,
- hash 24 bounded file inputs concurrently instead of serializing 16k open/read/close operations,
- re-run the strict `verifyReleaseRoot` on **all** file bytes and atomically rename the candidate to the new exact SHA-256 release directory.

**Actual verified second execution:** `WINDOWS_RUNTIME_RELEASE_STAGED_NOT_INSTALLED` and exitCode 0.
- Exact package SHA256: `b5e7fbdf2032314a1fd2fb014f977abf653584080e8915767b95019d1afcac4f`.
- Absolute directory: `E:\\radlina-v3-runtime\\releases\\b5e7fbdf2032314a1fd2fb014f977abf653584080e8915767b95019d1afcac4f`.
- Source Git SHA: `dd9727d2146fe4079b3709ad449c1ae497d02e92`.
- Exact validated manifest file set: **16,706 files** (includes compiled agent entrypoints and independently hashed Windows runtime dependencies).
- `agentEntrypointsIncluded=true`; `selfContainedWindowsDependencies=true`; `macCompatibilityVerified=false`; `serviceChanged=false`; `v2Changed=false`.
- The source helper `scripts/operations/v3-final4-stage-windows-release.ts` was independently recompiled and linted successfully before its bounded resumed execution.
- Do **not** confuse Windows runtime verification with cross-platform Mac compatibility or a two-host F01 acceptance result.

**Weighted stage-02 preparation measurement: 50/100** = 15 preflight + 15 clean manifest + 20 complete immutable Windows runtime staging. Windows native installation 0/20, Mac actual installation 0/25, post-install comparison 0/5. No user-facing deployed-V3 success is claimed.

## Remaining unfulfilled prerequisites
- Mac `radlina-macbook-main` runner was checked again and remained **offline**.
- Physical `LAPTOP-13QINEIF\\Radlina` interactive Windows owner token is not available to this remote session (which runs as SYSTEM).
- No independently SHA-pinned owner final-four binding / S03 Keychain witness credentials are present in the expected staging locations. Those cannot be fabricated.
- Active `RadlinaV3OAuthBeta` WinSW still points to the older `p08-heartbeat-20261012` release. The full new V3 release remains parked, not activated.
- Mac-specific dependencies require a separate Mac-compatible verified stage; Windows module tree alone cannot prove native macOS loadability.
- Do not alter active V2, Tailnet, WinSW or LaunchAgents to pretend installation succeeded.

Formal V3 operational gates remain **24/28 = 85.71%** until separate physical tests and independent owner/reviewer acceptance. Stage 03–07 do not receive fictitious credit for package compilation.
