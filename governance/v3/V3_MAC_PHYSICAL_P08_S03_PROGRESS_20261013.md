# V3 physical Mac P08/S03 receipts and native release boundary — 2026-10-13

Repo: rezanory/radlina-remote-mcp
Device: macbook-main / amirs-MacBook-Pro.local (x86_64, Node v24.20.0)
This is bounded real-execution evidence, not a claim of 28/28 release acceptance.
Official final-four gates P08/I01/F01/AC01 remain pending reviewer acceptance.

## P08 — real physical identity and persistent heartbeat

- GitHub owner-gated physical Mac read-only run **38378019206: PASS**. Exact runner radlina-macbook-main, macOS/x86_64/Node v24.20.0, real Tailscale rezanory.github Running and Windows peer visible.
- P03 real Mac dedicated Keychain signed-heartbeat run **38378208695: PASS**; pinned P03 Ed25519 fingerprint `f2c2e93ff120fbc5122cbb6b5a0b461a072f54bd8d226368c858fd0bd17037ea`; actual tailnet node hash `c7886ac103d4c05907ff8953ae60687d31303146a9b122cb55bff0dc1860bc9c`. Independent P03 Windows owner admission of a new, timely `38378659028` Mac-signed artifact **PASS** at physical signed age 54,197 ms; exact evidence response `REAL_MAC_P03_TRUSTED_LIVE_SIGNED_HEARTBEAT_PASS`, on Windows V3 registry: trusted/online/healthy, Ed25519 signature valid, Tailnet match and audit chain valid. This is NOT persistent sender proof.
- Owner-gated P08 persistent installer workflow PR **#16** merged; immutable installer source pin PR **#17** merged due GitHub protected environment requiring default branch; actual install run **38380095566: PASS**, created LaunchAgent `com.radlina.remote-mcp.v3.mac-heartbeat` in `gui/501`, pinned signer source `de625477bbbc60d37adcc690c082df53fe5e6d6f`. No V2 changes.
- Initial launchctl runtime FAILED: read-only diagnosis run **38380660351** observed 6 runs, last exit code 1, no ACK/events; bounded native-log diagnostics PRs #18–20, physical run **38383168101** found `Error: Transform failed with 2 errors`. Cause: copied TypeScript sender outside package module context had two unsupported top-level awaits under TSX CommonJS.
- Owner-gated P08 scoped ESM module context repair PR **#21** merged; run **38383770848: PASS**, no sender replacement and no key export, exact installed-script/pinned-source/plist/permissions verification, added 0600 `package.json` with private module type and kickstarted only P08 LaunchAgent.
- Independent post-repair macOS diagnosis run **38383941963: PASS**: launchctl total 44 runs, **last exit code 0**; two independently observed P08 signed gateway ACCEPTED deliveries at **2026-10-13T10:30:26.179Z** and **2026-10-13T10:31:15.970Z**; `heartbeat-latest-ack.json` present and 20,061 ms old; actual gateway ACK `V3_P08_REAL_MAC_SIGNED_HEARTBEAT_ACCEPTED`. Actual ChatGPT V3 plugin registry also confirmed trusted/online/healthy and fresh heartbeat after repair.
- Independent P08 reviewer restart/TTL acceptance and Final Four native routing are NOT established just by two good intervals.

## S03 — independent genuine physical Mac public identity

- Owner-gated dedicated physical macOS S03 Keychain public identity preparation workflow PR **#22** merged; real run **38384502815: PASS**, exports ONLY public receipt artifact `v3-s03-mac-public-only-38384502815`, no private key export, no S03 writer daemon or production credentials.
- Public receipt downloaded to isolated Windows V3 ingress under `E:\\radlina-v3-oauth-standalone\\p03-inbound\\s03-public-only-38384502815\\witness-public-receipt.json`. Independent Windows Node `crypto.createPublicKey()` validation **PASS**: Ed25519, SPKI DER SHA256 exactly `32f04e1a18f49fffd5111b98d70dc1f157326a356df3834f8c34b4d2bc7a2238`, different from P03 key, privateKeyExported false. Witness identity remains in actual separate Mac Keychain.
- S03 public identity is NOT a signed external witness append ACK. Separate owner-approved S03 policy, reviewer public key, valid writer bearer/HMAC Keychain entries, secure tunnel and live Mac installation are still required.

## Native Mac Final Four release packaging

- Source helper `scripts/operations/v3-final4-stage-mac-release.mjs` commit **dfbabeca64527b405fd9c35c42be74cf6c9dfea3**. It verifies real Mac identity, immutable Git SHA, 0700 V3-only state, source release and source SHA, native built agents/tsx, manifests, all-file hashes, rejects unsafe symlinks and cannot start V2, Keychain or final-four agents.
- Owner-gated isolated native Mac package workflow PR **#23** merged. Physical run **38385684139: FAIL** after Mac npm ci 488 packages + TypeScript compile; explicit reason nested npm CLI symlink `node_modules/@modelcontextprotocol/inspector/node_modules/.bin/vite`. Fail-closed source-only staging; no service changed.
- Fix commit **48f2c4a01adc365840a96b687717ddb34984d2ef** excludes ONLY nested npm `.bin` command-launcher folders from self-contained runtime manifest; all other symlinks still disallowed. Owner-gated workflow exact source pin updated via PR **#24** merged.
- Second physical stage run **38386390336**: **QUEUED / no final outcome observed** at last check. GitHub runner `radlina-macbook-main` was **Offline**, Tailscale Mac peer `Online=false`, and active ChatGPT V3 registry Mac heartbeat again stale/unknown. **Do not claim the native Mac release exists or passed verifier**; do not delete/rename a partial candidate. Recheck actual runner and workflow outcome on restoration.
- Mac Final Four Operator/Fleet/S03 LaunchAgent installer has NOT been run. No exact owner-approved Final Four policy, physical S03 writer secrets or S03 reviewer attestation has been fabricated.

## Last known Windows and V3 safety state

- Windows independent V3 OAuth/Tunnel 16/16 operational PASS; exact active Windows V3 Release Manifest `934cd1627f57b0c01e1fe9058524c8eb8b1af83a51671c04b1856c5d2a9039ec` / Git source `92c0cb40dcec0187c8c797633e1a1f88ec048f15`, 16,710 verified files, isolated and deployed to V3-only WinSW. V2 service and independent V3 tunnel preserved.
- Windows Final Four owner signing / recipient / fleet scheduled tasks NOT installed; immutable owner config, real authorized ChatGPT OAuth client policy, independent reviewer Ed25519 key and Mac S03 witness + writer credentials required. Do not run the Windows installer under NT AUTHORITY\\SYSTEM impersonating interactive owner `LAPTOP-13QINEIF\\Radlina`.
- Last actual ChatGPT plugin V3 `v3_admin_status`: `productionReady=false`, `remoteExecutionEnabled=false`, `finalFourPortsBound=false`, despite trusted P03 registry, public OAuth and independent Windows file tools.
- Preserve V2, peers, VPN and Tailscale. Do not reset/clean/prune/force-push, generate fake reviewer/owner tokens or conflate P08 Source/Heartbeat success with independent official acceptance.

## Immediate next verified actions

1. Restore macOS runner + Tailscale connectivity; check `38386390336` terminal outcome, actual immutable native Mac manifest and all-file verifier. Only if real staging PASS continue Mac owner-scoped install preflight.
2. Prepare legitimate owner-signed final-four production binding from actual owner Principal, approved ChatGPT OAuth client IDs, real independent reviewer public key, and freshly prepared separate S03 public witness identity. No substitute identities.
3. Verify real S03 writer bearer/HMAC Keychain presence via bounded boolean checks, never print/export secrets; install Mac Operator/Fleet/S03 only with real policy, then genuine Windows owner Tasks.
4. Conduct I01 and F01 physical acceptance on both devices with original ACK and independent reviewer; AC01 OAuth physical tools/permissions. Official accepted gates remain **24/28 = 85.71%** until independent sign-off.
