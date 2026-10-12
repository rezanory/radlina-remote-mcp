# V3 Final Four — future independent physical acceptance runbook
**Status: SOURCE-ONLY HANDOFF / NOT EXECUTED.** This file is a future checklist, not test evidence.

## Immutable safety contract
- Owner must separately authorize the operational gate after code completion; do not convert any step below into a current background or automatic action.
- Never modify or disable V2, existing VPN/Tailscale, Git peer worktrees or unrelated devices.
- Only the exact owner-pinned ChatGPT OAuth V3 issuer, local Windows and enrolled MacBook devices are in scope.
- Every live transition must produce **input → runtime → execution → output → independent acceptance** receipts. A null/timeout/unknown is NOT a PASS.
- No invented S03 witness token, public/private key, physical receipt, independent review signature or owner approval.
- Official 24/28 remains frozen until each of P08/I01/F01/AC01 has separate verified evidence.

## 0. Code-only release snapshot
- Freeze exact PR revision / commit SHA and source manifest digest; verify protected release contents and all installer/agent paths.
- Separately validate TypeScript, lint, build, dependency tree and built target entrypoints after owner authorizes testing.
- Verify V3 E: path boundaries and Mac ~/.local/share/radlina/v3-beta; isolate SQLite V3 version 1; perform authorized backup before any migration.
- Verify all three stable Mac LaunchAgent version references and Windows owner Task launcher routes point to the same intended V3 release.
- Resolve any existing native-switch sqlite phase **other than** native_start_returned using explicit owner+reviewer reconciliation; never auto-repeat a native activation.

## 1. P08 Mac persistent identity
- Input: exact owner-approved Ed25519 P03 key fingerprint, Mac hostname/architecture, signed capability policy and private Keychain.
- Runtime: registered P08 LaunchAgent starts after login; no private key export, no inbound shell.
- Execution: signed heartbeat sent to V3 TLS endpoint and admitted into shared P03 registry, with recipient fresh agentInstanceId and physically observed Tailnet peer hash.
- Output: exact signed heartbeat envelope, bounded acknowledged TLS response, local persisted signed envelope, independently verified Keychain signature and TTL.
- Acceptance: independent reviewer reconciles two runs across restart and expiry; false online and stale heartbeat fail closed.

## 2. I01 exact native Windows↔Mac
- Input: native ChatGPT OAuth client + pinned owner subject, source device, exact target/capability/input digest, S02E and target-local interactive approval.
- Runtime: both Mac and Windows operator cycles running under enrolled interactive users; no shell, no dynamic reroute or unsigned consent.
- Execution: each direction creates **one** bounded text-file operation under the approved native root, with exact requestId/idempotencyKey.
- Output: protected device-signed recipient reply persisted in SQLite BEFORE HTTP report; matching signed audit receipt and S03 independent witness ACK.
- Acceptance: signed result, target-file readback and P03 identity match, and a replay of the same id never reexecutes. Network-loss cases require **manual**, signed reconciliation, not automatic retry.

## 3. F01 two-host release Canary and Rollback
- Input: two exact verified and staged Release Manifest hashes, immutable owner rollout plan and target-local F01 human consent.
- Runtime: separate Windows owner supervisor and Mac F01 fleet LaunchAgent; no action on V2 services.
- Execution: Windows and Mac native release switches persist prepared/stopped/pointer-replaced/restart state; Mac switches every versioned operator LaunchAgent reference; Windows Tasks always resolve active verified release.
- Output: local phase SQLite, preserved original WinSW XML/plist, signed native target receipt escrow, remote S03 signed anchor, health check.
- Acceptance: owner-authorized Canary with rollback and independent service health proof. If any phase unknown, block all new rollouts until independently reconciled; do not call source code a successful physical rollback.

## 4. S03 witness and external audit
- Input: independently provisioned Mac Keychain witness key and approved bearer/HMAC files, pinned Ed25519 public key and external HTTPS endpoint.
- Runtime: S03 isolated Mac witness process and Cloudflare tunnel where authorized; never generate substitute secrets.
- Execution: I01/F01 immutable record hashes appended with exact idempotency and MAC; witness returns Ed25519-signed ACK.
- Output: chain index, previous hash, record hash and witnessed signature; requester must verify key fingerprint and exact hash.
- Acceptance: independent witness store and caller ledger show the identical hash sequence, and lost ACK is resolved by retrieving original signed proof without minting local success.

## 5. AC01 native ChatGPT MCP surface
- Input: exact connected V3 ChatGPT OAuth client, approved source device and scoped bearer token.
- Runtime: final-four physical bootstrap is the only composition; shared registry, exact signed Mac policy and independent S03 secrets.
- Execution: call get_capabilities, list_devices, get_device on each device, v3_consent_request, v3_exact_device_execute, fleet_plan/run and v3_release_acceptance_status under independent permission scopes.
- Output: consistent tool metadata, actual results or explicit denial, audit IDs and authorized owner/reviewer decisions.
- Acceptance: independent reviewer confirms four final gates separately; no acceptance is inferred from status, tests, source count, successful OAuth metadata or local-only simulation.

## Failure path matrix
| Failure | Expected safe behavior |
|---|---|
| Tailnet source/target mismatch | fail-closed; no native execution |
| Expired P08 capability policy | deny privileged operation; no silent permission refresh |
| I01/F01 recipient local denial | no execute/switch; persistent denial |
| HTTP ACK lost after target execution | preserve signed target receipt; mark unknown; no native retry |
| S03 unreachable or mismatched Ed25519 signature | do not anchor success; keep pending/manual reconciliation |
| Native switch interrupted after service stop | journal uncertain; preserve old manifest/plist/XML; no automatic follow-up |
| Existing Windows Task without exact owner hash | deny migration; preserve original task |
| Official reviewer signature absent | acceptance gate stays PENDING |

## Evidence format for later authorized run
Each gate receipt must include:
- input sha256, source commit sha, trusted owner/signer fingerprint, target P03 device id
- runtime PID/hostname/agent instance and signed time window
- exact action, native logs, SQLite sequence/hash and sealed command ID
- observed output, signed recipient response, S03 witness anchor and health result
- owner approval and independent reviewer decision with precise timestamp
- PASS/FAIL/UNKNOWN; never convert UNKNOWN to PASS or call CODE COMPLETE "Production Ready"
