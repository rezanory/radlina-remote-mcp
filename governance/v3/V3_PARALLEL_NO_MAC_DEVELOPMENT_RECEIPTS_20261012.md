# V3 Final Four — bounded parallel work without an online Mac

Date: 2026-10-12
Repository: `rezanory/radlina-remote-mcp`
Source before this slice: `779c880498186a398fa1246283739f9c5e7b8ed3`
Branch: `feature/v3-final4-composition-20261012`
Worktree: `E:\radlina-remote-mcp-worktrees\v3-final4-composition-20261012`
Scope: Stage 4 (I01 code-level recovery), Stage 5 (S03 source/test), Stage 6 (F01 journals), Stage 7 (MCP OAuth discovery and tool metadata). **No physical two-device operation.**

## Input → Runtime → Execution → Output → Acceptance evidence

### Stage 5 / S03 lost signed ACK

- **Input:** existing `S03ExternalAuditClient.submit`; exact Mac witness `POST /api/v1/anchor/lookup` authenticated read-only recovery endpoint.
- **Identified defect:** if an append returned HTTP 201 but the response-body `arrayBuffer()` then failed due to a disconnect, the original handler did not retrieve the persisted original ACK. This left a preventable UNKNOWN despite the witness already possibly appending.
- **Code change:** factor `recoverOriginal()` to make one authenticated lookup of the original immutable request hash and HMAC. On HTTP >=500 / fetch failure or HTTP 201 body-read failure, **never re-POST the mutating anchor**, and require a valid persisted, independently Ed25519-signed lookup response. Reject invalid signature, oversized ACK, second body-read failure and missing lookup.
- **Execution:** `tests/unit/v3/s03-external-ack-recovery.test.ts`, five isolated tests using explicitly ephemeral test-only Ed25519 keys and a stub fetch; no live Mac, no actual witness identity or production secret.
- **Output:** 5/5 PASS (`dbffdc07-337d-4ed9-a5bd-685ab1129eee`). Covered exact good ACK, 5xx→lookup, HTTP 201 response-body loss→lookup, missing 404 lookup, altered signed ACK rejection.
- **Acceptance:** **source/test slice PASS only**; the physical S03 witness and cross-device MAC credentials remain unverified.

### Stage 4 I01 / Stage 6 F01 persistent journals

- **Input:** production I01 `I01DurableDispatchJournal` and F01 `F01PhysicalDispatchJournal` code, exercised against disposable SQLite files.
- **Execution:** new `tests/unit/v3/final4-journal-reconciliation.test.ts` with four tests: I01 duplicate blocked while pending/uncertain and conflicting hashes denied; I01 manual completion only once from UNKNOWN; F01 original native switch receipt identity preserved and replay blocked; F01 manual ACK anchoring is single-CAS and cannot become automatic rollout continuation.
- **Output:** 4/4 PASS in focused run and in full V3 suite.
- **Acceptance:** no Mac command, Canary/Rollback, native mutation or independent reviewer acceptance was performed.

### Stage 7 OAuth/MCP conformance

- **Input:** V3 official OAuth issuer `https://v3-mcp.radlina.com`, independent localhost test MCP server, eight actual `server.registerTool()` calls in `final4-mcp-surface.ts`.
- **Defect fixed:** `get_capabilities` declared only six of the eight registered Final Four tools, omitting `v3_exact_device_reconcile` and `v3_fleet_reconcile`.
- **Code change:** one exported `V3_FINAL4_MCP_TOOL_NAMES` contract shared by registration metadata and physical-port-gated capability discovery.
- **Security preserved:** `device:execute` and `fleet:control` remain restricted to the exact production V3 issuer by `AuthService`; read-only instances do not advertise them. Test discovery uses issuer-scoped metadata but serves all OAuth requests locally, with deliberately NONEXECUTABLE test-only physical port fixtures and no production bearer token.
- **Execution:** `tests/unit/v3/final4-mcp-discovery.test.ts` exercised actual PKCE OAuth client, MCP `tools/list`, and `get_capabilities`, ensuring all eight declared Final Four tools align with registration.
- **Output:** 1/1 PASS (`29716aa8-f0bd-4795-adb5-f322d82294be`). Existing read-only OAuth regression also PASS.
- **External read-only HTTPS check:** `scripts/operations/v3-chatgpt-oauth-discovery-conformance.ps1` returned 13/13 PASS, `PASS_CHATGPT_OAUTH_DISCOVERY_ONLY`, session `560df247-5ec5-46c0-ab29-79e476111027`. Checks exact OAuth issuer/resource, PKCE S256, public client, forbidden admin scope, anonymous 401 challenge, resource metadata and endpoint origin. It explicitly returned `production_ready=false` and `chatgpt_app_connected=false` as acceptance fields.
- **Actual installed ChatGPT V3 connector:** connected successfully; `get_capabilities` reported `oauth-scoped-local-windows` with four read-only tools plus two Windows file tools; it does **not** yet expose the eight new Final Four tools. Actual `v3_admin_status`: `productionReady=false`, `remoteExecutionEnabled=false`, `deviceCount=2`, local Windows files and Mac signed-heartbeat ingress enabled. Actual V3 registry: `macbook-main` exists and trust state is `trusted`, but status `unknown` and heartbeat stale; `windows-main` is online with a fresh heartbeat but `health=degraded`. **Plugin installed ≠ new server runtime deployed.**
- **Acceptance:** discovery and source/tool metadata slice PASS; AC01 native owner OAuth and physical end-to-end remain PENDING.

### Broad regression evidence

- Full `vitest run tests/unit/v3 tests/integration/v3-control-plane-mcp.test.ts --maxWorkers=3`: **40 test files PASS, 219 tests PASS / 219**, session `6b09711d-9f41-4a21-a9e6-697d023fab36`, exitCode 0.
- Full `tsc -p tsconfig.json --noEmit`: **PASS exitCode 0**, session `08493d6c-4cab-498d-8271-4c2f98f9f6aa`.
- Full `tsc -p tsconfig.json`: **PASS exitCode 0**, session `8ab3c128-e310-4a86-97fc-253f48b7f2d4`.
- Full ESLint `eslint .`: **PASS exitCode 0**, session `74532627-e2b9-46ab-a7a5-7e892fd109ba` (zero errors).
- Untracked independent `cloudflare/` contents not edited, staged or deleted. No V2 changes, no active V3 WinSW replacement, no real Mac network execution, no generated provider secrets.

## Remaining boundaries and next authorized dependencies

- P08 must obtain a new actual Mac signed heartbeat from the enrolled physical agent. Independent owner/key and live Mac P03 validation are still required.
- Stage 2 Mac installer, LaunchAgents and physical Mac S03 witness cannot be activated while the Mac is offline; Windows owner installation still needs the actual interactive Windows owner and approved immutable config, not SYSTEM impersonation.
- S03 physical durable witness and exact lost-ACK retrieval against real Mac S03 must be checked once separate Keychain/bearer/HMAC provisioning and Mac connectivity exist. Test-only signatures never qualify.
- I01 must still run original exact cross-device capability under recipient-local S02E consent in both directions. Journal tests do not qualify.
- F01 must still execute a real two-host Canary and Rollback with S03 receipt and independent decision. Journal tests do not qualify.
- AC01 must verify native ChatGPT OAuth with independently scoped owner token, complete physical tool list, actual actions/denials and reviewer acceptance. Do not enable final-four privileged scopes while physical ports remain absent.
- **Official accepted V3 components remain 24/28 = 85.71%; do not close any of the four gates using only these source/test results.**
