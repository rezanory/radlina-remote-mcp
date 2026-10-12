# Radlina Remote MCP V3 — Seven-stage Operational Preparation / Stage 01

**Date:** 2026-10-12
**Target:** `rezanory/radlina-remote-mcp`, `feature/v3-final4-composition-20261012`, Draft PR #15
**Source checkpoint before repair:** `9c72fc8d7a8b387e7db589da737c689b41f6c4df`
**Canonical working root:** `E:\radlina-remote-mcp-worktrees\v3-final4-composition-20261012`
**Scope:** Typecheck, Build, Lint and evidence of repaired source. NO deployment.

## Input → runtime → execution → output → acceptance

1. **Input:** exact owner V3 worktree, unchanged historical V2, committed TypeScript project and existing `node_modules`. Git preflight: `feature/v3-final4-composition-20261012`; only unrelated untracked `cloudflare/` present, explicitly preserved.
2. **Runtime:** authenticated Radlina Remote Full MCP Windows `LAPTOP-13QINEIF`; Node executable `C:\Program Files\nodejs\node.exe` invoked through authenticated, reconnectable process sessions. The MCP server did not expose `node` or `npm` on its inherited PATH; using the exact executable resolved this without global PATH changes.
3. **Execution:** official equivalent of `npm run typecheck`, `npm run build`, `npm run lint`, via direct installed TypeScript / ESLint CLI below:

   ```text
   "C:\Program Files\nodejs\node.exe" node_modules\typescript\bin\tsc -p tsconfig.json --noEmit
   "C:\Program Files\nodejs\node.exe" node_modules\typescript\bin\tsc -p tsconfig.json
   "C:\Program Files\nodejs\node.exe" node_modules\eslint\bin\eslint.js .
   git diff --check
   ```

4. **Initial findings:** Typecheck detected two V3 incompatibilities: F01 `signedReply` property mismatch and a Windows I01 approval `schema` type; one additional F01 `unknown` payload type mismatch became visible after the first fixes. Initial ESLint found 30 errors: V3 operational scripts omitted from TypeScript project, unrelated untracked Cloudflare draft, unused symbols, redundant assertions, one unsafe owner policy `JSON.parse` and a redundant rethrow.
5. **Source repairs:** exact recipient result shape reconciled, F01 unknown payload checked structurally, Windows/Mac approval objects contextually typed against the formal approval message contract, five tracked V3 operation scripts included in `tsconfig.json`, untracked `cloudflare/**` excluded from type-checked lint **without modifying the directory**, unused imports/assertions and redundant catch removed, owner subject validated via already-verified `origins.isAuthorizedOwnerSubject`. No TypeScript/ESLint rules disabled for tracked V3 runtime.
6. **Final outputs:**
   - Typecheck session `3df4dcdb-2c5a-441a-afd5-bb38dfaf6dbb`: **exitCode 0; PASS**.
   - Build session `e3938026-3264-4898-9fc3-0a3e6302fa67`: **exitCode 0; PASS**.
   - ESLint session `5c9ba877-f71e-4a60-be3f-f34568f2f044`: **exitCode 0; PASS**.
   - `git diff --check` session `2102ed1e-6034-4c18-80c9-9080d329a5d5`: **exitCode 0; PASS** (Windows checkout shows line-ending warnings, not failures).
   - Emitted E:-only files exist: `dist/src/v3/fleet/native-switch-journal.js`, `dist/src/v3/integration/i01-secured-dispatch.js`, `dist/scripts/operations/v3-final4-native-switch-reconcile.js`, `dist/scripts/operations/v3-mac-heartbeat-sender.js`.
7. **Acceptance rule for Stage 01:** 4/4 engineering preparation checks above pass with machine-observed zero exit status and on-disk build products. Stage 01 source/build/lint checklist can be marked **100%** once this evidence and exact scoped code changes are committed and pushed. This is NOT the four final operational gates.

## Explicit non-claims and stage boundaries

- No `npm test`, integration/end-to-end, actual S03 witness, release installation, Windows/Mac user action, Canary/Rollback, native ChatGPT OAuth handover, secret generation or live API action occurred. Those belong to later stages 02–07.
- V2 and peers unchanged; `cloudflare/` remains untracked and untouched; `dist` is generated/ignored.
- Official component acceptance **24/28 (85.71%) unchanged**. Green TypeScript/Lint does not prove the V3 executable will correctly operate on either physical device.
- Dependency lockfile not modified; no `npm install`, `npm audit` or project reset/clean/force-push.
- Later operational verification may find new issues; green Stage 01 does not pre-approve Stage 02–07.
