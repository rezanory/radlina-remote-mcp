# V3 process no-repeat enforcement (staged candidate)

**Scope:** V3 branch `feature/v3-no-repeat-process-guard-20261019`. This does **not** modify V2, install a local update, bypass a permission, or certify G012. No live MCP deployment was performed during authoring.

## Design

The existing authenticated MCP `start_process` tool now accepts a bounded `repeatGuard` object. Before any child process or output log is created, the ProcessManager:

1. Applies the **existing** authentication, scope, executable allowlist, workspace resolver, environment allowlist and session-limit checks.
2. Recognizes test commands (pytest, unittest, Vitest, Jest, `manage.py test`, npm/pnpm test, Go test).
3. When `policy.requireRepeatGuardForTestCommands: true`, rejects matching test commands without `repeatGuard`. Default is **false** to keep existing V3 installations unchanged until explicit rollout.
4. Resolves `candidateFiles` and `stateFiles` using the original workspace-safe resolver; requires 1–16 files in each set, a maximum 1 MiB per file / 4 MiB per set, and reads the content to compute server-side SHA-256.
5. Atomically inserts one SQLite claim keyed by authenticated subject + profile + full command digest + source-file digest + relevant state-file digest. Changing gate, operation, error code, or MCP idempotency key does **not** change identity.
6. Rejects an unchanged claim with a `CONFLICT` MCP tool error **before spawning a process**. Missing/invalid evidence fails closed. Unknown previous execution is never silently retried or cleared.

Claim records contain only hashes, gate string and a timestamp; never raw command arguments, file contents or credentials. The existing audit remains authoritative for policy/scope decisions.

## Explicit V3 activation (not yet deployed)

In the **V3-only** current config, after completing the required native build/regressions and confirming no unrelated executor depends on unguarded validation commands, set:

```yaml
policy:
  requireRepeatGuardForTestCommands: true
```

Preserve all other current policy and credentials. Do not replace the whole existing config with this snippet. Then use the existing MCP `start_process` with normal explicit owner-scoped arguments plus:

```json
{
  "repeatGuard": {
    "gate": "G012",
    "operation": "native_pg_settlement",
    "errorCode": "W01_MISSING",
    "candidateFiles": ["C:\\path\\within\\authorized-root\\source.py"],
    "stateFiles": ["C:\\path\\within\\authorized-root\\current-state.json"]
  }
}
```

The paths above are documentation placeholders and must be replaced with actual existing evidence files. Use stable, authoritative evidence: don't include run IDs, timestamps, generated test logs or volatile heartbeats just to generate a different fingerprint.

## Limitations

- This applies to **process launches through this V3 service only**; GitHub, Remote Desktop Commander, preexisting V2, ChatGPT tool dispatch or other executors are not globally intercepted.
- Recognition is intentionally narrow. Generic scripts, migration commands and diagnostic reads are not automatically classed as tests.
- The guard does not enforce correctness of a user-designated state file. Owners must choose a relevant authoritative state, not a synthetic changed fixture.
- A legitimate required revalidation following changed code/state is allowed; final product acceptance still requires real stack proof.
- Existing SQLite claim rows remain across restart. Recovery of an unknown or interrupted original operation must inspect durable sessions and evidence first; never delete claims to make a retry green.

## Test and acceptance

Unit tests: `tests/unit/process-repeat-guard.test.ts`, covering same-state denial, source/state changes, distinct subjects, relabeling denial, malformed/missing evidence and narrow validation command classification.

A focused, isolated TypeScript + real SQLite local harness passed 7/7 checks. **Not yet proved:** full V3 native Windows typecheck, security/integration suite, actual authenticated MCP request through deployed `start_process`, and restart persistence in the original Windows service. Those gates remain OPEN.
