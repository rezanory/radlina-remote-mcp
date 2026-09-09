# User guide

## Workspace profiles

Edit only `config\local.yaml`. Each profile has explicit absolute Windows roots, an executable allowlist, optional environment-variable names, and a recoverable-trash switch. The shipped example exposes only `C:\radlina-remote-mcp`, allows no commands, does not invoke a shell, and disables trash.

An executable rule matches the normalized absolute executable path. Every argument must match at least one configured regular expression. Do not allow generic shells (`cmd.exe`, `powershell.exe`, `pwsh.exe`) with broad patterns. Prefer one narrow executable and anchored patterns such as `^status$`.

Validate after every edit:

```powershell
& .\.runtime\node-v24.20.0-win-x64\npm.cmd run build
& .\.runtime\node-v24.20.0-win-x64\node.exe .\dist\src\cli\diagnose.js
```

Restart the service only after validation passes.

## Scopes and risky tools

- `device:read`: health, identity, capabilities, and version.
- `filesystem:read`: bounded reads and searches inside profile roots.
- `filesystem:write`: atomic file mutations; every request needs a UUID idempotency key.
- `process:read`: process listing and caller-owned output sessions.
- `process:execute`: allowlisted process start/input/graceful termination.
- `admin`: sensitive diagnostics, effective configuration, trash, and force termination.

`admin` does not bypass path, command, size, runtime, output, session, kill-switch, or emergency-read-only controls.

## Reconnect and recovery

Search and process identifiers are durable and owner-bound. Output/result cursors can be resumed after client reconnect. After a service restart, completed logs remain readable; live search rows become `interrupted`, and process rows are reconciled using PID, start time, and executable identity. Interactive stdin cannot be recovered across a service restart.

Mutation keys are stored durably. A completed retry returns the prior result. If the service crashed after claiming a mutation but before recording its result, the key is blocked as an unknown outcome until it is reviewed locally. This favors at-most-once execution over automatic duplication.

## Availability

Configure ChatGPT with the canonical HTTPS hostname, never an IP address. Multiple A/AAAA addresses returned by Tailscale are transport details. A second server would require replicated policy/state, exclusive process-session ownership, audit-chain fan-in, and fencing before it could safely share the hostname.
