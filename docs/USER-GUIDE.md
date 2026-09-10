# User guide

## Workspace profiles

Edit only `config\local.yaml`. Each profile has explicit absolute Windows roots, an executable allowlist, optional environment-variable names, and a recoverable-trash switch. The shipped example exposes only `C:\radlina-remote-mcp`, allows no commands, does not invoke a shell, and disables trash.

When `allowShell` is false, an executable rule matches the normalized absolute executable path and every argument must match an allowed regular expression. When the machine owner explicitly enables trusted-owner mode, `allowShell: true` means direct executable access even if `commands` is empty. Process creation still uses `shell:false`; NUL/oversized arguments, unapproved environment variables, missing scopes, kill/read-only state, and audit failures remain denied. Only enable this mode on the owner-controlled workstation.

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

`admin` does not bypass path validation, bounded limits, session ownership, kill-switch, or emergency-read-only controls. Trusted-owner mode intentionally bypasses only the executable allowlist and expands the configured filesystem root to `C:\`.

## Persistent owner authorization

The internal issuer advertises `offline_access`, rotates seven-day refresh tokens, and accepts retry/concurrent replay of the same refresh token for only the configured short grace period. The first OAuth authorization for a registered client still requires local approval. That approval enrolls the exact client ID, redirect URI, MCP resource, subject, and approved scope set. Later authorization requests are automatic only for that same relationship and a subset of those scopes; a new client, redirect, resource, or scope escalation requires another local approval.

List or revoke durable owner enrollments locally:

```powershell
& .\.runtime\node-v24.20.0-win-x64\node.exe .\dist\src\cli\control.js owner-trust list
& .\.runtime\node-v24.20.0-win-x64\node.exe .\dist\src\cli\control.js owner-trust revoke <enrollment-id>
```

Revocation disables automatic authorization and removes outstanding refresh sessions, authorization codes, and approvals for that client. Access tokens remain bounded by their one-hour expiry and may also be revoked individually through the OAuth revocation endpoint. No raw authorization code, access token, or refresh token is stored in SQLite or OAuth telemetry.

## Reconnect and recovery

Search and process identifiers are durable and owner-bound. Output/result cursors can be resumed after client reconnect. After a service restart, completed logs remain readable; live search rows become `interrupted`, and process rows are reconciled using PID, start time, and executable identity. Interactive stdin cannot be recovered across a service restart.

Mutation keys are stored durably. A completed retry returns the prior result. If the service crashed after claiming a mutation but before recording its result, the key is blocked as an unknown outcome until it is reviewed locally. This favors at-most-once execution over automatic duplication.

## Availability

Configure ChatGPT with the canonical HTTPS hostname, never an IP address. Multiple A/AAAA addresses returned by Tailscale are transport details. A second server would require replicated policy/state, exclusive process-session ownership, audit-chain fan-in, and fencing before it could safely share the hostname.
