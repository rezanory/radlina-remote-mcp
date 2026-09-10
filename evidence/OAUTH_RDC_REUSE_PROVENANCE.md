# OAuth and remote-session reference provenance

Review date: 2026-09-10

Radlina remains a standalone product. No runtime, database, startup, release, recovery, or monitoring dependency on either reviewed project or any external supervisor was introduced.

## DesktopCommanderMCP

- Repository: `wonderwhy-er/DesktopCommanderMCP`
- Reviewed commit: `a781f5a4b8cfebac6638bc6fcbd38fca6326be53`
- License: MIT
- Reviewed paths: `src/remote-device/device.ts`, `src/remote-device/device-authenticator.ts`, `src/remote-device/remote-channel.ts`, `src/remote-device/desktop-commander-integration.ts`, and `src/npm-scripts/remote.ts`
- Decision: behavioral reference only; no source code was copied.
- Adapted concepts: durable enrollment/session identity, validation of persisted state before reuse, bounded reconnect/backoff, explicit health state, half-open connection detection, clock-skew awareness, and request deduplication.
- Radlina fit: persistent owner enrollment is bound to the exact registered OAuth client, redirect URI, MCP resource, and a subset of locally approved scopes. OAuth refresh state stays in Radlina's own SQLite/DPAPI implementation, while process/search session persistence remains independent and owner-bound.
- Security review: rejected environment-controlled remote endpoints and any pattern that could enable SSRF or credential forwarding; rejected false-health behavior that reports transport success while command execution is unavailable; rejected unbounded reconnect loops, stale session reuse without revalidation, shell-history leakage, and shell-redirection bypasses.
- Maintenance decision: use upstream only as a periodically reviewed behavioral reference. Radlina owns its implementation and tests.

## remote-desktop-commander

- Repository: `desktop-commander/remote-desktop-commander`
- Reviewed commit: `b480501dcca59f802ebaf97f2f57b45252d0b720`
- License/availability: repository documentation, manifests, and brand assets are not an open-source implementation of the hosted backend; the backend is proprietary/not present.
- Reviewed paths: `README.md` and `docs/SETUP.md`
- Decision: documentation reference only; no source or assets were copied or adapted.
- Relevant concepts reviewed: one-time device pairing, OAuth client authorization, dashboard revocation, and online/last-seen state.
- Security and fit decision: Radlina does not depend on the hosted service, does not share state with it, and does not inherit its trust model. The only retained product-level idea is that a previously approved device/client relationship may be durable and explicitly revocable.

## Known upstream failure patterns reviewed and rejected

- `wonderwhy-er/DesktopCommanderMCP#594`: unsafe configurable remote endpoint / SSRF and token-forwarding risk.
- `wonderwhy-er/DesktopCommanderMCP#661`: persisted session present while reauthentication or shell failure still occurs, creating a false-healthy state.
- `wonderwhy-er/DesktopCommanderMCP#406` and `#410`: history exposure, SSRF, REPL/shell bypass, and redirection risks.

Radlina's acceptance therefore requires exact OAuth health, token rotation/replay tests, secret scans, durable restart tests, executable policy tests, self-upgrade/rollback validation, and live production verification. Upstream availability is not required after completion.
