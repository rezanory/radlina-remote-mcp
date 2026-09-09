# Threat model and security acceptance

## Trust boundaries

```text
ChatGPT/client -> public TLS/Tailscale edge -> loopback HTTP auth gate -> MCP tool policy
                                                               -> filesystem/process/search
                                                               -> SQLite + DPAPI + audit chain
Local operator ------------------------------------------------> approval/kill/read-only/service control
```

The model and MCP client are untrusted request producers. The Node service is the authorization and policy boundary. Tailscale Funnel provides transport/TLS, not application authorization.

## Threats and controls

| Threat                                 | Required control                                                                                               | Verification                                                           |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| Public ingress/anonymous use           | bearer auth before MCP dispatch; HTTPS public URL                                                              | unauthenticated `/mcp` returns 401; Funnel only after local green      |
| OAuth compromise                       | PKCE S256, exact registered redirect URI, short token TTL, rotating refresh tokens, revocation, local approval | positive flow, replayed refresh rejection, issuer/audience/scope tests |
| CSRF/session fixation/replay           | opaque request IDs, OAuth state, one-time codes, hashed stored tokens, idempotency keys                        | OAuth and concurrent idempotency tests                                 |
| Confused deputy/prompt injection       | per-tool scope and workspace profile enforced server-side                                                      | negative scope integration test; policy tests                          |
| Command/argument injection             | exact executable path, argument regex allowlist, `shell:false`, bounded args/env                               | default command list empty; process integration test                   |
| Path traversal/ADS/UNC/device names    | lexical rejection plus canonical existing-ancestor resolution                                                  | adversarial path tests                                                 |
| Symlink/junction escape                | realpath containment and recursive link rejection for directory copy                                           | junction escape/copy test                                              |
| TOCTOU                                 | canonical resolve repeated immediately before mutations; atomic write staging                                  | filesystem tests; residual race documented below                       |
| Arbitrary file disclosure              | explicit roots, byte limits, caller scopes                                                                     | path and policy tests                                                  |
| Secret leakage                         | redact keys/value patterns before append; never audit file/process input content                               | redaction test and repository secret scan                              |
| Privilege escalation/persistence abuse | low-privilege service user; never SYSTEM/admin; loopback binding; direct inbound firewall block                | service XML/install checks; manual service-account evidence required   |
| Denial of service                      | request/body/rate/concurrency/session/runtime/output/page limits                                               | schema, rate, and bounded job tests                                    |
| PID reuse/process-tree confusion       | PID + start time + executable identity; fail closed if identity differs                                        | process manager test; forced termination requires admin                |
| Audit tampering                        | serialized HMAC chain, DPAPI key, rotation linkage, startup verification                                       | concurrent-chain and tamper tests                                      |
| SSRF                                   | no general network-fetch tool; external issuer URL is local configuration only                                 | tool inventory review                                                  |
| Dependency compromise                  | exact npm lock, pinned runtime URLs/SHA-256, SBOM/audit/license inventory                                      | release validation artifacts                                           |
| Malicious repository content           | no shell; no command enabled by default; path boundaries remain authoritative                                  | default config review                                                  |
| Network/sleep interruption             | durable process/search rows and cursors; HTTP sessions are reconnectable/stateless                             | reconnect/restart evidence before PASS                                 |

## Residual risks

- A local user who can edit the installed source/config can alter future service behavior. ACL verification is required during service installation.
- Filesystem operations cannot make arbitrary multi-file workflows transactional. Each individual write is atomic; callers must use idempotency keys and verification hashes.
- WinSW 2.12.0's official x64 asset is not Authenticode-signed and upstream publishes no checksum. The build pins its observed SHA-256 plus official release URL and signed release-tag commit. This provenance limitation must remain visible in acceptance evidence.
- A single laptop is still one failure domain. Tailscale supplies multiple edge/relay addresses behind one DNS name, but not a second device containing the same state.
