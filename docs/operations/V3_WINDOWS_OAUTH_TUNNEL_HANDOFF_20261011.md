# Radlina V3 — Windows OAuth beta and Cloudflare Tunnel handoff

## Superseding operational update — 2026-10-11

V3 Tunnel and public HTTPS have ALREADY been activated and verified. Do not repeat the older token provisioning steps below. The current service reads a protected token file from E:\radlina-v3-runtime\secrets\cloudflared.token. Its ACL is explicit and limited to SYSTEM and Administrators; the token contents have not been read or committed.

The issuer is https://v3-mcp.radlina.com; ChatGPT custom MCP URL: https://v3-mcp.radlina.com/mcp. Public OAuth metadata and protected-resource discovery are available. Public anonymous MCP requests are HTTP 401, and admin scope is HTTP 400. The updated preflight validates the actual WinSW token-file source and sixteen security/operational checks.

Evidence: governance/v3/validation/V3_I01_PUBLIC_HTTPS_SMOKE_PASS_20261011.json. Status is PUBLIC OAUTH SMOKE PASS ONLY, not I01/AC01 production acceptance.

Next user-controlled step in ChatGPT: Plugins > Add > Add custom MCP server. Name: Radlina Remote MCP V3. URL: https://v3-mcp.radlina.com/mcp. Complete the real OAuth account connection and verify read-only tools. Keep V2 active. Do not mark installation complete without an actual ChatGPT host connection receipt.

---

## Verified state (2026-10-11)

- V2: service RadlinaRemoteMCP on 127.0.0.1:7337, version 2.0.0-alpha.2; do not touch or disable.
- V3 OAuth: auto-start service RadlinaV3OAuthBeta, dedicated 127.0.0.1:7344.
- V3 OAuth issuer is configured for https://v3-mcp.radlina.com; this does NOT prove public TLS works.
- OAuth local health PASS, anonymous MCP returns HTTP 401, admin scope returns HTTP 400.
- Signing public JWK identity remained stable across restarting only the V3 service.
- V3 state directory E:\radlina-v3-oauth-standalone is restricted to SYSTEM and Administrators.
- Tunnel radlina-v3-mcp-beta-20261011 exists in Cloudflare (ID f9a09a4e-2cd3-468b-ae6e-2139fb0e1810).
- DNS v3-mcp.radlina.com points to that independent Tunnel, whose ingress is http://127.0.0.1:7344 with HTTP 404 fallback.
- Tunnel service RadlinaV3Tunnel is installed in Windows, Manual start mode and Stopped, pending local secure token provisioning.
- Pinned cloudflared binary: E:\radlina-v3-runtime\cloudflared-2026.10.0.exe; SHA256 86aee4017b26625cee8484c113558f48effa4cd47f7aa05fcf425604e5d2b23c.

## Human-local provisioning checkpoint

The Tunnel connector token MUST NOT be pasted into ChatGPT, PRs, CI logs, task comments or command-line arguments. Automated transfer between Cloudflare and the workstation was denied by security checks; do not bypass that restriction.

1. On Windows, as authorized administrator, open Cloudflare Dashboard > Networking > Tunnels, select the existing radlina-v3-mcp-beta-20261011 Tunnel, retrieve the connector token from its install/run instructions.
2. Enter the token LOCALLY into E:\radlina-v3-tunnel-credentials\cloudflared.token using a secure local non-logging editor or private input process. Do not paste it into terminal command history. File must hold only the token, with no wrappers. Never commit or upload this file.
3. Ensure token file ACL lists only SYSTEM and Administrators (no broad inherited entries). Inspection command is:
   Get-Acl 'E:\radlina-v3-tunnel-credentials\cloudflared.token' | Select-Object -ExpandProperty Access
   This prints metadata only, not token contents.
4. Start ONLY the independent Tunnel service:
   Start-Service -Name RadlinaV3Tunnel
   Do not change Tailscale Serve or existing V2 ingress.
5. From the repository worktree, verify:
   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/operations/v3-windows-oauth-preflight.ps1 -RequirePublicTls
   Only PASS here confirms public HTTPS, dedicated OAuth issuer and MCP authentication boundary. If fail, leave V3 ChatGPT plugin disconnected and inspect Tunnel logs (without secrets).
6. Once independently verified, enable auto start for ONLY V3 Tunnel:
   Set-Service -Name RadlinaV3Tunnel -StartupType Automatic
7. Register separate ChatGPT custom MCP server Radlina Remote MCP V3 at https://v3-mcp.radlina.com/mcp. Complete real OAuth flow. Confirm read-only capabilities; no mutating operator tools and no false device enrollment.

## Reproducible acceptance

The verification script is READ ONLY and never reads or prints the Tunnel token:

powershell -NoProfile -ExecutionPolicy Bypass -File scripts/operations/v3-windows-oauth-preflight.ps1

Local only should return WINDOWS_LOCAL_OAUTH_SERVICE_PASS_PUBLIC_TLS_PENDING while the Tunnel is unconnected. With -RequirePublicTls but no local token/active Tunnel, it MUST return BLOCKED_FAIL_CLOSED with exit code 2. Never report I01/AC01 complete based solely on local evidence.

## Remaining production gates

P08 persistent trusted MacBook enrollment and fresh signed heartbeat; P06 genuine device routing; S02E target-local consent; S03 signed distributed audit; F01 live Mac and Windows canary/rollback with signed receipts; AC01 native end-to-end ChatGPT V3. Keep V2 running.

No reset, clean, force push, or claiming 100% without real Input -> Runtime -> Execution -> Output -> Acceptance.
