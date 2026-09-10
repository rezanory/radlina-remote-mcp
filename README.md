# Radlina Remote MCP

Self-hosted MCP server for `LAPTOP-13QINEIF`. It exposes a loopback-only Streamable HTTP endpoint, performs OAuth 2.1-style authorization with PKCE and local approval, applies per-tool scopes and workspace policies, persists sessions in SQLite, and writes a tamper-evident redacted audit chain.

## Secure local build

Run in PowerShell:

```powershell
Set-Location C:\radlina-remote-mcp
.\scripts\operations\bootstrap-runtime.ps1
Copy-Item .\config\example.yaml .\config\local.yaml
& .\.runtime\node-v24.20.0-win-x64\npm.cmd ci --ignore-scripts
& .\.runtime\node-v24.20.0-win-x64\npm.cmd run build
& .\.runtime\node-v24.20.0-win-x64\npm.cmd test
& .\.runtime\node-v24.20.0-win-x64\npm.cmd start
```

The local MCP URL is `http://127.0.0.1:7337/mcp`. MCP requests without a valid bearer token return `401`. The example profile allows only `C:\radlina-remote-mcp\workspace` and allows no executable by default.

## Local safety controls

```powershell
& .\.runtime\node-v24.20.0-win-x64\node.exe .\dist\src\cli\control.js readonly on
& .\.runtime\node-v24.20.0-win-x64\node.exe .\dist\src\cli\control.js kill on
& .\.runtime\node-v24.20.0-win-x64\node.exe .\dist\src\cli\control.js status
& .\.runtime\node-v24.20.0-win-x64\node.exe .\dist\src\cli\control.js verify-audit
```

`kill on` immediately denies every remote tool except minimal health/readiness tools. `readonly on` denies mutations and process execution.

## Deployment

- Windows service: `scripts\operations\install-service.ps1` from an elevated PowerShell terminal. WinSW uses `LocalSystem` so the explicitly authorized trusted-owner profile has capability parity without a service password. Authentication, scopes, kill/read-only controls, path validation, and audit remain mandatory.
- Service start/stop/restart/status: `scripts\operations\service-control.ps1 -Action <Start|Stop|Restart|Status>`.
- Private tailnet ingress: `scripts\operations\configure-tailscale.ps1 -Mode Serve`.
- ChatGPT-compatible public HTTPS ingress: `scripts\operations\configure-tailscale.ps1 -Mode Funnel`.
- ChatGPT connector instructions: `docs\operations\CHATGPT-CONNECT.md`.
- Backup/restore: `scripts\operations\backup.ps1` and `scripts\operations\restore.ps1`.
- Rollback: `scripts\operations\rollback-service.ps1`, `scripts\operations\uninstall-service.ps1`, and `scripts\operations\restore-tailscale.ps1`.
- In-service release lifecycle: `admin_stage_release`, `admin_verify_release`, `admin_upgrade_preflight`, `admin_activate_release`, `admin_upgrade_status`, `admin_rollback_release`, and `admin_verify_post_restart`. Release manifests bind the exact source SHA/tree, evidence hashes, entry point, and complete file set. Activation and rollback are locked, durable, self-restarting, and health-confirmed.

Do not enable Funnel until the local validation pipeline is green. Funnel traffic is public internet traffic; OAuth and policy remain mandatory.

## Validation

```powershell
& .\.runtime\node-v24.20.0-win-x64\npm.cmd run format:check
& .\.runtime\node-v24.20.0-win-x64\npm.cmd run lint
& .\.runtime\node-v24.20.0-win-x64\npm.cmd run typecheck
& .\.runtime\node-v24.20.0-win-x64\npm.cmd test
& .\.runtime\node-v24.20.0-win-x64\npm.cmd run build
& .\.runtime\node-v24.20.0-win-x64\npm.cmd run security:audit
.\scripts\operations\validate-release.ps1
```

Architecture decisions are under `docs\architecture`; the capability matrix, threat model, runbook, user guide, and exact third-party pins are under `docs` and `third_party`.
