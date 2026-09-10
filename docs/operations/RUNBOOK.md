# Operations runbook

All commands run from `C:\radlina-remote-mcp`. Keep `config\local.yaml`, `.state`, backup archives, and OAuth material out of Git and chat.

## Validate a release

```powershell
.\scripts\operations\bootstrap-runtime.ps1
.\scripts\operations\validate-release.ps1
```

The validation runner does not fail fast. It records every gate with command arguments, UTC start time, exit code, duration, sanitized output path, output SHA-256, and artifact hashes under `evidence\PH-01\P001`.

## Install and update

Run service installation from an elevated PowerShell terminal:

```powershell
.\scripts\operations\install-service.ps1
```

The installer uses `LocalSystem` without a password and hardens the project ACL to the preserved owner, Administrators, and LocalSystem. This identity is required for the explicitly authorized trusted-owner profile. The service still binds only to `127.0.0.1:7337`; bearer authentication, scopes, path validation, kill/read-only controls, idempotency, and audit remain server-side requirements. The firewall rule blocks direct inbound connections to the pinned Node runtime.

```powershell
.\scripts\operations\service-control.ps1 -Action Status
.\scripts\operations\service-control.ps1 -Action Restart
```

`Status` is read-only and confirms both SCM state and the loopback `401` authentication gate. Start, Stop, and Restart require elevation.

Updates create a consistent backup before changing dependencies or restarting:

```powershell
.\scripts\operations\update-service.ps1
```

For manifest-bound in-service upgrades, stage a unique candidate, verify it, run preflight, and activate it with a fresh idempotency key. Confirm the exact manifest with `admin_verify_post_restart` after reconnect. `admin_rollback_release` supports a prior immutable release or the explicit `ROOT` runtime. A pending release that fails to confirm health is automatically rolled back on the next service boot. Never clear an unknown-outcome idempotency claim until the local pointer, journal, and filesystem result have been reconciled.

## Backup, restore, and rollback

```powershell
$backup = .\scripts\operations\backup.ps1
.\scripts\operations\restore.ps1 -Archive C:\radlina-remote-mcp\backups\radlina-backup-YYYYMMDDTHHMMSSZ.zip
```

Backups contain the local configuration, SQLite state, DPAPI-protected signing key, audit chain, and release metadata. Restore verifies every manifest hash before changing live state and retains the replaced state under `backups\pre-restore-*`. DPAPI data is usable only on this Windows machine by identities permitted through the restricted project ACL.

For a source rollback, first select the reviewed prior Git commit, then run:

```powershell
.\scripts\operations\rollback-service.ps1 -BackupArchive <verified-backup.zip>
.\scripts\operations\update-service.ps1
```

## Tailscale exposure

Private tailnet only:

```powershell
.\scripts\operations\configure-tailscale.ps1 -Mode Serve
```

Public ChatGPT ingress:

```powershell
.\scripts\operations\configure-tailscale.ps1 -Mode Funnel
```

Both modes keep the application on loopback and publish one canonical `*.ts.net` HTTPS hostname. Tailscale DNS/edge redundancy is used; individual IPs are never pinned into OAuth, TLS, or ChatGPT configuration. Roll back with `restore-tailscale.ps1`.

## Incident controls

```powershell
& .\.runtime\node-v24.20.0-win-x64\node.exe .\dist\src\cli\control.js kill on
& .\.runtime\node-v24.20.0-win-x64\node.exe .\dist\src\cli\control.js readonly on
& .\.runtime\node-v24.20.0-win-x64\node.exe .\dist\src\cli\control.js status
& .\.runtime\node-v24.20.0-win-x64\node.exe .\dist\src\cli\control.js verify-audit
```

After a crash, inspect unresolved at-most-once operations locally:

```powershell
& .\.runtime\node-v24.20.0-win-x64\node.exe .\dist\src\cli\control.js idempotency list
```

Only after independently checking the filesystem/process outcome, clear one exact claim with `idempotency clear <key>`. Reusing the key before that is denied.

## Uninstall

```powershell
.\scripts\operations\restore-tailscale.ps1
.\scripts\operations\uninstall-service.ps1
```

State is retained by default. `uninstall-service.ps1 -PurgeState` permanently removes it and must only be used after a verified backup.
