[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$backup = Join-Path $projectRoot '.state\tailscale-before.json'
if (-not (Test-Path -LiteralPath $backup)) { throw 'no pre-change Tailscale configuration snapshot exists' }
& tailscale.exe serve set-config $backup --all
if ($LASTEXITCODE -ne 0) { throw 'Tailscale configuration restore failed' }
$configBackup = Join-Path $projectRoot '.state\config-before-tailscale.yaml'
if (Test-Path -LiteralPath $configBackup) {
  Copy-Item -LiteralPath $configBackup -Destination (Join-Path $projectRoot 'config\local.yaml') -Force
}
Write-Output 'Previous Tailscale serving configuration and local URL configuration restored. Restart the service.'
