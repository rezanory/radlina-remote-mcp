[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$BackupArchive
)

$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'restore.ps1') -Archive $BackupArchive
if ($LASTEXITCODE -ne 0) { throw 'state/config rollback failed' }
Write-Output 'State and configuration rollback completed. Source rollback must use the reviewed prior Git commit, followed by update-service.ps1.'
