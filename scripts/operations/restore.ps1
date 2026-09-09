[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Archive
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$archivePath = (Resolve-Path -LiteralPath $Archive).Path
$projectPrefix = $projectRoot.TrimEnd('\') + '\'
$stage = [IO.Path]::GetFullPath((Join-Path $projectRoot ('.restore-' + [guid]::NewGuid().ToString('N'))))
if (-not $stage.StartsWith($projectPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "refusing unexpected staging path: $stage"
}
$serviceExecutable = Join-Path $projectRoot 'service\RadlinaRemoteMCP.exe'
$service = Get-Service -Name 'RadlinaRemoteMCP' -ErrorAction SilentlyContinue
$restartService = $service -and $service.Status -eq 'Running'
$recoveryRoot = Join-Path $projectRoot ('backups\pre-restore-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + '-' + [guid]::NewGuid().ToString('N'))
$stateTarget = [IO.Path]::GetFullPath((Join-Path $projectRoot '.state'))
$configTarget = [IO.Path]::GetFullPath((Join-Path $projectRoot 'config\local.yaml'))
if (-not $stateTarget.StartsWith($projectPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    -not $configTarget.StartsWith($projectPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw 'refusing restore targets outside the project root'
}

try {
  if ($restartService) {
    & $serviceExecutable stop
    if ($LASTEXITCODE -ne 0) { throw 'could not stop service before restore' }
  }
  New-Item -ItemType Directory -Force -Path $stage | Out-Null
  Expand-Archive -LiteralPath $archivePath -DestinationPath $stage
  $manifestPath = Join-Path $stage 'manifest.json'
  $payload = Join-Path $stage 'payload'
  if (-not (Test-Path -LiteralPath $manifestPath) -or -not (Test-Path -LiteralPath $payload)) {
    throw 'backup archive is missing its manifest or payload'
  }
  $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
  if ($manifest.schemaVersion -ne 1) { throw 'unsupported backup manifest version' }
  if (-not $manifest.items -or $manifest.items.Count -lt 1) { throw 'backup manifest contains no files' }
  $payloadPrefix = [IO.Path]::GetFullPath($payload).TrimEnd('\') + '\'
  foreach ($item in $manifest.items) {
    if ($item.path -isnot [string] -or $item.sha256 -isnot [string]) {
      throw 'invalid backup manifest item'
    }
    $source = [IO.Path]::GetFullPath((Join-Path $payload ([string]$item.path)))
    if (-not $source.StartsWith($payloadPrefix, [StringComparison]::OrdinalIgnoreCase)) {
      throw "backup path escapes payload: $($item.path)"
    }
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "backup file missing: $($item.path)" }
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash.ToLowerInvariant()
    if ($hash -ne ([string]$item.sha256).ToLowerInvariant()) {
      throw "backup hash mismatch: $($item.path)"
    }
  }

  New-Item -ItemType Directory -Force -Path $recoveryRoot | Out-Null
  if (Test-Path -LiteralPath $stateTarget) {
    Move-Item -LiteralPath $stateTarget -Destination (Join-Path $recoveryRoot '.state')
  }
  if (Test-Path -LiteralPath $configTarget) {
    New-Item -ItemType Directory -Force -Path (Join-Path $recoveryRoot 'config') | Out-Null
    Move-Item -LiteralPath $configTarget -Destination (Join-Path $recoveryRoot 'config\local.yaml')
  }
  $restoredState = Join-Path $payload '.state'
  $restoredConfig = Join-Path $payload 'config\local.yaml'
  if (Test-Path -LiteralPath $restoredState) {
    Copy-Item -LiteralPath $restoredState -Destination $stateTarget -Recurse
  }
  if (Test-Path -LiteralPath $restoredConfig) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $configTarget) | Out-Null
    Copy-Item -LiteralPath $restoredConfig -Destination $configTarget
  }
  & (Join-Path $PSScriptRoot 'migrate-dpapi-protection.ps1')
  & (Join-Path $PSScriptRoot 'configure-service-acl.ps1')
  $node = Join-Path $projectRoot '.runtime\node-v24.20.0-win-x64\node.exe'
  & $node (Join-Path $projectRoot 'dist\src\cli\diagnose.js') | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'restored configuration/state failed diagnostics' }
  Write-Output "restored=$archivePath"
  Write-Output "previous-state=$recoveryRoot"
} catch {
  if (Test-Path -LiteralPath $stateTarget) { Remove-Item -LiteralPath $stateTarget -Recurse -Force }
  if (Test-Path -LiteralPath (Join-Path $recoveryRoot '.state')) {
    Move-Item -LiteralPath (Join-Path $recoveryRoot '.state') -Destination $stateTarget
  }
  if (Test-Path -LiteralPath $configTarget) { Remove-Item -LiteralPath $configTarget -Force }
  if (Test-Path -LiteralPath (Join-Path $recoveryRoot 'config\local.yaml')) {
    Move-Item -LiteralPath (Join-Path $recoveryRoot 'config\local.yaml') -Destination $configTarget
  }
  throw
} finally {
  if (Test-Path -LiteralPath $stage) {
    $resolvedStage = [IO.Path]::GetFullPath($stage)
    if (-not $resolvedStage.StartsWith($projectPrefix, [StringComparison]::OrdinalIgnoreCase)) {
      throw "refusing to remove unexpected staging path: $resolvedStage"
    }
    Remove-Item -LiteralPath $resolvedStage -Recurse -Force
  }
  if ($restartService) {
    & $serviceExecutable start
    if ($LASTEXITCODE -ne 0) { throw 'restore finished but service restart failed' }
  }
}
