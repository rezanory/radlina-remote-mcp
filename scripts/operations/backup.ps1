[CmdletBinding()]
param(
  [string]$Destination
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$backupRoot = Join-Path $projectRoot 'backups'
New-Item -ItemType Directory -Force -Path $backupRoot | Out-Null
if (-not $Destination) {
  $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
  $Destination = Join-Path $backupRoot "radlina-backup-$stamp.zip"
} elseif (-not [IO.Path]::IsPathRooted($Destination)) {
  $Destination = Join-Path $backupRoot $Destination
}
$destinationPath = [IO.Path]::GetFullPath($Destination)
if (Test-Path -LiteralPath $destinationPath) { throw "backup already exists: $destinationPath" }
New-Item -ItemType Directory -Force -Path ([IO.Path]::GetDirectoryName($destinationPath)) | Out-Null

$stage = [IO.Path]::GetFullPath((Join-Path $projectRoot ('.backup-' + [guid]::NewGuid().ToString('N'))))
$projectPrefix = $projectRoot.TrimEnd('\') + '\'
if (-not $stage.StartsWith($projectPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "refusing unexpected staging path: $stage"
}
$payload = Join-Path $stage 'payload'
$serviceExecutable = Join-Path $projectRoot 'service\RadlinaRemoteMCP.exe'
$service = Get-Service -Name 'RadlinaRemoteMCP' -ErrorAction SilentlyContinue
$restartService = $service -and $service.Status -eq 'Running'

try {
  if ($restartService) {
    & $serviceExecutable stop
    if ($LASTEXITCODE -ne 0) { throw 'could not stop service for a consistent backup' }
  }
  New-Item -ItemType Directory -Force -Path $payload | Out-Null
  $items = @(
    'config\local.yaml',
    '.state',
    'package.json',
    'package-lock.json',
    'service\RadlinaRemoteMCP.xml',
    'third_party\runtime-manifest.json'
  )
  foreach ($relative in $items) {
    $source = Join-Path $projectRoot $relative
    if (-not (Test-Path -LiteralPath $source)) { continue }
    $target = Join-Path $payload $relative
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
    Copy-Item -LiteralPath $source -Destination $target -Recurse
  }
  $payloadPrefix = $payload.TrimEnd('\') + '\'
  $files = Get-ChildItem -LiteralPath $payload -File -Recurse | Sort-Object FullName
  $manifestItems = foreach ($file in $files) {
    [ordered]@{
      path = $file.FullName.Substring($payloadPrefix.Length).Replace('\', '/')
      bytes = $file.Length
      sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
    }
  }
  $manifest = [ordered]@{
    schemaVersion = 1
    createdAt = (Get-Date).ToUniversalTime().ToString('o')
    machine = $env:COMPUTERNAME
    user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    note = 'DPAPI-protected material can only be restored by the same Windows identity on this machine.'
    items = @($manifestItems)
  }
  $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $stage 'manifest.json') -Encoding utf8NoBOM
  Compress-Archive -LiteralPath (Join-Path $stage 'manifest.json'), $payload -DestinationPath $destinationPath -CompressionLevel Optimal
  $archiveHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $destinationPath).Hash.ToLowerInvariant()
  Write-Output "backup=$destinationPath"
  Write-Output "sha256=$archiveHash"
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
    if ($LASTEXITCODE -ne 0) { throw 'backup completed but service restart failed' }
  }
}
