[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$runtimeRoot = Join-Path $projectRoot '.runtime'
$downloads = Join-Path $runtimeRoot 'downloads'
New-Item -ItemType Directory -Force -Path $downloads | Out-Null

function Get-VerifiedArtifact {
  param(
    [Parameter(Mandatory)][string]$Uri,
    [Parameter(Mandatory)][string]$Destination,
    [Parameter(Mandatory)][string]$Sha256
  )
  if (-not (Test-Path -LiteralPath $Destination)) {
    Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $Destination
  }
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash.ToLowerInvariant()
  if ($actual -ne $Sha256) {
    throw "SHA-256 mismatch for $Destination. Expected $Sha256, got $actual"
  }
}

$nodeZip = Join-Path $downloads 'node-v24.20.0-win-x64.zip'
Get-VerifiedArtifact -Uri 'https://nodejs.org/dist/v24.20.0/node-v24.20.0-win-x64.zip' -Destination $nodeZip -Sha256 '6cac9ffbca8f6a47091e4b5c772e0606049c3871cb67d900c0cedde630e545ba'
$nodeRoot = Join-Path $runtimeRoot 'node-v24.20.0-win-x64'
if (-not (Test-Path -LiteralPath (Join-Path $nodeRoot 'node.exe'))) {
  Expand-Archive -LiteralPath $nodeZip -DestinationPath $runtimeRoot -Force
}

$ripgrepZip = Join-Path $downloads 'ripgrep-15.2.0-x86_64-pc-windows-msvc.zip'
Get-VerifiedArtifact -Uri 'https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/ripgrep-15.2.0-x86_64-pc-windows-msvc.zip' -Destination $ripgrepZip -Sha256 '71b2fef860abe467217a538ff31de02f5258807c0129f771846f87bd029aafc5'
$ripgrepRoot = Join-Path $runtimeRoot 'ripgrep-15.2.0-x86_64-pc-windows-msvc'
if (-not (Test-Path -LiteralPath (Join-Path $ripgrepRoot 'rg.exe'))) {
  Expand-Archive -LiteralPath $ripgrepZip -DestinationPath $runtimeRoot -Force
}

$winswRoot = Join-Path $runtimeRoot 'winsw-2.12.0'
New-Item -ItemType Directory -Force -Path $winswRoot | Out-Null
$winsw = Join-Path $winswRoot 'WinSW-x64.exe'
Get-VerifiedArtifact -Uri 'https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe' -Destination $winsw -Sha256 '05b82d46ad331cc16bdc00de5c6332c1ef818df8ceefcd49c726553209b3a0da'

$nodeVersion = & (Join-Path $nodeRoot 'node.exe') --version
$ripgrepVersion = (& (Join-Path $ripgrepRoot 'rg.exe') --version | Select-Object -First 1)
Write-Output "runtime ready: Node $nodeVersion; $ripgrepVersion; WinSW 2.12.0"
