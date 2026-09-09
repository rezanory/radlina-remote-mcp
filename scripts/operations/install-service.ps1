[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$runtimeBootstrap = Join-Path $PSScriptRoot 'bootstrap-runtime.ps1'
& $runtimeBootstrap

$localConfig = Join-Path $projectRoot 'config\local.yaml'
if (-not (Test-Path -LiteralPath $localConfig)) {
  Copy-Item -LiteralPath (Join-Path $projectRoot 'config\example.yaml') -Destination $localConfig
}

$nodeRoot = Join-Path $projectRoot '.runtime\node-v24.20.0-win-x64'
& (Join-Path $nodeRoot 'npm.cmd') ci --ignore-scripts
if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
& (Join-Path $nodeRoot 'npm.cmd') run build
if ($LASTEXITCODE -ne 0) { throw 'build failed' }
& (Join-Path $nodeRoot 'npm.cmd') test
if ($LASTEXITCODE -ne 0) { throw 'tests failed' }
& (Join-Path $nodeRoot 'npm.cmd') run security:audit
if ($LASTEXITCODE -ne 0) { throw 'dependency audit failed' }

$serviceDirectory = Join-Path $projectRoot 'service'
$serviceExecutable = Join-Path $serviceDirectory 'RadlinaRemoteMCP.exe'
$sourceWinSw = Join-Path $projectRoot '.runtime\winsw-2.12.0\WinSW-x64.exe'
Copy-Item -LiteralPath $sourceWinSw -Destination $serviceExecutable -Force
$expectedWinSw = '05b82d46ad331cc16bdc00de5c6332c1ef818df8ceefcd49c726553209b3a0da'
$actualWinSw = (Get-FileHash -Algorithm SHA256 -LiteralPath $serviceExecutable).Hash.ToLowerInvariant()
if ($actualWinSw -ne $expectedWinSw) { throw 'copied WinSW executable failed integrity verification' }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this script from an elevated PowerShell terminal. WinSW will then prompt for the low-privilege Windows account and password used by the service.'
}

$existing = Get-Service -Name 'RadlinaRemoteMCP' -ErrorAction SilentlyContinue
if ($existing) { throw 'RadlinaRemoteMCP is already installed; use update-service.ps1 or uninstall-service.ps1' }

& (Join-Path $PSScriptRoot 'configure-firewall.ps1')
Write-Output 'At the WinSW prompts enter .\Radlina, then the Windows password, then answer y to grant Log on as a service. Do not choose LocalSystem.'
& $serviceExecutable install /p
if ($LASTEXITCODE -ne 0) { throw 'WinSW service installation failed' }
& $serviceExecutable start
if ($LASTEXITCODE -ne 0) { throw 'WinSW service start failed' }
Start-Sleep -Seconds 2
$service = Get-Service -Name 'RadlinaRemoteMCP' -ErrorAction Stop
if ($service.Status -ne 'Running') { throw "service is not running; current status: $($service.Status)" }
Write-Output 'RadlinaRemoteMCP service installed and running.'
