[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$serviceExecutable = Join-Path $projectRoot 'service\RadlinaRemoteMCP.exe'
if (-not (Test-Path -LiteralPath $serviceExecutable)) { throw 'service wrapper is missing; run install-service.ps1 first' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this script from an elevated PowerShell terminal' }

& (Join-Path $PSScriptRoot 'backup.ps1')
if ($LASTEXITCODE -ne 0) { throw 'pre-update backup failed' }
& $serviceExecutable stop
if ($LASTEXITCODE -ne 0) { throw 'service stop failed' }
$nodeRoot = Join-Path $projectRoot '.runtime\node-v24.20.0-win-x64'
& (Join-Path $nodeRoot 'npm.cmd') ci --ignore-scripts
if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
& (Join-Path $nodeRoot 'npm.cmd') run build
if ($LASTEXITCODE -ne 0) { throw 'build failed' }
& (Join-Path $nodeRoot 'npm.cmd') test
if ($LASTEXITCODE -ne 0) { throw 'tests failed; service remains stopped' }
& $serviceExecutable start
if ($LASTEXITCODE -ne 0) { throw 'service restart failed' }
Write-Output 'RadlinaRemoteMCP service updated and running.'
