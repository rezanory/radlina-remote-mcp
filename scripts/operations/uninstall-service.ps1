[CmdletBinding()]
param(
  [switch]$PurgeState
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$serviceExecutable = Join-Path $projectRoot 'service\RadlinaRemoteMCP.exe'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this script from an elevated PowerShell terminal' }

if (Get-Service -Name 'RadlinaRemoteMCP' -ErrorAction SilentlyContinue) {
  & $serviceExecutable stop
  & $serviceExecutable uninstall
  if ($LASTEXITCODE -ne 0) { throw 'service uninstall failed' }
}
& (Join-Path $PSScriptRoot 'remove-firewall.ps1')
if ($PurgeState) {
  $state = [IO.Path]::GetFullPath((Join-Path $projectRoot '.state'))
  $expected = [IO.Path]::GetFullPath('C:\radlina-remote-mcp\.state')
  if ($state -ne $expected) { throw "refusing to purge unexpected path: $state" }
  if (Test-Path -LiteralPath $state) { Remove-Item -LiteralPath $state -Recurse -Force }
  Write-Output 'Service removed and state permanently purged.'
} else {
  Write-Output 'Service removed. State and audit data were retained.'
}
