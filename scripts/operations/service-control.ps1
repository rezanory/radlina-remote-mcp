[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('Start', 'Stop', 'Restart', 'Status')][string]$Action
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$serviceExecutable = Join-Path $projectRoot 'service\RadlinaRemoteMCP.exe'
$service = Get-Service -Name 'RadlinaRemoteMCP' -ErrorAction SilentlyContinue

if ($Action -eq 'Status') {
  $probe = $null
  try {
    $response = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:7337/mcp' -Method Post -ContentType 'application/json' -Body '{}' -SkipHttpErrorCheck -TimeoutSec 3
    $probe = [ordered]@{ reachable = $true; status = $response.StatusCode; authGate = $response.StatusCode -eq 401 }
  } catch {
    $probe = [ordered]@{ reachable = $false; status = $null; authGate = $false }
  }
  [ordered]@{
    installed = [bool]$service
    status = if ($service) { [string]$service.Status } else { 'NotInstalled' }
    startType = if ($service) { [string]$service.StartType } else { $null }
    loopback = $probe
  } | ConvertTo-Json -Depth 3
  return
}

if (-not $service -or -not (Test-Path -LiteralPath $serviceExecutable -PathType Leaf)) {
  throw 'RadlinaRemoteMCP is not installed'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run Start, Stop, or Restart from an elevated PowerShell terminal'
}

switch ($Action) {
  'Start' { & $serviceExecutable start }
  'Stop' { & $serviceExecutable stop }
  'Restart' { & $serviceExecutable restart }
}
if ($LASTEXITCODE -ne 0) { throw "service $Action failed" }
Start-Sleep -Seconds 2
$current = Get-Service -Name 'RadlinaRemoteMCP' -ErrorAction Stop
$expected = if ($Action -eq 'Stop') { 'Stopped' } else { 'Running' }
if ([string]$current.Status -ne $expected) {
  throw "service state mismatch: expected $expected, found $($current.Status)"
}
Write-Output "RadlinaRemoteMCP $($current.Status)."
