[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('Start', 'Stop', 'Restart', 'Status')][string]$Action
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$serviceExecutable = Join-Path $projectRoot 'service\RadlinaRemoteMCP.exe'
$service = Get-Service -Name 'RadlinaRemoteMCP' -ErrorAction SilentlyContinue

if ($Action -eq 'Status') {
  $statusCode = $null
  try {
    $response = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:7337/mcp' -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 3
    $statusCode = [int]$response.StatusCode
  } catch {
    if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
      $statusCode = [int]$_.Exception.Response.StatusCode
    }
  }
  $probe = [ordered]@{ reachable = $null -ne $statusCode; status = $statusCode; authGate = $statusCode -eq 401 }
  $serviceRecord = Get-CimInstance Win32_Service -Filter "Name='RadlinaRemoteMCP'" -ErrorAction SilentlyContinue
  [ordered]@{
    installed = [bool]$service
    status = if ($service) { [string]$service.Status } else { 'NotInstalled' }
    startType = if ($service) { [string]$service.StartType } else { $null }
    identity = if ($serviceRecord) { [string]$serviceRecord.StartName } else { $null }
    identityIsTrustedOwner = [bool]($serviceRecord -and $serviceRecord.StartName -eq 'LocalSystem')
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
