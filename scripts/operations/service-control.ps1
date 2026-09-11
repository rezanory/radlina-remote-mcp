[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('Start', 'Stop', 'Restart', 'Status')][string]$Action
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$serviceExecutable = Join-Path $projectRoot 'service\RadlinaRemoteMCP.exe'
$service = Get-Service -Name 'RadlinaRemoteMCP' -ErrorAction SilentlyContinue

if ($Action -eq 'Status') {
  function Invoke-McpProbe([string]$Uri) {
    $statusCode = $null
    $errorText = $null
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    try {
      $response = Invoke-WebRequest -UseBasicParsing -Uri $Uri -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 5
      $statusCode = [int]$response.StatusCode
    } catch {
      if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
        $statusCode = [int]$_.Exception.Response.StatusCode
      } else {
        $errorText = [string]$_.Exception.Message
      }
    } finally {
      $stopwatch.Stop()
    }
    return [ordered]@{
      reachable = $null -ne $statusCode
      status = $statusCode
      authGate = $statusCode -eq 401
      ready = $statusCode -eq 401
      latencyMs = [int64]$stopwatch.ElapsedMilliseconds
      error = $errorText
    }
  }

  $configFile = Join-Path $projectRoot 'config\local.yaml'
  $publicUrl = $null
  $port = 7337
  if (Test-Path -LiteralPath $configFile -PathType Leaf) {
    foreach ($line in Get-Content -LiteralPath $configFile) {
      if (-not $publicUrl -and $line -match '^\s*publicUrl:\s*(.+?)\s*$') {
        $publicUrl = $Matches[1].Trim().Trim('"').Trim("'")
      }
      if ($line -match '^\s{2}port:\s*(\d+)\s*$') {
        $port = [int]$Matches[1]
      }
    }
  }

  $localProbe = Invoke-McpProbe "http://127.0.0.1:$port/mcp"
  $publicProbe = $null
  $tailscaleRequired = $false
  if ($publicUrl) {
    $publicUri = [Uri]$publicUrl
    $publicProbe = Invoke-McpProbe ($publicUrl.TrimEnd('/') + '/mcp')
    $tailscaleRequired = $publicUri.Host.ToLowerInvariant().EndsWith('.ts.net')
  }

  $tailscale = [ordered]@{
    required = $tailscaleRequired
    ready = if ($tailscaleRequired) { $false } else { $true }
    backendState = $null
    selfOnline = $null
    relay = $null
    healthIssueCount = $null
    error = $null
  }
  if ($tailscaleRequired) {
    $tailscaleExe = if (${env:ProgramFiles}) { Join-Path ${env:ProgramFiles} 'Tailscale\tailscale.exe' } else { $null }
    if (-not $tailscaleExe -or -not (Test-Path -LiteralPath $tailscaleExe -PathType Leaf)) {
      $tailscaleCommand = Get-Command tailscale.exe -ErrorAction SilentlyContinue
      if ($tailscaleCommand) { $tailscaleExe = $tailscaleCommand.Source }
    }
    try {
      if (-not $tailscaleExe -or -not (Test-Path -LiteralPath $tailscaleExe -PathType Leaf)) {
        throw 'tailscale executable was not found'
      }
      $tailscaleStatus = (& $tailscaleExe status --json | ConvertFrom-Json)
      if ($LASTEXITCODE -ne 0) { throw 'tailscale status failed' }
      $tailscale.backendState = [string]$tailscaleStatus.BackendState
      $tailscale.selfOnline = [bool]$tailscaleStatus.Self.Online
      $tailscale.relay = [string]$tailscaleStatus.Self.Relay
      $tailscale.healthIssueCount = @($tailscaleStatus.Health).Count
      $tailscale.ready = $tailscale.backendState -eq 'Running' -and $tailscale.selfOnline -and $tailscale.healthIssueCount -eq 0
    } catch {
      $tailscale.error = [string]$_.Exception.Message
    }
  }

  $serviceRecord = Get-CimInstance Win32_Service -Filter "Name='RadlinaRemoteMCP'" -ErrorAction SilentlyContinue
  [ordered]@{
    installed = [bool]$service
    status = if ($service) { [string]$service.Status } else { 'NotInstalled' }
    startType = if ($service) { [string]$service.StartType } else { $null }
    identity = if ($serviceRecord) { [string]$serviceRecord.StartName } else { $null }
    identityIsTrustedOwner = [bool]($serviceRecord -and $serviceRecord.StartName -eq 'LocalSystem')
    localReady = [bool]$localProbe.ready
    publicReady = if ($publicProbe) { [bool]$publicProbe.ready } else { $null }
    tailscaleReady = [bool]$tailscale.ready
    local = $localProbe
    public = $publicProbe
    tailscale = $tailscale
  } | ConvertTo-Json -Depth 4
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
