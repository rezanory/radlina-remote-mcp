[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('Serve', 'Funnel')][string]$Mode,
  [ValidateSet(443, 8443, 10000)][int]$HttpsPort = 443
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$stateDirectory = Join-Path $projectRoot '.state'
New-Item -ItemType Directory -Force -Path $stateDirectory | Out-Null
$backup = Join-Path $stateDirectory 'tailscale-before.json'
if (-not (Test-Path -LiteralPath $backup)) {
  $existingConfig = & tailscale.exe serve get-config --all
  if ($LASTEXITCODE -ne 0) { throw 'could not snapshot the existing Tailscale serving configuration' }
  $existingConfigText = ($existingConfig -join [Environment]::NewLine)
  try {
    [void]($existingConfigText | ConvertFrom-Json)
  } catch {
    throw 'Tailscale returned an invalid serving configuration snapshot'
  }
  [IO.File]::WriteAllText($backup, $existingConfigText, [Text.UTF8Encoding]::new($false))
}
$configBackup = Join-Path $stateDirectory 'config-before-tailscale.yaml'
$localConfig = Join-Path $projectRoot 'config\local.yaml'
if (-not (Test-Path -LiteralPath $localConfig)) {
  Copy-Item -LiteralPath (Join-Path $projectRoot 'config\example.yaml') -Destination $localConfig
}
if (-not (Test-Path -LiteralPath $configBackup)) {
  Copy-Item -LiteralPath $localConfig -Destination $configBackup
}

$statusCode = $null
try {
  $probe = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:7337/mcp' -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 5
  $statusCode = [int]$probe.StatusCode
} catch {
  if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
    $statusCode = [int]$_.Exception.Response.StatusCode
  } else {
    throw "local MCP preflight failed: $($_.Exception.Message)"
  }
}
if ($statusCode -ne 401) { throw "local MCP auth gate returned $statusCode, expected 401" }

if ($Mode -eq 'Serve') {
  & tailscale.exe serve --bg --https=$HttpsPort 'http://127.0.0.1:7337'
} else {
  & tailscale.exe funnel --bg --https=$HttpsPort 'http://127.0.0.1:7337'
}
if ($LASTEXITCODE -ne 0) { throw "Tailscale $Mode configuration failed" }
$tailscaleStatus = (& tailscale.exe status --json | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0) { throw 'Tailscale status probe failed after serving configuration' }
$healthIssueCount = @($tailscaleStatus.Health).Count
if ([string]$tailscaleStatus.BackendState -ne 'Running' -or -not [bool]$tailscaleStatus.Self.Online -or $healthIssueCount -ne 0) {
  throw "Tailscale is not ready after serving configuration: backend=$($tailscaleStatus.BackendState);online=$($tailscaleStatus.Self.Online);healthIssues=$healthIssueCount"
}
$dnsName = ([string]$tailscaleStatus.Self.DNSName).TrimEnd('.')
if (-not $dnsName) { throw 'Tailscale did not report a MagicDNS name' }
$portSuffix = if ($HttpsPort -eq 443) { '' } else { ":$HttpsPort" }
$publicUrl = "https://$dnsName$portSuffix"
$node = Join-Path $projectRoot '.runtime\node-v24.20.0-win-x64\node.exe'
& $node (Join-Path $projectRoot 'dist\src\cli\configure-public-url.js') $publicUrl
if ($LASTEXITCODE -ne 0) { throw 'public URL configuration update failed' }
Write-Output "Tailscale $Mode configured at $publicUrl. Restart the RadlinaRemoteMCP service before connecting a client."
