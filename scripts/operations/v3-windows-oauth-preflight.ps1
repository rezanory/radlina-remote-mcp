param(
  [switch]$RequirePublicTls
)

$ErrorActionPreference = 'Stop'
$startedAt = (Get-Date).ToUniversalTime().ToString('o')
$expectedIssuer = 'https://v3-mcp.radlina.com'
$origin = 'http://127.0.0.1:7344'
$stateDirectory = 'E:\radlina-v3-oauth-standalone'
$tokenFile = 'E:\radlina-v3-tunnel-credentials\cloudflared.token'
$cloudflaredFile = 'E:\radlina-v3-runtime\cloudflared-2026.10.0.exe'
$cloudflaredHash = '86aee4017b26625cee8484c113558f48effa4cd47f7aa05fcf425604e5d2b23c'

$checks = [ordered]@{}
$failures = [System.Collections.Generic.List[string]]::new()

function Check([string]$name, [bool]$passed, [string]$reason) {
  $script:checks[$name] = $passed
  if (-not $passed) { $script:failures.Add("$name : $reason") }
}

function HttpCode([string]$url, [string]$method = 'GET', [string]$body = '') {
  try {
    if ($method -eq 'POST') {
      $response = Invoke-WebRequest -Uri $url -Method POST -UseBasicParsing -TimeoutSec 8 -ContentType 'application/json' -Body $body
    } else {
      $response = Invoke-WebRequest -Uri $url -Method GET -UseBasicParsing -TimeoutSec 8
    }
    return [int]$response.StatusCode
  } catch {
    if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
    return 0
  }
}

function PrivateAcl([string]$location) {
  if (-not (Test-Path -LiteralPath $location)) { return $false }
  $acl = Get-Acl -LiteralPath $location
  foreach ($entry in $acl.Access) {
    $principal = $entry.IdentityReference.Value
    if ($entry.IsInherited -or $entry.AccessControlType -ne 'Allow' -or
        $principal -notin @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
      return $false
    }
  }
  return $acl.Access.Count -eq 2
}

try {
  $v2 = @(Get-NetTCPConnection -State Listen -LocalPort 7337 -ErrorAction SilentlyContinue)
  Check 'v2_7337_untouched' ($v2.Count -eq 1 -and $v2[0].LocalAddress -eq '127.0.0.1') 'V2 loopback listener missing or changed'

  $oauth = Get-Service -Name 'RadlinaV3OAuthBeta' -ErrorAction Stop
  Check 'v3_oauth_service_running' ($oauth.Status -eq 'Running') 'V3 OAuth service is not running'

  $listeners = @(Get-NetTCPConnection -State Listen -LocalPort 7344 -ErrorAction SilentlyContinue)
  Check 'v3_oauth_loopback_only' ($listeners.Count -eq 1 -and $listeners[0].LocalAddress -eq '127.0.0.1') 'V3 OAuth binds outside its dedicated loopback'

  $health = Invoke-RestMethod -Uri ($origin + '/auth-health') -TimeoutSec 8
  Check 'v3_oauth_signing' ($health.status -eq 'healthy' -and $health.signingReady -eq $true -and $health.tokenEndpointReady -eq $true) 'Local V3 OAuth signing or token endpoint unhealthy'

  $metadata = Invoke-RestMethod -Uri ($origin + '/.well-known/oauth-authorization-server') -TimeoutSec 8
  Check 'v3_independent_issuer' ($metadata.issuer -eq $expectedIssuer) 'V3 OAuth issuer differs from pinned independent hostname'

  $anonCode = HttpCode ($origin + '/mcp') 'POST' '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
  Check 'anonymous_mcp_rejected_401' ($anonCode -eq 401) 'Anonymous MCP access was not rejected'

  $adminCode = HttpCode ($origin + '/authorize?scope=admin')
  Check 'admin_scope_rejected_400' ($adminCode -eq 400) 'Elevated OAuth scope was not rejected'

  Check 'v3_state_acl_private' (PrivateAcl $stateDirectory) 'V3 OAuth state storage has broad permissions'

  $actualHash = if (Test-Path -LiteralPath $cloudflaredFile) {
    (Get-FileHash -LiteralPath $cloudflaredFile -Algorithm SHA256).Hash.ToLowerInvariant()
  } else { '' }
  Check 'cloudflared_vendor_sha256' ($actualHash -eq $cloudflaredHash) 'Tunnel binary checksum incorrect'

  $tunnelService = Get-Service -Name 'RadlinaV3Tunnel' -ErrorAction Stop
  $tokenPresent = Test-Path -LiteralPath $tokenFile
  $tokenAclGood = if ($tokenPresent) { PrivateAcl $tokenFile } else { $false }
  if ($tokenPresent) { Check 'tunnel_token_acl_private' $tokenAclGood 'Tunnel token file has unsafe ACL' }

  $liveTls = $false
  if ($RequirePublicTls) {
    Check 'tunnel_secure_token_provisioned' $tokenPresent 'Tunnel token is not provisioned locally'
    Check 'tunnel_service_running' ($tunnelService.Status -eq 'Running') 'Tunnel connector service is not running'
    if ($tokenPresent -and $tunnelService.Status -eq 'Running') {
      try {
        $public = Invoke-RestMethod -Uri ($expectedIssuer + '/.well-known/oauth-authorization-server') -TimeoutSec 12
        $liveTls = $public.issuer -eq $expectedIssuer
      } catch { $liveTls = $false }
    }
    Check 'public_https_oauth_issuer_verified' $liveTls 'External HTTPS tunnel and OAuth metadata are not validated'
  }

  $complete = $failures.Count -eq 0
  $output = [ordered]@{
    schema_version = 'radlina.v3.windows-oauth-service-operational-check/v1'
    input = [ordered]@{
      workstation = 'LAPTOP-13QINEIF'
      expected_oauth_issuer = $expectedIssuer
      public_tls_required = [bool]$RequirePublicTls
    }
    runtime = [ordered]@{
      windows_service = 'RadlinaV3OAuthBeta'
      tunnel_service = 'RadlinaV3Tunnel'
      oauth_loopback = '127.0.0.1:7344'
      v2_loopback = '127.0.0.1:7337'
    }
    execution = [ordered]@{
      started_at = $startedAt
      checked_at = (Get-Date).ToUniversalTime().ToString('o')
      checks = $checks
    }
    output = [ordered]@{
      passed = $complete
      tunnel_token_present = $tokenPresent
      tunnel_service_status = [string]$tunnelService.Status
      public_tls_verified = $liveTls
      failures = @($failures)
    }
    acceptance = if ($complete -and $RequirePublicTls) {
      'WINDOWS_PUBLIC_OAUTH_SMOKE_PASS_NOT_V3_PRODUCTION_ACCEPTANCE'
    } elseif ($complete) {
      'WINDOWS_LOCAL_OAUTH_SERVICE_PASS_PUBLIC_TLS_PENDING'
    } else {
      'BLOCKED_FAIL_CLOSED'
    }
  }
  $output | ConvertTo-Json -Depth 9 -Compress
  if (-not $complete) { exit 2 }
} catch {
  $message = $_.Exception.Message
  if ($message.Length -gt 240) { $message = $message.Substring(0,240) }
  [ordered]@{
    schema_version='radlina.v3.windows-oauth-service-operational-check/v1'
    acceptance='BLOCKED_FAIL_CLOSED'
    error=$message
    checks=$checks
  } | ConvertTo-Json -Depth 7 -Compress
  exit 2
}
