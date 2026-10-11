param(
  [string]$BaseUrl = "https://v3-mcp.radlina.com"
)

$ErrorActionPreference = "Stop"
$base = $BaseUrl.TrimEnd("/")
$resourceUrl = $base + "/mcp"
$metadataPath = "/.well-known/oauth-protected-resource/mcp"
$metadataUrl = $base + $metadataPath
$results = [ordered]@{}
$failures = New-Object System.Collections.Generic.List[string]

function AssertCheck([string]$Name, [bool]$Passed) {
  $script:results[$Name] = $Passed
  if (-not $Passed) { $script:failures.Add($Name) }
}

function IsSafeHttpsEndpoint([object]$Url, [string]$Origin) {
  if ($null -eq $Url) { return $false }
  try {
    $uri = [System.Uri]([string]$Url)
    return $uri.Scheme -eq "https" -and $uri.GetLeftPart([System.UriPartial]::Authority) -eq $Origin
  } catch { return $false }
}

function StatusWithHeader([string]$Target, [string]$Method, [string]$Body) {
  try {
    $resp = if ($Method -eq "POST") {
      Invoke-WebRequest -UseBasicParsing -Method POST -Uri $Target -Body $Body -ContentType "application/json" -TimeoutSec 12
    } else {
      Invoke-WebRequest -UseBasicParsing -Method GET -Uri $Target -TimeoutSec 12
    }
    return @{ status = [int]$resp.StatusCode; challenge = [string]$resp.Headers["WWW-Authenticate"] }
  } catch {
    if ($_.Exception.Response) {
      $resp = $_.Exception.Response
      return @{ status = [int]$resp.StatusCode; challenge = [string]$resp.Headers["WWW-Authenticate"] }
    }
    return @{ status = 0; challenge = "" }
  }
}

try {
  if (-not $base.StartsWith("https://", [System.StringComparison]::Ordinal)) { throw "HTTPS origin is required" }
  $oauth = Invoke-RestMethod -UseBasicParsing -Uri ($base + "/.well-known/oauth-authorization-server") -TimeoutSec 12
  $resource = Invoke-RestMethod -UseBasicParsing -Uri $metadataUrl -TimeoutSec 12

  AssertCheck "oauth_issuer_matches" ([string]$oauth.issuer -ceq $base)
  AssertCheck "resource_uri_matches_mcp" ([string]$resource.resource -ceq $resourceUrl)
  AssertCheck "authorization_server_links_issuer" (@($resource.authorization_servers) -ccontains $base)
  AssertCheck "auth_endpoint_https_same_origin" (IsSafeHttpsEndpoint $oauth.authorization_endpoint $base)
  AssertCheck "token_endpoint_https_same_origin" (IsSafeHttpsEndpoint $oauth.token_endpoint $base)
  AssertCheck "registration_endpoint_https_same_origin" (IsSafeHttpsEndpoint $oauth.registration_endpoint $base)
  AssertCheck "dynamic_registration_advertised" (![string]::IsNullOrWhiteSpace([string]$oauth.registration_endpoint))
  AssertCheck "pkce_s256_advertised" (@($oauth.code_challenge_methods_supported) -contains "S256")
  AssertCheck "public_oauth_client_supported" (@($oauth.token_endpoint_auth_methods_supported) -contains "none")
  AssertCheck "read_scope_advertised" (@($oauth.scopes_supported) -contains "device:read")
  AssertCheck "forbidden_admin_scope_not_advertised" (@($oauth.scopes_supported) -notcontains "admin")

  $challenge = StatusWithHeader $resourceUrl "POST" '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
  AssertCheck "anonymous_mcp_rejected_401" ($challenge.status -eq 401)
  AssertCheck "bearer_challenge_advertises_resource_metadata" (
    $challenge.challenge.StartsWith("Bearer", [System.StringComparison]::Ordinal) -and
    $challenge.challenge.Contains('resource_metadata="' + $metadataUrl + '"')
  )

  $privilege = StatusWithHeader ($base + "/authorize?scope=admin") "GET" ""
  AssertCheck "admin_scope_rejected_400" ($privilege.status -eq 400)

  $passed = $failures.Count -eq 0
  [ordered]@{
    schema_version = "radlina.v3.chatgpt-mcp-oauth-discovery-conformance/v1"
    test_type = "EXTERNAL_REAL_HTTPS_READ_ONLY"
    verified_issuer = $base
    protected_resource = $resourceUrl
    protected_resource_metadata_url = $metadataUrl
    checks = $results
    outcome = if($passed) { "PASS_CHATGPT_OAUTH_DISCOVERY_ONLY" } else { "BLOCKED_FAIL_CLOSED" }
    failures = @($failures)
    production_ready = $false
    chatgpt_app_connected = $false
    v2_modified = $false
  } | ConvertTo-Json -Depth 8 -Compress
  if (-not $passed) { exit 2 }
} catch {
  $errName = $_.Exception.GetType().Name
  [ordered]@{
    schema_version = "radlina.v3.chatgpt-mcp-oauth-discovery-conformance/v1"
    outcome = "BLOCKED_FAIL_CLOSED"
    failure_type = $errName
    checks = $results
    production_ready = $false
  } | ConvertTo-Json -Depth 6 -Compress
  exit 2
}
