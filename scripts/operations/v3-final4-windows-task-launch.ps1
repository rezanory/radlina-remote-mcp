# Immutable-role V3 task launcher; installed in a separate supervisor folder.
# A V3 service release switch updates all task entrypoints automatically.
# This script is never executed during the code-only completion phase.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidateSet('OwnerSigning','WindowsRecipient','WindowsFleet')]
  [string]$Role,
  [Parameter(Mandatory=$true)][string]$FinalFourConfigFile,
  [Parameter(Mandatory=$true)][string]$FinalFourConfigSha256
)
$ErrorActionPreference='Stop'
if ([Environment]::MachineName -ne 'LAPTOP-13QINEIF') {
  throw 'Dedicated Windows V3 host required'
}
$who=[Security.Principal.WindowsIdentity]::GetCurrent()
if ($who.Name.ToLowerInvariant() -ne 'laptop-13qineif\radlina') {
  throw 'V3 task must run under the real interactive Windows owner'
}
if ($FinalFourConfigSha256 -cnotmatch '^[a-f0-9]{64}$') {
  throw 'Owner-signed V3 config digest required'
}
$config=(Resolve-Path -LiteralPath $FinalFourConfigFile -ErrorAction Stop).Path
if ($config -match '(?i)\\v2\\' -or
    (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash.ToLowerInvariant() -cne $FinalFourConfigSha256) {
  throw 'V3 final-four owner configuration changed'
}
$serviceFile='E:\radlina-v3-runtime\RadlinaV3OAuthBeta.xml'
if (-not (Test-Path -LiteralPath $serviceFile -PathType Leaf)) {
  throw 'Standalone V3 service configuration unavailable'
}
[xml]$service=Get-Content -LiteralPath $serviceFile -Raw -ErrorAction Stop
if ([string]$service.service.id -cne 'RadlinaV3OAuthBeta') {
  throw 'Dedicated V3 service identity mismatch'
}
$root='E:\radlina-v3-runtime\releases'
$requested=[string]$service.service.workingdirectory
if ([string]::IsNullOrWhiteSpace($requested) -or $requested.Contains('..')) {
  throw 'Invalid V3 active release pointer'
}
$manifestSha=Split-Path -Path $requested -Leaf
if ($manifestSha -cnotmatch '^[a-f0-9]{64}$') {
  throw 'V3 active release pointer is not a manifest SHA256'
}
$directory=(Resolve-Path -LiteralPath $requested -ErrorAction Stop).Path
$expected=Join-Path $root $manifestSha
if (-not [string]::Equals($directory,$expected,[StringComparison]::OrdinalIgnoreCase)) {
  throw 'V3 active release escaped independently staged root'
}
if ((Get-Item -LiteralPath $directory).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
  throw 'V3 release directory symlink refused'
}
$manifest=Join-Path $directory 'RELEASE_MANIFEST.json'
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf) -or
    (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifestSha) {
  throw 'Active V3 release manifest failed integrity validation'
}
$node='C:\radlina-remote-mcp\.runtime\node-v24.20.0-win-x64\node.exe'
if (-not (Test-Path -LiteralPath $node -PathType Leaf)) {
  throw 'Owner-approved Node runtime unavailable'
}
$entry=@{
  'OwnerSigning'='dist\scripts\operations\v3-owner-interactive-cycle.js'
  'WindowsRecipient'='dist\scripts\operations\v3-windows-operator-cycle.js'
  'WindowsFleet'='dist\scripts\operations\v3-windows-fleet-cycle.js'
}[$Role]
$script=Join-Path $directory $entry
if (-not (Test-Path -LiteralPath $script -PathType Leaf)) {
  throw 'Required V3 executable entrypoint not included in active release'
}
if ((Get-Item -LiteralPath $script).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
  throw 'V3 agent entrypoint cannot be a symlink'
}
if ($Role -ceq 'WindowsRecipient') {
  $env:RADLINA_V3_WINDOWS_OWNER_OPERATOR='1'
}
if ($Role -ceq 'WindowsFleet') {
  $env:RADLINA_V3_FLEET_SUPERVISOR='1'
  $env:RADLINA_V3_FINAL4_CONFIG_PATH=$config
  $env:RADLINA_V3_FINAL4_CONFIG_SHA256=$FinalFourConfigSha256
}
Push-Location -LiteralPath $directory
try {
  & $node $script
  if ($LASTEXITCODE -ne 0) { throw ('V3 '+$Role+' exited with failure') }
} finally {
  Pop-Location
}
