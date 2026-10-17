# V3 final-four gateway service configuration. SOURCE ONLY: not executed in the coding phase.
# Stages a separate WinSW XML without exposing bearer/HMAC secrets in the XML.
# -Stage creates a candidate; -Apply requires a separate explicit human deployment decision.
[CmdletBinding(DefaultParameterSetName='Stage')]
param(
  [Parameter(Mandatory=$true)][string]$ReleaseManifestSha256,
  [Parameter(Mandatory=$true)][string]$OwnerBindingConfigPath,
  [Parameter(Mandatory=$true)][string]$OwnerBindingConfigSha256,
  [Parameter(Mandatory=$true)][string]$MacOperatorPolicyPath,
  [Parameter(Mandatory=$true)][string]$MacOperatorPolicySha256,
  [Parameter(Mandatory=$true)][string]$S03WriterTokenFile,
  [Parameter(Mandatory=$true)][string]$S03HmacDpapiFile,
  [Parameter(ParameterSetName='Stage')][switch]$Stage,
  [Parameter(ParameterSetName='Apply',Mandatory=$true)][switch]$Apply
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ([Environment]::MachineName -ne 'LAPTOP-13QINEIF') {
  throw 'Only exact owner-controlled V3 Windows service host is permitted'
}
if (([Security.Principal.WindowsIdentity]::GetCurrent().Name).ToLowerInvariant() -ne 'nt authority\system' -and
    ([Security.Principal.WindowsIdentity]::GetCurrent().Name).ToLowerInvariant() -ne 'laptop-13qineif\radlina') {
  throw 'Only V3 owner or SYSTEM service configuration principal is permitted'
}
$hashPattern='^[0-9a-f]{64}$'
foreach ($digest in @($ReleaseManifestSha256,$OwnerBindingConfigSha256,$MacOperatorPolicySha256)) {
  if ($digest -cnotmatch $hashPattern) {throw 'Pinned SHA256 identifier required'}
}
function ExactPrivateFile([string]$p,[string]$label) {
  if (-not [IO.Path]::IsPathRooted($p) -or $p -notlike 'E:\*' -or $p -match '\.\.' -or
      $p.ToLowerInvariant().Contains('\v2\') -or -not (Test-Path -LiteralPath $p -PathType Leaf)) {
    throw "Existing isolated V3 private file missing: $label"
  }
  $obj=Get-Item -LiteralPath $p
  if ($obj.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "V3 private file cannot be a symlink: $label"
  }
  return $obj.FullName
}
$config=ExactPrivateFile $OwnerBindingConfigPath 'owner binding policy'
$macPolicy=ExactPrivateFile $MacOperatorPolicyPath 'signed Mac capability policy'
$token=ExactPrivateFile $S03WriterTokenFile 'independent Mac witness token'
$hmac=ExactPrivateFile $S03HmacDpapiFile 'machine-DPAPI S03 HMAC'
if ((Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash.ToLowerInvariant() -cne $OwnerBindingConfigSha256) {
  throw 'Owner-pinned V3 binding policy digest mismatch'
}
# Development-only public policies can be generated before final reviewer
# approval, but must NEVER activate real physical ports or reach WinSW.
$binding=Get-Content -LiteralPath $config -Raw -Encoding UTF8 | ConvertFrom-Json
$devTag=$binding.PSObject.Properties['developmentOnly']
$activationTag=$binding.PSObject.Properties['productionActivationPermitted']
$reviewerTag=$binding.PSObject.Properties['independentReviewerPublicKeyPem']
if ($binding.schema -cne 'radlina.v3.final-four-production-binding/v1' -or
    ($null -ne $devTag -and $devTag.Value -eq $true) -or
    ($null -ne $activationTag -and $activationTag.Value -eq $false) -or
    $null -eq $reviewerTag -or
    [string]::IsNullOrWhiteSpace([string]$reviewerTag.Value)) {
  throw 'Development-only or unreviewed V3 configuration cannot be staged or applied to production service'
}
if ((Get-FileHash -LiteralPath $macPolicy -Algorithm SHA256).Hash.ToLowerInvariant() -cne $MacOperatorPolicySha256) {
  throw 'Owner-signed V3 Mac policy digest mismatch'
}
$manifest=ExactPrivateFile ('E:\radlina-v3-runtime\releases\'+$ReleaseManifestSha256+'\RELEASE_MANIFEST.json') 'V3 candidate manifest'
if ((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ReleaseManifestSha256) {
  throw 'V3 release content must be immutable and pinned'
}
$activePath='E:\radlina-v3-runtime\RadlinaV3OAuthBeta.xml'
$active=ExactPrivateFile $activePath 'dedicated V3 WinSW config'
[xml]$doc=Get-Content -LiteralPath $active -Raw -Encoding UTF8
if ($doc.service.id -cne 'RadlinaV3OAuthBeta') {
  throw 'Never change V2 or an unknown service'
}
$service=$doc.service
$working=$doc.SelectSingleNode('/service/workingdirectory')
if ($null -eq $working) {throw 'Dedicated V3 release working directory missing'}
$working.InnerText='E:\radlina-v3-runtime\releases\'+$ReleaseManifestSha256
$settings=@{
  'RADLINA_V3_PUBLIC_URL'='https://v3-mcp.radlina.com';
  'RADLINA_V3_FINAL4_ENABLE'='1';
  'RADLINA_V3_MAC_SIGNED_HEARTBEAT_ENABLED'='1';
  'RADLINA_V3_FINAL4_CONFIG_PATH'=$config;
  'RADLINA_V3_FINAL4_CONFIG_SHA256'=$OwnerBindingConfigSha256;
  'RADLINA_V3_SIGNED_MAC_OPERATOR_POLICY_PATH'=$macPolicy;
  'RADLINA_V3_SIGNED_MAC_OPERATOR_POLICY_SHA256'=$MacOperatorPolicySha256;
  'RADLINA_V3_S03_WRITER_TOKEN_FILE'=$token;
  'RADLINA_V3_S03_HMAC_DPAPI_FILE'=$hmac
}
foreach ($item in $settings.GetEnumerator()) {
  if ($item.Value -match '^(Bearer|sk-|eyJ)' -or $item.Name.EndsWith('_KEY') -or
      $item.Name.EndsWith('_TOKEN')) {
    throw 'Plaintext credentials may never be saved into WinSW configuration'
  }
  $nodes=@($doc.SelectNodes('/service/env[@name="'+$item.Key+'"]'))
  if ($nodes.Count -gt 1) {throw 'Conflicting existing V3 service environment entries'}
  if ($nodes.Count -eq 1) {
    $nodes[0].SetAttribute('value',[string]$item.Value)
  } else {
    $env=$doc.CreateElement('env')
    $env.SetAttribute('name',[string]$item.Key)
    $env.SetAttribute('value',[string]$item.Value)
    [void]$service.AppendChild($env)
  }
}
$candidates='E:\radlina-v3-runtime\candidates'
[void](New-Item -ItemType Directory -Path $candidates -Force)
$candidate=Join-Path $candidates ('RadlinaV3OAuthBeta.final4.'+$ReleaseManifestSha256+'.xml')
# Stage and Apply are separate owner-approved steps. The Apply step must
# consume the *same* pre-staged, verified XML; it must not create a new candidate
# or silently replace one that differs from the currently pinned policy.
if (Test-Path -LiteralPath $candidate) {
  $existing=Get-Item -LiteralPath $candidate -ErrorAction Stop
  if ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint -or
      -not ($existing -is [System.IO.FileInfo])) {
    throw 'V3 candidate must be an existing regular non-symlink file'
  }
  [xml]$stagedDoc=Get-Content -LiteralPath $candidate -Raw -Encoding UTF8 -ErrorAction Stop
  if ($stagedDoc.OuterXml -cne $doc.OuterXml) {
    throw 'Previously staged V3 candidate does not match current owner-pinned inputs'
  }
  Write-Output ('V3_FINAL4_CANDIDATE_VERIFIED '+$candidate)
} elseif ($Apply) {
  throw 'V3 final-four Apply requires a prior separately staged owner-pinned candidate'
} else {
  $doc.Save($candidate)
  Write-Output ('V3_FINAL4_CANDIDATE_STAGED '+$candidate)
}
if (-not $Apply) {
  Write-Output 'V2 remains untouched; no deployment or acceptance was performed'
  return
}
# This branch of the installer belongs ONLY to the later authorized deployment phase.
$backup=$activePath+'.before-final4.'+([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())+'.xml'
Copy-Item -LiteralPath $activePath -Destination $backup -ErrorAction Stop
try {
  Stop-Service -Name 'RadlinaV3OAuthBeta' -ErrorAction Stop
  Copy-Item -LiteralPath $candidate -Destination $activePath -Force -ErrorAction Stop
  Start-Service -Name 'RadlinaV3OAuthBeta' -ErrorAction Stop
  Write-Output ('V3_FINAL4_SERVICE_CONFIG_INSTALLED backup='+$backup)
} catch {
  Copy-Item -LiteralPath $backup -Destination $activePath -Force
  try {Start-Service -Name 'RadlinaV3OAuthBeta' -ErrorAction Stop} catch {}
  throw 'V3 activation rejected and isolated configuration restored'
}
