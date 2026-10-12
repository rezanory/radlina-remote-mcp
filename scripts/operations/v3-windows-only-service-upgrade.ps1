# Standalone V3 Windows-only OAuth upgrade. Does not turn on Final Four,
# access Mac, change V2, edit tunnel, mutate runtime secrets or acceptance.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$ReleaseManifestSha256,
  [Parameter(Mandatory=$true)][string]$ExpectedGitSha,
  [string]$OriginalXmlSha256,
  [switch]$Stage,
  [switch]$Apply
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if (([bool]$Stage -eq [bool]$Apply) -or
    [Environment]::MachineName -cne 'LAPTOP-13QINEIF' -or
    $ReleaseManifestSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $ExpectedGitSha -cnotmatch '^[0-9a-f]{40}$') {
  throw 'Explicit exact-host, pinned Git SHA and -Stage XOR -Apply required'
}
$who=[Security.Principal.WindowsIdentity]::GetCurrent().Name.ToLowerInvariant()
if ($who -notin @('nt authority\system','laptop-13qineif\radlina')) {
  throw 'Standalone V3 owner/SYSTEM operator required'
}
$root='E:\radlina-v3-runtime'
$active=Join-Path $root 'RadlinaV3OAuthBeta.xml'
$release=Join-Path (Join-Path $root 'releases') $ReleaseManifestSha256
$manifestFile=Join-Path $release 'RELEASE_MANIFEST.json'
$entry=Join-Path $release 'dist\scripts\operations\v3-oauth-readonly-daemon.js'
$service='RadlinaV3OAuthBeta'
if (-not (Test-Path -LiteralPath $manifestFile -PathType Leaf) -or
    -not (Test-Path -LiteralPath $entry -PathType Leaf) -or
    -not (Test-Path -LiteralPath $active -PathType Leaf)) {
  throw 'Standalone V3 source, entrypoint or original service XML missing'
}
foreach ($candidatePath in @($release,$manifestFile,$entry,$active)) {
  if ((Get-Item -LiteralPath $candidatePath).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)){
    throw 'V3 release/service symlink refused'
  }
}
if ((Get-FileHash -LiteralPath $manifestFile -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ReleaseManifestSha256) {
  throw 'Exact V3 Release Manifest digest mismatch'
}
$manifest=Get-Content -LiteralPath $manifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.schema -cne 'radlina.release-manifest.v2' -or
    $manifest.source.gitSha -cne $ExpectedGitSha -or
    @($manifest.files).Count -lt 10000) {
  throw 'Refuse non-self-contained or unpinned V3 Windows artifact'
}
$originalHash=(Get-FileHash -LiteralPath $active -Algorithm SHA256).Hash.ToLowerInvariant()
[xml]$doc=Get-Content -LiteralPath $active -Raw -Encoding UTF8
if ([string]$doc.service.id -cne $service -or
    [string]$doc.service.arguments -cne '--enable-source-maps dist/scripts/operations/v3-oauth-readonly-daemon.js' -or
    [string]$doc.service.executable -cne 'C:\radlina-remote-mcp\.runtime\node-v24.20.0-win-x64\node.exe') {
  throw 'Current running service is not the isolated approved V3 OAuth executable'
}
$final4=@($doc.SelectNodes('/service/env[@name="RADLINA_V3_FINAL4_ENABLE"]'))
if ($final4.Count -gt 1 -or ($final4.Count -eq 1 -and $final4[0].GetAttribute('value') -cne '0')) {
  throw 'This installer cannot upgrade an already enabled physical Final Four deployment'
}
$working=$doc.SelectSingleNode('/service/workingdirectory')
$previous=[string]$working.InnerText
if ($previous -notlike 'E:\radlina-v3-runtime\releases\*' -or $previous.Contains('..')) {
  throw 'Original V3 working directory is outside isolated V3 releases'
}
$working.InnerText=$release
$candidateDir=Join-Path $root 'candidates'
[void](New-Item -ItemType Directory -Path $candidateDir -Force)
$candidate=Join-Path $candidateDir ('RadlinaV3OAuthBeta.windows-only.'+$ReleaseManifestSha256+'.xml')
if($Stage){
  if(Test-Path -LiteralPath $candidate){throw 'V3 staged candidate already exists; reconcile exact SHA'}
  $doc.Save($candidate)
  $candidateSha=(Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
  [pscustomobject]@{
    outcome='V3_WINDOWS_ONLY_SERVICE_CONFIG_STAGED_NOT_APPLIED'
    service=$service;sourceGitSha=$ExpectedGitSha;releaseManifest=$ReleaseManifestSha256
    originalXmlSha256=$originalHash;candidateXmlSha256=$candidateSha
    candidate=$candidate;previousRelease=$previous;v2Changed=$false
  }|ConvertTo-Json -Compress
  return
}
if($OriginalXmlSha256 -cnotmatch '^[0-9a-f]{64}$' -or $originalHash -cne $OriginalXmlSha256){
  throw 'Owner-pinned original service XML changed before deployment'
}
if(-not (Test-Path -LiteralPath $candidate -PathType Leaf)){
  throw 'Explicitly staged V3 candidate required before -Apply'
}
if((Get-Service -Name 'RadlinaRemoteMCP' -ErrorAction Stop).Status -ne 'Running' -or
   (Get-Service -Name $service -ErrorAction Stop).Status -ne 'Running'){
  throw 'V2 and existing V3 must be running before isolated Windows-only upgrade'
}
[xml]$saved=Get-Content -LiteralPath $candidate -Raw -Encoding UTF8
if($saved.service.id -cne $service -or
   [string]$saved.service.workingdirectory -cne $release -or
   [string]$saved.service.arguments -cne [string]$doc.service.arguments){
  throw 'Candidate V3 service definition is not the owner-staged immutable one'
}
# Compare every other XML field by rewriting only active workingdirectory and
# hashing a fresh canonical staged serialization. Any altered candidate is denied.
$compare=Join-Path $candidateDir ('v3-exact-'+[guid]::NewGuid().ToString('N')+'.xml')
try{
  $doc.Save($compare)
  if((Get-FileHash -LiteralPath $compare -Algorithm SHA256).Hash.ToLowerInvariant() -cne
     (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()){
    throw 'Staged WinSW candidate changed or carries unapproved service settings'
  }
}finally{Remove-Item -LiteralPath $compare -Force -ErrorAction SilentlyContinue}
$backupRoot=Join-Path $root 'backups'
[void](New-Item -ItemType Directory -Path $backupRoot -Force)
$backup=Join-Path $backupRoot ('RadlinaV3OAuthBeta.windows-only.'+[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()+'.xml')
Copy-Item -LiteralPath $active -Destination $backup -ErrorAction Stop
function AssertLocalV3Healthy(){
  $health=Invoke-RestMethod -Uri 'http://127.0.0.1:7344/auth-health' -TimeoutSec 4
  $oauth=Invoke-RestMethod -Uri 'http://127.0.0.1:7344/.well-known/oauth-authorization-server' -TimeoutSec 4
  $listener=@(Get-NetTCPConnection -State Listen -LocalPort 7344 -ErrorAction SilentlyContinue)
  if($health.status -cne 'healthy' -or $health.signingReady -ne $true -or
     $health.tokenEndpointReady -ne $true -or
     $oauth.issuer -cne 'https://v3-mcp.radlina.com' -or
     $listener.Count -ne 1 -or $listener[0].LocalAddress -cne '127.0.0.1' -or
     (Get-Service RadlinaRemoteMCP).Status -ne 'Running'){
    throw 'Isolated V3 local OAuth or preserved V2 service is unhealthy'
  }
}
$activated=$false
try{
  Stop-Service -Name $service -ErrorAction Stop
  Copy-Item -LiteralPath $candidate -Destination $active -Force -ErrorAction Stop
  Start-Service -Name $service -ErrorAction Stop
  for($attempt=1;$attempt -le 24;$attempt++){
    try{AssertLocalV3Healthy;$activated=$true;break}
    catch{Start-Sleep -Milliseconds 750}
  }
  if(-not $activated){throw 'New standalone V3 OAuth failed real listener/issuer validation'}
  [pscustomobject]@{
    outcome='V3_WINDOWS_ONLY_SERVICE_ACTIVATED_LOCAL_OAUTH_PASS'
    service=$service;releaseManifest=$ReleaseManifestSha256;sourceGitSha=$ExpectedGitSha
    previousRelease=$previous;activeRelease=$release
    backupXml=$backup;v2Modified=$false
    finalFourEnabled=$false;macProductionAccepted=$false
  }|ConvertTo-Json -Compress
}catch{
  $failure=$_.Exception.Message
  try{
    Stop-Service -Name $service -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $backup -Destination $active -Force -ErrorAction Stop
    Start-Service -Name $service -ErrorAction Stop
    $restored=$false
    for($attempt=1;$attempt -le 24;$attempt++){
      try{AssertLocalV3Healthy;$restored=$true;break}catch{Start-Sleep -Milliseconds 750}
    }
    if(-not $restored){throw 'Original service did not recover after rollback'}
  }catch{
    throw ('V3-only upgrade failed; AUTOMATIC ROLLBACK NOT CONFIRMED; original='+$failure+'; recovery='+$_.Exception.Message)
  }
  throw ('V3-only upgrade rejected and independently healthy original restored: '+$failure)
}
