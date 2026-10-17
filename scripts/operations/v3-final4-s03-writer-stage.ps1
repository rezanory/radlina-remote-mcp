# V3 S03 writer secret preparation — owner-authorized staging only.
# Not invoked by the technical coding session. Never outputs secret values.
# Input files must already have been securely shared with the physical Mac.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$PrivateBearerInputFile,
  [Parameter(Mandatory=$true)][string]$PrivateHmacBase64InputFile,
  [Parameter(Mandatory=$true)][string]$PrivateOutputDirectory,
  [switch]$Stage
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Security
if (-not $Stage -or [Environment]::MachineName -cne 'LAPTOP-13QINEIF') {
  throw 'Explicit physical owner V3 S03 staging required'
}
$who=[Security.Principal.WindowsIdentity]::GetCurrent()
if ($who.Name.ToLowerInvariant() -cne 'laptop-13qineif\radlina') {
  throw 'Real interactive Windows V3 owner is required to prepare S03 credentials'
}
if ([IO.Path]::GetFullPath($PrivateOutputDirectory) -cnotmatch '^E:\\radlina-v3-oauth-standalone\\final4\\') {
  throw 'V3 secret outputs must remain under isolated E: final-four state'
}
function PrivateFile([string]$Path,[string]$Name) {
  if (-not [IO.Path]::IsPathRooted($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "Pre-provisioned private $Name file missing"
  }
  $object=Get-Item -LiteralPath $Path
  if ($object.Length -lt 40 -or $object.Length -gt 4096 -or
      ($object.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw "Invalid bounded private file: $Name"
  }
  return $object.FullName
}
$bearerPath=PrivateFile $PrivateBearerInputFile 'S03 bearer'
$hmacPath=PrivateFile $PrivateHmacBase64InputFile 'S03 HMAC'
$bearer=[IO.File]::ReadAllText($bearerPath,[Text.Encoding]::UTF8).Trim()
$hmacText=[IO.File]::ReadAllText($hmacPath,[Text.Encoding]::UTF8).Trim()
if ($bearer.Length -lt 32 -or $bearer.Length -gt 512 -or
    $bearer -match '\s' -or
    $hmacText -cnotmatch '^[A-Za-z0-9+/]+={0,2}$') {
  throw 'Explicit S03 credentials invalid; no random fallback generated'
}
$hmacBytes=[Convert]::FromBase64String($hmacText)
if ($hmacBytes.Length -lt 32 -or $hmacBytes.Length -gt 128) {
  throw 'S03 HMAC secret must be 256–1024 bits'
}
[void](New-Item -ItemType Directory -Path $PrivateOutputDirectory -Force)
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach ($account in @($who.User.Value,'S-1-5-18','S-1-5-32-544')) {
  $sid=New-Object Security.Principal.SecurityIdentifier($account)
  $rule=New-Object Security.AccessControl.FileSystemAccessRule(
    $sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'
  )
  $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $PrivateOutputDirectory -AclObject $acl
$tokenOut=Join-Path $PrivateOutputDirectory 's03-writer-token.secret'
$hmacOut=Join-Path $PrivateOutputDirectory 's03-writer-hmac.dpapi'
if ((Test-Path -LiteralPath $tokenOut) -or (Test-Path -LiteralPath $hmacOut)) {
  throw 'Existing V3 writer credentials cannot be rotated or overwritten by staging'
}
try {
  # Machine-scoped DPAPI is required because only the isolated V3 SYSTEM
  # gateway uses this HMAC. No secret itself is placed in WinSW environment.
  $sealed=[Security.Cryptography.ProtectedData]::Protect(
    $hmacBytes,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine
  )
  [IO.File]::WriteAllText($hmacOut,[Convert]::ToBase64String($sealed),[Text.Encoding]::ASCII)
  [IO.File]::WriteAllText($tokenOut,$bearer,[Text.Encoding]::UTF8)
  foreach ($file in @($tokenOut,$hmacOut)) {
    $meta=Get-Item -LiteralPath $file
    if ($meta.Attributes -band [IO.FileAttributes]::ReparsePoint) {
      throw 'Secret outputs must not be symlinks'
    }
    $fileAcl=New-Object Security.AccessControl.FileSecurity
    $fileAcl.SetAccessRuleProtection($true,$false)
    foreach ($account in @($who.User.Value,'S-1-5-18','S-1-5-32-544')) {
      $sid=New-Object Security.Principal.SecurityIdentifier($account)
      $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','Allow')
      $fileAcl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $file -AclObject $fileAcl
  }
  Write-Output ('V3_S03_WRITER_SECRETS_STAGED tokenFile='+$tokenOut+' hmacDpapiFile='+$hmacOut)
  Write-Output 'No secret material displayed, no service changed and no test performed'
} finally {
  if ($null -ne $hmacBytes) { [Array]::Clear($hmacBytes,0,$hmacBytes.Length) }
  if ($null -ne $sealed) { [Array]::Clear($sealed,0,$sealed.Length) }
}
