# Radlina V3-only physical Windows final-four owner task installer.
# Source code only; this script is NOT executed in code-completion turns.
# Never changes V2 services, credentials, Tailscale, VPN or Git worktrees.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$ManifestSha256,
  [Parameter(Mandatory=$true)][string]$FinalFourConfigFile,
  [Parameter(Mandatory=$true)][string]$FinalFourConfigSha256,
  [switch]$Install
)
$ErrorActionPreference='Stop'
if (-not $Install) { throw 'Explicit -Install switch required' }
if ($ManifestSha256 -cnotmatch '^[a-f0-9]{64}$' -or $FinalFourConfigSha256 -cnotmatch '^[a-f0-9]{64}$') {
  throw 'Exact independently approved SHA256 manifests required'
}
if ([Environment]::MachineName -ne 'LAPTOP-13QINEIF') { throw 'Physical Windows V3 host required' }
$who=[Security.Principal.WindowsIdentity]::GetCurrent()
if ($who.Name.ToLowerInvariant() -ne 'laptop-13qineif\radlina') {
  throw 'Logged-in Windows owner required'
}
$principalCheck=New-Object Security.Principal.WindowsPrincipal($who)
if (-not $principalCheck.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Elevated interactive physical Windows owner required'
}
$node='C:\radlina-remote-mcp\.runtime\node-v24.20.0-win-x64\node.exe'
$release=Join-Path 'E:\radlina-v3-runtime\releases' $ManifestSha256
$manifest=Join-Path $release 'RELEASE_MANIFEST.json'
$config=(Resolve-Path -LiteralPath $FinalFourConfigFile).Path
if (-not (Test-Path -LiteralPath $node -PathType Leaf) -or -not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
  throw 'Staged V3 release or Node runtime missing'
}
if ((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ManifestSha256) {
  throw 'Exact staged V3 manifest SHA256 mismatched'
}
if ((Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash.ToLowerInvariant() -ne $FinalFourConfigSha256) {
  throw 'Owner-pinned V3 capability configuration changed'
}
$operator=Join-Path $release 'dist\scripts\operations\v3-windows-operator-cycle.js'
$fleet=Join-Path $release 'dist\scripts\operations\v3-windows-fleet-cycle.js'
$signer=Join-Path $release 'dist\scripts\operations\v3-owner-interactive-cycle.js'
foreach ($file in @($operator,$fleet,$signer)) {
  if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "V3 agent missing: $file" }
}
# Task actions MUST NOT pin their JS entrypoint to the initial release.
# Only the owner-installed, V3-only launcher has a stable path; it resolves
# the verified active release from RadlinaV3OAuthBeta.xml on every cycle.
$supervisor='E:\radlina-v3-runtime\supervisor'
$sourceLauncher=Join-Path $release 'scripts\operations\v3-final4-windows-task-launch.ps1'
$hiddenHelper=Join-Path $release 'scripts\operations\v3-owner-hidden-task-action.ps1'
if (-not (Test-Path -LiteralPath $hiddenHelper -PathType Leaf)) {
  throw 'Verified V3 hidden task action helper missing'
}
. $hiddenHelper
$launcher=Join-Path $supervisor 'v3-final4-windows-task-launch.ps1'
if (-not (Test-Path -LiteralPath $sourceLauncher -PathType Leaf)) {
  throw 'Version-safe V3 Windows task launcher not staged'
}
# Fail before making any filesystem/ACL changes when an existing scheduled
# task could require an owner-authorized migration instead of replacement.
foreach ($taskName in @('RadlinaV3OwnerSigning','RadlinaV3WindowsRecipient','RadlinaV3WindowsFleet')) {
  if (Get-ScheduledTask -TaskName $taskName -TaskPath '\RadlinaV3\' -ErrorAction SilentlyContinue) {
    throw ('Existing V3 task requires explicit version-safe migration: '+$taskName)
  }
}
New-Item -Path $supervisor -ItemType Directory -Force | Out-Null
if ((Get-Item -LiteralPath $supervisor).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
  throw 'V3 supervisor cannot be a symlink'
}
$aclExe=Join-Path $env:WINDIR 'System32\icacls.exe'
& $aclExe $supervisor '/inheritance:r' '/grant:r' 'LAPTOP-13QINEIF\Radlina:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' 'NT AUTHORITY\SYSTEM:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Unable to protect V3 supervisor directory ACL' }
if (Test-Path -LiteralPath $launcher -PathType Leaf) {
  if ((Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash.ToLowerInvariant() -ne
      (Get-FileHash -LiteralPath $sourceLauncher -Algorithm SHA256).Hash.ToLowerInvariant()) {
    throw 'Existing protected V3 launcher changed: explicit owner migration required'
  }
} elseif (-not (Test-Path -LiteralPath $launcher)) {
  Copy-Item -LiteralPath $sourceLauncher -Destination $launcher -ErrorAction Stop
} else {
  throw 'Unexpected V3 launcher filesystem object'
}
$tasks=@(
  [pscustomobject]@{Name='RadlinaV3OwnerSigning';Role='OwnerSigning'},
  [pscustomobject]@{Name='RadlinaV3WindowsRecipient';Role='WindowsRecipient'},
  [pscustomobject]@{Name='RadlinaV3WindowsFleet';Role='WindowsFleet'}
)
foreach ($task in $tasks) {
  if (Get-ScheduledTask -TaskName $task.Name -TaskPath '\RadlinaV3\' -ErrorAction SilentlyContinue) {
    throw ('Existing V3 task must not be replaced: '+$task.Name)
  }
}
# Isolated V3-only Windows Task Scheduler folder; never touch V2.
$scheduler=New-Object -ComObject Schedule.Service
$scheduler.Connect()
$rootFolder=$scheduler.GetFolder('\')
try {$null=$scheduler.GetFolder('\RadlinaV3')} catch {
  $null=$rootFolder.CreateFolder('RadlinaV3')
}
$principal=New-ScheduledTaskPrincipal -UserId 'LAPTOP-13QINEIF\Radlina' -LogonType Interactive -RunLevel Highest
$trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650)
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -StartWhenAvailable:$false -MultipleInstances IgnoreNew -Disable
foreach ($task in $tasks) {
  $argument='-NoProfile -NonInteractive -File "'+$launcher+'" -Role '+$task.Role+' -FinalFourConfigFile "'+$config+'" -FinalFourConfigSha256 '+$FinalFourConfigSha256
  $action=New-V3HiddenOwnerTaskAction -Role $task.Role -PowerShellArguments $argument -Supervisor $supervisor
  Register-ScheduledTask -TaskName $task.Name -TaskPath '\RadlinaV3\' -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
}
Write-Output 'V3_WINDOWS_FINAL4_INTERACTIVE_TASKS_INSTALLED'
Write-Output 'All three V3 tasks installed DISABLED pending scoped owner approval; no V2 changes, canary/rollback or acceptance claimed.'
