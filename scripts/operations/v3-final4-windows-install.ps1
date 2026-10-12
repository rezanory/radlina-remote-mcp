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
$tasks=@(
  [pscustomobject]@{Name='RadlinaV3OwnerSigning';Script=$signer;Prefix=''},
  [pscustomobject]@{Name='RadlinaV3WindowsRecipient';Script=$operator;Prefix='$env:RADLINA_V3_WINDOWS_OWNER_OPERATOR=''1''; '},
  [pscustomobject]@{Name='RadlinaV3WindowsFleet';Script=$fleet;Prefix=('$env:RADLINA_V3_FLEET_SUPERVISOR=''1''; $env:RADLINA_V3_FINAL4_CONFIG_PATH='''+$config+'''; $env:RADLINA_V3_FINAL4_CONFIG_SHA256='''+$FinalFourConfigSha256+'''; ')}
)
foreach ($task in $tasks) {
  if (Get-ScheduledTask -TaskName $task.Name -TaskPath '\RadlinaV3\' -ErrorAction SilentlyContinue) {
    throw ('Existing V3 task must not be replaced: '+$task.Name)
  }
}
$principal=New-ScheduledTaskPrincipal -UserId 'LAPTOP-13QINEIF\Radlina' -LogonType Interactive -RunLevel Highest
$trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650)
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -StartWhenAvailable:$false -MultipleInstances IgnoreNew
foreach ($task in $tasks) {
  $command=$task.Prefix + "& '" + $node + "' '" + $task.Script + "'"
  $argument='-NoProfile -NonInteractive -Command "' + $command + '"'
  $action=New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument $argument -WorkingDirectory $release
  Register-ScheduledTask -TaskName $task.Name -TaskPath '\RadlinaV3\' -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
}
Write-Output 'V3_WINDOWS_FINAL4_INTERACTIVE_TASKS_INSTALLED'
Write-Output 'No V2 changes, physical canary/rollback or acceptance claimed.'
