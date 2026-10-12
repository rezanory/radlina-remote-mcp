# Explicit migration of three existing V3 Windows owner tasks.
# Source only. Never invoked during code-only development.
# No V2 tasks, services, Tailscale, credentials or operator approval bypass.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$ExistingTaskHashesFile,
  [Parameter(Mandatory=$true)][string]$ExistingTaskHashesSha256,
  [Parameter(Mandatory=$true)][string]$FinalFourConfigFile,
  [Parameter(Mandatory=$true)][string]$FinalFourConfigSha256,
  [switch]$Migrate
)
$ErrorActionPreference='Stop'
if (-not $Migrate) { throw 'Explicit owner -Migrate required' }
$who=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($who)
if ([Environment]::MachineName -cne 'LAPTOP-13QINEIF' -or
    $who.Name.ToLowerInvariant() -cne 'laptop-13qineif\radlina' -or
    -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Owner must be physically logged in and elevated on registered V3 Windows'
}
foreach ($digest in @($ExistingTaskHashesSha256,$FinalFourConfigSha256)) {
  if ($digest -cnotmatch '^[a-f0-9]{64}$') { throw 'Exact owner-pinned SHA256 required' }
}
$manifestPath=(Resolve-Path -LiteralPath $ExistingTaskHashesFile -ErrorAction Stop).Path
$config=(Resolve-Path -LiteralPath $FinalFourConfigFile -ErrorAction Stop).Path
if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExistingTaskHashesSha256 -or
    (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash.ToLowerInvariant() -cne $FinalFourConfigSha256) {
  throw 'Owner-reviewed migration inputs changed'
}
if ($manifestPath -match '(?i)\\v2\\' -or $config -match '(?i)\\v2\\') {
  throw 'V2 paths cannot enter the V3 owner migration'
}
$expected=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($expected.schema -cne 'radlina.v3.windows-task-migration-pins/v1') {
  throw 'Unexpected Windows V3 task migration contract'
}
$taskNames=@('RadlinaV3OwnerSigning','RadlinaV3WindowsRecipient','RadlinaV3WindowsFleet')
$roles=@('OwnerSigning','WindowsRecipient','WindowsFleet')
$launcher='E:\radlina-v3-runtime\supervisor\v3-final4-windows-task-launch.ps1'
if (-not (Test-Path -LiteralPath $launcher -PathType Leaf) -or
    (Get-Item -LiteralPath $launcher).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
  throw 'Protected stable V3 task launcher must already be installed'
}
$taskPath='\RadlinaV3\'
$copies=@()
$sha=[Security.Cryptography.SHA256]::Create()
try {
  # Read-only exact current definitions BEFORE creating migration state.
  for ($i=0;$i -lt $taskNames.Length;$i++) {
    $name=$taskNames[$i]
    $hash=[string]$expected.$name
    if ($hash -cnotmatch '^[a-f0-9]{64}$') { throw ('Missing pinned task definition: '+$name) }
    $task=Get-ScheduledTask -TaskName $name -TaskPath $taskPath -ErrorAction Stop
    if ($task.Actions.Count -ne 1 -or $task.Principal.UserId -notmatch '(?i)radlina$') {
      throw ('Unrecognized original V3 task owner/action: '+$name)
    }
    $xml=Export-ScheduledTask -TaskName $name -TaskPath $taskPath -ErrorAction Stop
    $bytes=[Text.Encoding]::UTF8.GetBytes($xml)
    $actual=[Convert]::ToHexString($sha.ComputeHash($bytes)).ToLowerInvariant()
    if ($actual -cne $hash) { throw ('Owner hash of existing V3 task changed: '+$name) }
    $copies+= [pscustomobject]@{Name=$name;Role=$roles[$i];Xml=$xml;Task=$task}
  }
} finally { $sha.Dispose() }
$supervisor='E:\radlina-v3-runtime\supervisor'
$folder=Join-Path $supervisor 'owner-task-migrations'
New-Item -Path $folder -ItemType Directory -Force | Out-Null
if ((Get-Item -LiteralPath $folder).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
  throw 'Protected migration directory must not be a symlink'
}
$id=[guid]::NewGuid().ToString('N')
$session=Join-Path $folder $id
New-Item -Path $session -ItemType Directory -ErrorAction Stop | Out-Null
$stateFile=Join-Path $session 'state.json'
foreach ($item in $copies) {
  [IO.File]::WriteAllText((Join-Path $session ($item.Name+'.xml')),$item.Xml,[Text.UTF8Encoding]::new($false))
}
$state=[ordered]@{schema='radlina.v3.windows-task-migration/v1';migrationId=$id
  status='prepared';sourcePinSha256=$ExistingTaskHashesSha256;rolesUpdated=@()}
[IO.File]::WriteAllText($stateFile,($state|ConvertTo-Json -Compress -Depth 6),[Text.UTF8Encoding]::new($false))
try {
  foreach ($item in $copies) {
    $arguments='-NoProfile -NonInteractive -File "'+$launcher+'" -Role '+$item.Role+
      ' -FinalFourConfigFile "'+$config+'" -FinalFourConfigSha256 '+$FinalFourConfigSha256
    $action=New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument $arguments -WorkingDirectory $supervisor
    # Preserve exact original principal, triggers and settings.
    Set-ScheduledTask -TaskName $item.Name -TaskPath $taskPath -Action $action -ErrorAction Stop | Out-Null
    $state.rolesUpdated+= $item.Name
    $state.status='updating'
    [IO.File]::WriteAllText($stateFile,($state|ConvertTo-Json -Compress -Depth 6),[Text.UTF8Encoding]::new($false))
  }
  $state.status='migrated-not-accepted'
  [IO.File]::WriteAllText($stateFile,($state|ConvertTo-Json -Compress -Depth 6),[Text.UTF8Encoding]::new($false))
  Write-Output ('V3_OWNER_TASK_MIGRATION_RECORDED '+$id)
} catch {
  $state.status='uncertain-owner-reconcile-required'
  [IO.File]::WriteAllText($stateFile,($state|ConvertTo-Json -Compress -Depth 6),[Text.UTF8Encoding]::new($false))
  throw
}
