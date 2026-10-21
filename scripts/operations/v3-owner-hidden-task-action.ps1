# V3-only GUI-less owner task action. Same signed owner, role and 1-minute trigger.
# The Windows Script Host launcher does not allocate a visible console.
# Never changes V2, trust checks, task principals or recipient consent.
function New-V3HiddenOwnerTaskAction {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('OwnerSigning','WindowsRecipient','WindowsFleet')]
    [string]$Role,
    [Parameter(Mandatory=$true)][string]$PowerShellArguments,
    [Parameter(Mandatory=$true)][string]$Supervisor
  )
  $ErrorActionPreference='Stop'
  $powerShell=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $wscript=Join-Path $env:WINDIR 'System32\wscript.exe'
  if (-not (Test-Path -LiteralPath $powerShell -PathType Leaf) -or
      -not (Test-Path -LiteralPath $wscript -PathType Leaf)) {
    throw 'Required Windows V3 background host missing'
  }
  if ($PowerShellArguments -notmatch '(?i)v3-final4-windows-task-launch\.ps1' -or
      $PowerShellArguments -notmatch ('(?i)(?:^|\s)-Role\s+'+[regex]::Escape($Role)+'(?:\s|$)')) {
    throw 'V3 task role or immutable launcher changed'
  }
  $supervisorDir=(Resolve-Path -LiteralPath $Supervisor -ErrorAction Stop).Path
  if ((Get-Item -LiteralPath $supervisorDir).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
    throw 'V3 supervisor symlink refused'
  }
  $hidden=Join-Path $supervisorDir ('v3-'+$Role+'-background.vbs')
  $command='"'+$powerShell+'" '+$PowerShellArguments
  $vbs=@(
    'Option Explicit',
    'Dim shell, command, exitCode',
    'Set shell = CreateObject("WScript.Shell")',
    ('command = "'+$command.Replace('"','""')+'"'),
    'exitCode = shell.Run(command, 0, True)',
    'WScript.Quit exitCode'
  ) -join "`r`n"
  $vbs+="`r`n"
  if (Test-Path -LiteralPath $hidden -PathType Leaf) {
    $existing=Get-Item -LiteralPath $hidden
    if ($existing.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
        [IO.File]::ReadAllText($hidden) -cne $vbs) {
      throw 'Existing V3 hidden task launcher changed; explicit owner migration required'
    }
  } elseif (Test-Path -LiteralPath $hidden) {
    throw 'Unexpected V3 background launcher filesystem object'
  } else {
    [IO.File]::WriteAllText($hidden,$vbs,[Text.UTF8Encoding]::new($false))
  }
  New-ScheduledTaskAction -Execute $wscript -Argument ('//B //Nologo "'+$hidden+'"') -WorkingDirectory $supervisorDir
}
