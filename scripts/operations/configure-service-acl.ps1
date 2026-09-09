[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this script from an elevated PowerShell terminal.'
}

$stateDirectory = Join-Path $projectRoot '.state'
$workspaceDirectory = Join-Path $projectRoot 'workspace'
New-Item -ItemType Directory -Force -Path $stateDirectory, $workspaceDirectory | Out-Null

$administratorSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$localServiceSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-19')
$authenticatedUsersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-11')
$builtinUsersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$none = [Security.AccessControl.PropagationFlags]::None
$allow = [Security.AccessControl.AccessControlType]::Allow

$rootAcl = [Security.AccessControl.DirectorySecurity]::new()
$rootAcl.SetOwner($identity.User)
$rootAcl.SetAccessRuleProtection($true, $false)
foreach ($entry in @(
    @($identity.User, [Security.AccessControl.FileSystemRights]::FullControl),
    @($administratorSid, [Security.AccessControl.FileSystemRights]::FullControl),
    @($systemSid, [Security.AccessControl.FileSystemRights]::FullControl),
    @($localServiceSid, [Security.AccessControl.FileSystemRights]::ReadAndExecute)
  )) {
  [void]$rootAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($entry[0], $entry[1], $inheritance, $none, $allow))
}
Set-Acl -LiteralPath $projectRoot -AclObject $rootAcl

foreach ($writableDirectory in @($stateDirectory, $workspaceDirectory)) {
  $acl = Get-Acl -LiteralPath $writableDirectory
  $acl.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
      $localServiceSid,
      [Security.AccessControl.FileSystemRights]::Modify,
      $inheritance,
      $none,
      $allow
    ))
  Set-Acl -LiteralPath $writableDirectory -AclObject $acl
}

$rootCheck = Get-Acl -LiteralPath $projectRoot
$forbidden = @($rootCheck.Access | Where-Object {
    $sid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier])
    $sid -eq $authenticatedUsersSid -or $sid -eq $builtinUsersSid
  })
if ($rootCheck.AreAccessRulesProtected -ne $true -or $forbidden.Count -gt 0) {
  throw 'project ACL verification failed closed'
}
$localServiceRootRules = @($rootCheck.Access | Where-Object {
    $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]) -eq $localServiceSid
  })
$writeRights = [Security.AccessControl.FileSystemRights]'Write, Delete, ChangePermissions, TakeOwnership'
if ($localServiceRootRules.Count -ne 1 -or
    ($localServiceRootRules[0].FileSystemRights -band $writeRights) -ne 0) {
  throw 'LocalService has unexpected write access to the project root'
}

Write-Output 'Project ACL hardened; LocalService can modify only .state and workspace.'
