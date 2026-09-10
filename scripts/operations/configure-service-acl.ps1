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
$authenticatedUsersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-11')
$builtinUsersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$none = [Security.AccessControl.PropagationFlags]::None
$allow = [Security.AccessControl.AccessControlType]::Allow

$existingRootAcl = Get-Acl -LiteralPath $projectRoot
$ownerSid = $existingRootAcl.Owner |
  ForEach-Object { ([Security.Principal.NTAccount]$_).Translate([Security.Principal.SecurityIdentifier]) }
$rootAcl = [Security.AccessControl.DirectorySecurity]::new()
$rootAcl.SetOwner($ownerSid)
$rootAcl.SetAccessRuleProtection($true, $false)
foreach ($entry in @(
    @($ownerSid, [Security.AccessControl.FileSystemRights]::FullControl),
    @($administratorSid, [Security.AccessControl.FileSystemRights]::FullControl),
    @($systemSid, [Security.AccessControl.FileSystemRights]::FullControl)
  )) {
  [void]$rootAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($entry[0], $entry[1], $inheritance, $none, $allow))
}
Set-Acl -LiteralPath $projectRoot -AclObject $rootAcl

$rootCheck = Get-Acl -LiteralPath $projectRoot
$forbidden = @($rootCheck.Access | Where-Object {
    $sid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier])
    $sid -eq $authenticatedUsersSid -or $sid -eq $builtinUsersSid
  })
if ($rootCheck.AreAccessRulesProtected -ne $true -or $forbidden.Count -gt 0) {
  throw 'project ACL verification failed closed'
}
$systemRules = @($rootCheck.Access | Where-Object {
    $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]) -eq $systemSid
  })
if ($systemRules.Count -ne 1 -or
    ($systemRules[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl) {
  throw 'LocalSystem does not have full control of the Radlina project root'
}

Write-Output 'Project ACL hardened; owner, Administrators and LocalSystem retain FullControl.'
