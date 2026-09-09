[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$stateDirectory = Join-Path $projectRoot '.state'
if (-not (Test-Path -LiteralPath $stateDirectory -PathType Container)) {
  Write-Output 'No DPAPI state requires migration.'
  return
}

Add-Type -AssemblyName System.Security

function Convert-ToMachineDpapi {
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
  $encoded = (Get-Content -LiteralPath $Path -Raw).Trim()
  if ([string]::IsNullOrWhiteSpace($encoded)) { throw "empty DPAPI blob: $Path" }
  try {
    $protected = [Convert]::FromBase64String($encoded)
  } catch {
    throw "invalid DPAPI blob encoding: $Path"
  }

  try {
    $alreadyMachineProtected = [Security.Cryptography.ProtectedData]::Unprotect(
      $protected,
      $null,
      [Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    [Array]::Clear($alreadyMachineProtected, 0, $alreadyMachineProtected.Length)
    return
  } catch {
    try {
      $plain = [Security.Cryptography.ProtectedData]::Unprotect(
        $protected,
        $null,
        [Security.Cryptography.DataProtectionScope]::CurrentUser
      )
    } catch {
      throw "DPAPI blob is neither machine-protected nor migratable by the current Windows identity: $Path"
    }
  }

  try {
    $machineProtected = [Security.Cryptography.ProtectedData]::Protect(
      $plain,
      $null,
      [Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    $replacement = [Convert]::ToBase64String($machineProtected)
    $temporary = "$Path.migrate-$([guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText($temporary, $replacement, [Text.UTF8Encoding]::new($false))
    [IO.File]::Replace($temporary, $Path, $null)
    $verified = [Security.Cryptography.ProtectedData]::Unprotect(
      [Convert]::FromBase64String((Get-Content -LiteralPath $Path -Raw).Trim()),
      $null,
      [Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    if ([Convert]::ToBase64String($verified) -ne [Convert]::ToBase64String($plain)) {
      throw "DPAPI migration verification failed: $Path"
    }
  } finally {
    if ($plain) { [Array]::Clear($plain, 0, $plain.Length) }
    if ($verified) { [Array]::Clear($verified, 0, $verified.Length) }
    if ($temporary -and (Test-Path -LiteralPath $temporary)) {
      [IO.File]::Delete($temporary)
    }
  }
}

Convert-ToMachineDpapi -Path (Join-Path $stateDirectory 'audit-key.dpapi')
Convert-ToMachineDpapi -Path (Join-Path $stateDirectory 'oauth-signing-key.dpapi')
Write-Output 'DPAPI state is protected for this Windows machine.'
