[CmdletBinding()]
param(
  [string]$RipgrepPath
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$expectedRipgrep = '14231169855ec5205cf5a1b6f1db358ff4aed4247c86b69ce8aae647c77f6680'
$candidates = @(
  $RipgrepPath,
  (Join-Path $projectRoot '.runtime\ripgrep-15.2.0-x86_64-pc-windows-msvc\rg.exe'),
  'C:\radlina-remote-mcp\.runtime\ripgrep-15.2.0-x86_64-pc-windows-msvc\rg.exe'
) | Where-Object { $_ }
$ripgrep = @($candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1)
if ($ripgrep.Count -ne 1) { throw 'pinned ripgrep executable is missing' }
$ripgrep = $ripgrep[0]
$actualRipgrep = (Get-FileHash -Algorithm SHA256 -LiteralPath $ripgrep).Hash.ToLowerInvariant()
if ($actualRipgrep -ne $expectedRipgrep) {
  throw "pinned ripgrep executable hash mismatch: $actualRipgrep"
}
$pattern = '(?i)(sk-[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)'
$arguments = @(
  '--hidden', '--line-number', '--no-heading',
  '-g', '!.git/**', '-g', '!node_modules/**', '-g', '!.temp/**', '-g', '!.runtime/**', '-g', '!.state/**',
  '-g', '!scripts/operations/security-scan.ps1',
  $pattern, $projectRoot
)
$findings = & $ripgrep @arguments
if ($LASTEXITCODE -eq 0) {
  $findings | Write-Error
  throw 'potential committed secret detected'
}
if ($LASTEXITCODE -ne 1) { throw "secret scan failed with ripgrep exit code $LASTEXITCODE" }
Write-Output 'secret scan passed'
