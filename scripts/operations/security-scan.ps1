[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$ripgrep = Join-Path $projectRoot '.runtime\ripgrep-15.2.0-x86_64-pc-windows-msvc\rg.exe'
if (-not (Test-Path -LiteralPath $ripgrep -PathType Leaf)) { throw 'pinned ripgrep executable is missing' }
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
