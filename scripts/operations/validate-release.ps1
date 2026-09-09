[CmdletBinding()]
param(
  [switch]$SkipCleanInstall,
  [switch]$SkipBenchmark
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$evidenceRoot = Join-Path $projectRoot 'evidence\PH-01\P001'
$reportRoot = Join-Path $projectRoot 'reports\PH-01'
New-Item -ItemType Directory -Force -Path $evidenceRoot, $reportRoot | Out-Null
$npm = Join-Path $projectRoot '.runtime\node-v24.20.0-win-x64\npm.cmd'
$nodeRoot = Join-Path $projectRoot '.runtime\node-v24.20.0-win-x64'
$env:Path = $nodeRoot + ';' + $env:Path
$powerShell = (Get-Command powershell.exe -ErrorAction Stop).Source
$records = [Collections.Generic.List[object]]::new()

function ConvertTo-SafeText([string]$Value) {
  $safe = $Value -replace '(?i)Bearer\s+[A-Za-z0-9._~+/-]+=*', 'Bearer [REDACTED]'
  $safe = $safe -replace '(?i)(sk|ghp|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{16,}', '[REDACTED]'
  $safe = $safe -replace '(?is)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (RSA |EC |OPENSSH )?PRIVATE KEY-----', '[REDACTED PRIVATE KEY]'
  return $safe
}

function Invoke-Gate {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Executable,
    [Parameter(Mandatory)][string[]]$Arguments
  )
  $startedAt = (Get-Date).ToUniversalTime()
  $timer = [Diagnostics.Stopwatch]::StartNew()
  $previousPreference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  $output = (& $Executable @Arguments 2>&1 | Out-String)
  $exitCode = $LASTEXITCODE
  $ErrorActionPreference = $previousPreference
  $timer.Stop()
  $safeName = $Name -replace '[^A-Za-z0-9._-]', '-'
  $outputPath = Join-Path $evidenceRoot "$safeName.txt"
  ConvertTo-SafeText $output | Set-Content -LiteralPath $outputPath -Encoding utf8NoBOM
  $outputHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $outputPath).Hash.ToLowerInvariant()
  $records.Add([ordered]@{
    name = $Name
    executable = $Executable
    arguments = $Arguments
    startedAt = $startedAt.ToString('o')
    durationMs = $timer.ElapsedMilliseconds
    exitCode = $exitCode
    output = $outputPath.Substring($projectRoot.Length + 1).Replace('\', '/')
    outputSha256 = $outputHash
  })
  Write-Output "$Name exit=$exitCode durationMs=$($timer.ElapsedMilliseconds)"
}

if (-not $SkipCleanInstall) { Invoke-Gate 'clean-install' $npm @('ci', '--ignore-scripts') }
Invoke-Gate 'format-check' $npm @('run', 'format:check')
Invoke-Gate 'lint' $npm @('run', 'lint')
Invoke-Gate 'typecheck' $npm @('run', 'typecheck')
Invoke-Gate 'test-all' $npm @('test')
Invoke-Gate 'build' $npm @('run', 'build')
Invoke-Gate 'package-dry-run' $npm @('pack', '--dry-run', '--json')
Invoke-Gate 'dependency-audit' $npm @('run', 'security:audit')
Invoke-Gate 'sbom' $npm @('run', 'sbom')
Invoke-Gate 'license-inventory' $npm @('run', 'licenses')
Invoke-Gate 'secret-scan' $powerShell @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'security-scan.ps1'))
if (-not $SkipBenchmark) { Invoke-Gate 'benchmark' $npm @('run', 'benchmark') }

$artifactPaths = @(
  'package.json',
  'package-lock.json',
  'reports\PH-01\sbom.cdx.json',
  'reports\PH-01\licenses.json',
  'service\RadlinaRemoteMCP.xml',
  'third_party\runtime-manifest.json'
)
$artifacts = foreach ($relative in $artifactPaths) {
  $file = Join-Path $projectRoot $relative
  if (Test-Path -LiteralPath $file -PathType Leaf) {
    [ordered]@{
      path = $relative.Replace('\', '/')
      bytes = (Get-Item -LiteralPath $file).Length
      sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant()
    }
  }
}
$summary = [ordered]@{
  schemaVersion = 1
  generatedAt = (Get-Date).ToUniversalTime().ToString('o')
  sourceRoot = $projectRoot
  node = (& (Join-Path $nodeRoot 'node.exe') --version)
  sourceCommit = if (Test-Path -LiteralPath (Join-Path $projectRoot '.git')) { (& git.exe -C $projectRoot rev-parse HEAD 2>$null) } else { $null }
  sourceTree = if (Test-Path -LiteralPath (Join-Path $projectRoot '.git')) { (& git.exe -C $projectRoot rev-parse 'HEAD^{tree}' 2>$null) } else { $null }
  initialGitStatus = if (Test-Path -LiteralPath (Join-Path $projectRoot '.git')) { @(& git.exe -C $projectRoot status --porcelain=v1) } else { @() }
  gates = @($records)
  artifacts = @($artifacts)
}
$summaryPath = Join-Path $evidenceRoot 'validation-summary.json'
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding utf8NoBOM
$failed = @($records | Where-Object { $_.exitCode -ne 0 })
if ($failed.Count -gt 0) {
  Write-Error "release validation failed: $($failed.name -join ', ')"
  exit 1
}
Write-Output "release validation passed: $summaryPath"
