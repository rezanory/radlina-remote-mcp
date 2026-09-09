[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$nodeExecutable = [IO.Path]::GetFullPath((Join-Path $projectRoot '.runtime\node-v24.20.0-win-x64\node.exe'))
$expectedNode = [IO.Path]::GetFullPath('C:\radlina-remote-mcp\.runtime\node-v24.20.0-win-x64\node.exe')
if ($nodeExecutable -ne $expectedNode -or -not (Test-Path -LiteralPath $nodeExecutable)) {
  throw "refusing unexpected or missing Node executable: $nodeExecutable"
}
$ruleName = 'Radlina Remote MCP - Block direct Node ingress'
$existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($existing) { Remove-NetFirewallRule -DisplayName $ruleName }
New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Block -Program $nodeExecutable -Profile Any -Enabled True | Out-Null
$rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
if ($rule.Action -ne 'Block' -or $rule.Direction -ne 'Inbound' -or $rule.Enabled -ne 'True') {
  throw 'firewall rule verification failed'
}
Write-Output 'Dedicated inbound block rule installed for the Radlina portable Node runtime.'
