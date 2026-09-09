[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ruleName = 'Radlina Remote MCP - Block direct Node ingress'
$existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($existing) { Remove-NetFirewallRule -DisplayName $ruleName }
Write-Output 'Radlina firewall rule removed; unrelated firewall rules were not changed.'
