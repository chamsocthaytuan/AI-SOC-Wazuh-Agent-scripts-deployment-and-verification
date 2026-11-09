#Requires -Version 5.1
[CmdletBinding()]
param([string]$AgentRoot)
$ErrorActionPreference='Stop'
if (-not $AgentRoot) {
    $AgentRoot = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
}
$bin = Join-Path $AgentRoot 'active-response\bin'
$files = @('ai-soc-ar-common.ps1','ai-soc-ar-policy.json','block-ip.ps1','block-ip-win.cmd','isolate-host.ps1','isolate-host.cmd','kill-process-win.ps1','kill-process-win.cmd','kill-process.ps1')
$failed = $false
foreach ($file in $files) {
    $exists = Test-Path -LiteralPath (Join-Path $bin $file) -PathType Leaf
    if (-not $exists) { $failed = $true }
    Write-Host (('{0,-28} {1}' -f $file, $(if ($exists) {'OK'} else {'MISSING'})))
    if ($exists -and $file.EndsWith('.ps1')) {
        $tokens=$null; $errors=$null
        $null=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $bin $file),[ref]$tokens,[ref]$errors)
        if ($null -ne $errors -and $errors.Count -gt 0) { $failed=$true; Write-Host "SYNTAX_ERROR: $file $($errors[0].Message)" }
    }
}
Get-Service -Name 'wazuh','WazuhSvc' -ErrorAction SilentlyContinue | Select-Object Name,Status | Format-Table -AutoSize
Write-Host 'No firewall changes or processes terminated by this test.'
if ($failed) { exit 1 }
Write-Host 'STATIC_CHECK_OK (not an E2E verification)'
