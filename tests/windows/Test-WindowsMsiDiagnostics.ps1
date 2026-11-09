#Requires -Version 5.1
# Windows-only non-destructive smoke test for OneClick MSI error diagnostics.
$ErrorActionPreference='Stop'
$target=Join-Path $PSScriptRoot '..\..\windows\oneclick-v0.1\Setup-AISOCWindowsPrerequisites.ps1'
if(-not(Test-Path -LiteralPath $target -PathType Leaf)) { throw "Missing installer: $target" }
$tokens=$null; $parseErrors=$null
$null=[System.Management.Automation.Language.Parser]::ParseFile($target,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count -gt 0) { throw "PowerShell parser error: $($parseErrors[0].Message)" }
$source=Get-Content -LiteralPath $target -Raw
foreach($required in @(
 'function Test-PendingRestart',
 "'/L*v'",
 '1603 { Fail',
 '3010 { throw',
 '1618 { Fail',
 'WAZUH_MSI_LOG:',
 'ENROLLMENT_PASSWORD_EXISTS',
 'refusing a blind MSI reinstall'
)) {
 if(-not $source.Contains($required)) { throw "Missing MSI safety diagnostic: $required" }
}
$output=& $target -ManagerIP '10.0.70.12' | Out-String
if($output -notmatch 'PREVIEW_WINDOWS' -or $output -notmatch 'No changes made') {
 throw 'Preview did not clearly state that it made no changes'
}
Write-Host 'WINDOWS_MSI_DIAGNOSTICS_STATIC_OK'
