#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$BackupPath, [switch]$Apply)
$ErrorActionPreference = 'Stop'
$manifestPath = Join-Path $BackupPath 'manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$root = [string]$manifest.agent_root
if (-not (Test-Path -LiteralPath (Join-Path $root 'ossec.conf'))) { throw 'Target is not a Wazuh Agent root.' }
$destination = Join-Path $root 'active-response\bin'
$state = Join-Path $env:ProgramData 'AI-SOC\WindowsAR\isolation-state.json'
if (Test-Path $state) { throw 'Active isolation found. Restore it before rolling back the installation.' }
foreach ($entry in $manifest.files) {
    $target = Join-Path $destination $entry.name
    if (-not (Test-Path $target)) { throw "Installed file missing: $($entry.name)" }
    $hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    if ($hash -ne $entry.installed_sha256) { throw "Modified since installation: $($entry.name). Manual recovery required." }
}
if (-not $Apply) { Write-Host "DRY RUN: Restore $(@($manifest.files).Count) files from $BackupPath. Use -Apply to proceed."; return }
$id = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required.' }
foreach ($entry in $manifest.files) {
    $target = Join-Path $destination $entry.name
    if ($entry.original_existed) { Copy-Item -LiteralPath (Join-Path $BackupPath $entry.name) -Destination $target -Force -ErrorAction Stop }
    else { Remove-Item -LiteralPath $target -Force -ErrorAction Stop }
}
$service = Get-Service -Name 'wazuh','WazuhSvc' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -ne $service -and $service.Status -eq 'Running') { Restart-Service -Name $service.Name -ErrorAction Stop }
Write-Host 'RESTORE_OK: Original files restored. Agent service restarted if it was running.'
