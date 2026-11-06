#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$NoRestartAgent,
    [string]$AgentRoot
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$names = @(
    'ai-soc-ar-common.ps1', 'ai-soc-ar-policy.json',
    'block-ip.ps1', 'block-ip-win.cmd',
    'isolate-host.ps1', 'isolate-host.cmd',
    'kill-process-win.ps1', 'kill-process-win.cmd', 'kill-process.ps1'
)
function Resolve-AgentRoot([string]$Preferred) {
    $options = @()
    if ($Preferred) { $options += $Preferred }
    else {
        if (${env:ProgramFiles(x86)}) { $options += (Join-Path ${env:ProgramFiles(x86)} 'ossec-agent') }
        if ($env:ProgramFiles) { $options += (Join-Path $env:ProgramFiles 'ossec-agent') }
    }
    foreach ($option in $options) {
        if (Test-Path -LiteralPath (Join-Path $option 'ossec.conf') -PathType Leaf) {
            return (Get-Item -LiteralPath $option).FullName
        }
    }
    throw 'Wazuh Agent not found (ossec.conf). Install Agent first or specify -AgentRoot.'
}
$root = Resolve-AgentRoot $AgentRoot
$destination = Join-Path $root 'active-response\bin'
$source = Join-Path $PSScriptRoot 'scripts'
$backupBase = Join-Path $root 'active-response\ai-soc-installer-backups'
$activeState = Join-Path $env:ProgramData 'AI-SOC\WindowsAR\isolation-state.json'
if (Test-Path -LiteralPath $activeState) {
    throw 'Active AI-SOC isolation state exists. Restore isolation before updating scripts.'
}
foreach ($name in $names) {
    $file = Join-Path $source $name
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing package file: $name" }
    if ($name.EndsWith('.ps1')) {
        $tokens = $null; $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)
        if ($null -ne $errors -and $errors.Count -gt 0) { throw "PowerShell syntax error ($name): $($errors[0].Message)" }
    }
}
foreach ($pair in @(@('block-ip-win.cmd','block-ip.ps1'), @('isolate-host.cmd','isolate-host.ps1'), @('kill-process-win.cmd','kill-process-win.ps1'))) {
    $data = Get-Content -LiteralPath (Join-Path $source $pair[0]) -Raw
    if (-not $data.Contains('%~dp0' + $pair[1])) { throw "Wrong wrapper target: $($pair[0])" }
}
Write-Host "Wazuh Agent: $root"
Write-Host "Destination: $destination"
Write-Host "Files to install: $($names.Count)"
Write-Host 'Mode: install scripts only; no automatic defense rules or Manager config changes.'
if (-not $Apply) {
    Write-Host 'DRY RUN: Nothing changed. Use -Apply to install.' -ForegroundColor Yellow
    return
}
$identity = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run PowerShell as Administrator.' }
$service = Get-Service -Name 'wazuh','WazuhSvc' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $service) { throw 'Wazuh Agent service not found. Refusing to modify scripts.' }
$wasRunning = ($service.Status -eq 'Running')
$stamp = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + ([guid]::NewGuid().ToString('N').Substring(0,8))
$backup = Join-Path $backupBase $stamp
New-Item -ItemType Directory -Path $backup -Force | Out-Null
New-Item -ItemType Directory -Path $destination -Force | Out-Null
$manifestFiles = @()
foreach ($name in $names) {
    $target = Join-Path $destination $name
    $present = Test-Path -LiteralPath $target -PathType Leaf
    if ($present) { Copy-Item -LiteralPath $target -Destination (Join-Path $backup $name) -ErrorAction Stop }
    $manifestFiles += [pscustomobject]@{ name = $name; original_existed = $present; installed_sha256 = (Get-FileHash -LiteralPath (Join-Path $source $name) -Algorithm SHA256).Hash }
}
$manifest = [pscustomobject]@{ created_utc = [DateTime]::UtcNow.ToString('o'); agent_root = $root; files = $manifestFiles }
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $backup 'manifest.json') -Encoding UTF8
$copied = @()
try {
    foreach ($name in $names) {
        Copy-Item -LiteralPath (Join-Path $source $name) -Destination (Join-Path $destination $name) -Force -ErrorAction Stop
        $copied += $name
        $expected = @($manifestFiles | Where-Object { $_.name -eq $name })[0].installed_sha256
        $actual = (Get-FileHash -LiteralPath (Join-Path $destination $name) -Algorithm SHA256).Hash
        if ($expected -ne $actual) { throw "Hash mismatch after install: $name" }
    }
    if ($wasRunning -and -not $NoRestartAgent) {
        Restart-Service -Name $service.Name -ErrorAction Stop
        $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    }
    Write-Host 'INSTALL_OK: All files installed and verified.' -ForegroundColor Green
    Write-Host "BACKUP: $backup"
    if (-not $wasRunning) { Write-Warning 'Agent service was stopped before installation and has NOT been started.' }
    if ($NoRestartAgent) { Write-Warning 'Wazuh Agent was NOT restarted (-NoRestartAgent).' }
    Write-Warning 'Manager-side command registration is separate; scripts have NOT been invoked.'
} catch {
    $failure = $_.Exception.Message
    foreach ($name in $copied) {
        $entry = @($manifestFiles | Where-Object { $_.name -eq $name })[0]
        $target = Join-Path $destination $name
        if ($entry.original_existed) { Copy-Item -LiteralPath (Join-Path $backup $name) -Destination $target -Force -ErrorAction SilentlyContinue }
        else { Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue }
    }
    throw "Install failed, best-effort rollback completed; backup=$backup; reason=$failure"
}
