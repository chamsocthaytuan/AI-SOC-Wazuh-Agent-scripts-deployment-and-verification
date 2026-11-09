# Shared helpers for the Windows Wazuh Active Response scripts.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-AISocAgentRoot {
    return (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
}
function Write-AISocARLog([string]$Tag, [string]$Message) {
    $root = Get-AISocAgentRoot
    $file = Join-Path $root 'active-response\active-responses.log'
    $line = '{0} active-response/{1}: {2}' -f (Get-Date -Format 'yyyy/MM/dd HH:mm:ss'), $Tag, ($Message -replace '[\r\n]', ' ')
    try { Add-Content -LiteralPath $file -Value $line -Encoding UTF8 -ErrorAction Stop }
    catch { [Console]::Error.WriteLine($line) }
}
function Read-AISocARInput([string]$RawInput) {
    if (-not $RawInput) { $RawInput = [Console]::In.ReadLine() }  # Wazuh sends one JSON line; do not ReadToEnd.
    if ([string]::IsNullOrWhiteSpace($RawInput)) { return $null }
    if ($RawInput.Length -gt 131072) { throw 'AR message exceeds 128 KiB limit' }
    $msg = ConvertFrom-Json -InputObject $RawInput -ErrorAction Stop
    if ($null -eq $msg -or $msg.command -notin @('add','delete')) { throw 'Unknown AR command' }
    return $msg
}
function Get-AISocNestedValue($Object, [string]$Path) {
    $v = $Object
    foreach ($piece in $Path.Split('.')) {
        if ($null -eq $v) { return $null }
        $prop = $v.PSObject.Properties[$piece]
        if ($null -eq $prop) { return $null }
        $v = $prop.Value
    }
    return $v
}
function Assert-AISocIP([string]$Value) {
    $result = $null
    if (-not [System.Net.IPAddress]::TryParse($Value, [ref]$result)) { throw 'Not a valid IP literal' }
    if ([System.Net.IPAddress]::IsLoopback($result)) { throw 'Loopback IP is not a permitted target' }
    if ($result.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $b = $result.GetAddressBytes()
        if ($b[0] -eq 0 -or $b[0] -ge 224 -or ($b[0] -eq 169 -and $b[1] -eq 254) -or ($b[0] -eq 255)) { throw 'Unsupported IPv4 address' }
    } elseif ($result.IsIPv6Multicast -or $result.IsIPv6LinkLocal -or $result.Equals([System.Net.IPAddress]::IPv6Any)) {
        throw 'Unsupported IPv6 address'
    }
    return $result.ToString()
}
function Assert-AISocElevated {
    $principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator or SYSTEM privileges required'
    }
}
