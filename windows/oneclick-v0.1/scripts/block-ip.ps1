[CmdletBinding()]
param([Parameter(ValueFromPipeline=$true)][string]$RawInput)
process {
    . (Join-Path $PSScriptRoot 'ai-soc-ar-common.ps1')
    try {
        $message = Read-AISocARInput $RawInput
        if ($null -eq $message) { return }
        Assert-AISocElevated
        $alert = Get-AISocNestedValue $message 'parameters.alert'
        $candidate = $null
        foreach ($field in @('data.srcip','srcip','data.src_ip','data.win.eventdata.ipAddress')) {
            $candidate = Get-AISocNestedValue $alert $field
            if ($candidate) { break }
        }
        if (-not $candidate) { throw 'Missing source IP' }
        $ip = Assert-AISocIP ([string]$candidate)
        $ruleName = 'AI-SOC-AR-Block-' + $ip.Replace(':','_')
        $existing = @(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)
        if ($existing.Count -gt 1) { throw 'Conflicting duplicate firewall rules' }
        if ($existing.Count -eq 1) {
            $r = $existing[0]
            $filter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction Stop
            if ($r.Group -ne 'AI-SOC-WindowsAR' -or $r.Direction -ne 'Inbound' -or $r.Action -ne 'Block' -or
                @($filter.RemoteAddress).Count -ne 1 -or @($filter.RemoteAddress)[0] -ne $ip) {
                throw 'Existing rule does not match owned rule; refusing to modify'
            }
        }
        if ($message.command -eq 'add') {
            if ($existing.Count -eq 0) {
                New-NetFirewallRule -DisplayName $ruleName -Group 'AI-SOC-WindowsAR' -Direction Inbound -Action Block -RemoteAddress $ip -Enabled True -Profile Any -Description 'AI-SOC Windows AR owned rule' -ErrorAction Stop | Out-Null
            } elseif ($existing[0].Enabled -ne 'True') { throw 'Owned rule is disabled; manual inspection required' }
            $check = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
            if ($check.Action -ne 'Block' -or $check.Enabled -ne 'True') { throw 'Firewall rule post-check failed' }
            Write-AISocARLog 'win_block_ip' "Installed/confirmed inbound block for $ip"
        } else {
            if ($existing.Count -eq 1) { $existing[0] | Remove-NetFirewallRule -ErrorAction Stop }
            Write-AISocARLog 'win_block_ip' "Removed owned inbound block for $ip (if present)"
        }
    } catch {
        Write-AISocARLog 'win_block_ip' "ERROR: $($_.Exception.Message)"
        $global:LASTEXITCODE = 1
        exit 1
    }
}
