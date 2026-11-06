[CmdletBinding()]
param([Parameter(ValueFromPipeline=$true)][string]$RawInput)
process {
    . (Join-Path $PSScriptRoot 'ai-soc-ar-common.ps1')
    try {
        $message = Read-AISocARInput $RawInput
        if ($null -eq $message -or $message.command -eq 'delete') { return }
        Assert-AISocElevated
        $alert = Get-AISocNestedValue $message 'parameters.alert'
        $rawPid = $null
        foreach ($field in @('data.win.eventdata.processId','data.process.pid','data.pid','data.win.system.processId')) {
            $rawPid = Get-AISocNestedValue $alert $field
            if ($rawPid) { break }
        }
        if ($null -eq $rawPid) { throw 'Missing PID in alert' }
        $text = ([string]$rawPid).Trim()
        if ($text -match '^0x[0-9a-fA-F]{1,8}$') { $pidValue = [Convert]::ToInt64($text.Substring(2),16) }
        elseif ($text -match '^[0-9]{1,10}$') { $pidValue = [long]::Parse($text) }
        else { throw 'Invalid PID format' }
        if ($pidValue -lt 5 -or $pidValue -gt [int]::MaxValue) { throw 'Invalid/critical PID' }

        # Explicit lab allowlist, not a generic unrestricted process killer.
        $policyPath = Join-Path $PSScriptRoot 'ai-soc-ar-policy.json'
        $policy = Get-Content -LiteralPath $policyPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $allowlist = @($policy.allowed_process_names | ForEach-Object { ([string]$_).ToLowerInvariant().Replace('.exe','') })
        if ($allowlist.Count -eq 0) { throw 'Empty process allowlist' }
        $critical = @('system','idle','registry','csrss','lsass','smss','services','wininit','winlogon','explorer','svchost','wazuh-agent','wazuh-execd','ossec-agent','powershell','pwsh','cmd')

        $process = Get-Process -Id ([int]$pidValue) -ErrorAction Stop
        $name = $process.ProcessName.ToLowerInvariant()
        if ($critical -contains $name -or $allowlist -notcontains $name) { throw "Process $name is not allowlisted" }
        # When the alert supplies a process image path/name, reject a mismatched target.
        $expected = $null
        foreach ($field in @('data.win.eventdata.image','data.process.executable','data.process.name')) {
            $expected = Get-AISocNestedValue $alert $field
            if ($expected) { break }
        }
        if ($expected) {
            $expectedName = [System.IO.Path]::GetFileNameWithoutExtension([string]$expected).ToLowerInvariant()
            if ($expectedName -ne $name) { throw 'Alert image and current PID process name differ' }
        }
        # Kill the captured process object and verify termination; do not re-query and kill by PID.
        $process.Kill()
        if (-not $process.WaitForExit(5000)) { throw 'Process did not exit within 5 seconds' }
        Write-AISocARLog 'kill-process-win' "Confirmed process exit: $name, PID=$pidValue"
    } catch {
        Write-AISocARLog 'kill-process-win' "ERROR: $($_.Exception.Message)"
        exit 1
    }
}
