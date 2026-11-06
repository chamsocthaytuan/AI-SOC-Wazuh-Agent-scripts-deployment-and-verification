[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline=$true)][string]$RawInput,
    [switch]$RestoreFromTimer
)
process {
    . (Join-Path $PSScriptRoot 'ai-soc-ar-common.ps1')
    $stateDir = Join-Path $env:ProgramData 'AI-SOC\WindowsAR'
    $stateFile = Join-Path $stateDir 'isolation-state.json'
    $taskName = 'AI-SOC-WindowsAR-IsolationAutoRestore'
    $ruleName = 'AI-SOC-AR-Isolate-Allow-Manager'
    $mutex = New-Object System.Threading.Mutex($false, 'Global\AI-SOC-WindowsAR-Isolation')
    $lockAcquired = $false
    try {
        Assert-AISocElevated
        $lockAcquired = $mutex.WaitOne(10000)
        if (-not $lockAcquired) { throw 'Isolation lock timed out' }
        $message = $null
        if (-not $RestoreFromTimer) {
            $message = Read-AISocARInput $RawInput
            if ($null -eq $message) { return }
        }
        $doRestore = $RestoreFromTimer -or $message.command -eq 'delete'
        if ($doRestore) {
            if (-not (Test-Path -LiteralPath $stateFile)) {
                Write-AISocARLog 'win_isolate_host' 'No saved isolation state; nothing changed'
                return
            }
            $state = Get-Content -LiteralPath $stateFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if (@($state.profiles).Count -ne 3) { throw 'Invalid saved state: profile count' }
            # Restore all 3 profiles to their EXACT pre-isolation settings; never turn off all firewalls blindly.
            foreach ($profile in @($state.profiles)) {
                if ($profile.Name -notin @('Domain','Private','Public')) { throw 'Invalid profile name in state' }
                Set-NetFirewallProfile -Profile $profile.Name -DefaultInboundAction $profile.DefaultInboundAction -DefaultOutboundAction $profile.DefaultOutboundAction -Enabled ([bool]$profile.Enabled) -ErrorAction Stop
            }
            $owned = @(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)
            foreach ($rule in $owned) {
                if ($rule.Group -ne 'AI-SOC-WindowsAR-Isolation') { throw 'Manager allow rule ownership mismatch' }
                $rule | Remove-NetFirewallRule -ErrorAction Stop
            }
            Remove-Item -LiteralPath $stateFile -Force -ErrorAction Stop
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-AISocARLog 'win_isolate_host' 'Restored original firewall profile configuration'
            return
        }
        if ($message.command -ne 'add') { throw 'Unsupported isolation command' }
        if (Test-Path -LiteralPath $stateFile) { throw 'An isolation is already active. Refusing to overwrite its recovery state' }
        $prior = @(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)
        if ($prior.Count -gt 0) { throw 'Stale/conflicting Manager allow rule; manual review required' }
        $legacy = @(Get-NetFirewallRule -DisplayName 'Wazuh_AR_Isolate_*' -ErrorAction SilentlyContinue)
        if ($legacy.Count -gt 0) { throw 'Legacy isolation rules present; review/restore the prior installation first' }

        # Fail closed when Wazuh Manager connection data is missing or ambiguous.
        $confPath = Join-Path (Get-AISocAgentRoot) 'ossec.conf'
        [xml]$conf = Get-Content -LiteralPath $confPath -Raw -ErrorAction Stop
        $servers = @($conf.SelectNodes('//client/server'))
        if ($servers.Count -ne 1) { throw 'Expected exactly one Wazuh Manager server in ossec.conf' }
        $manager = Assert-AISocIP ([string]$servers[0].address)
        $port = 1514
        if ([string]$servers[0].port) { $port = [int]$servers[0].port }
        if ($port -lt 1 -or $port -gt 65535) { throw 'Invalid Manager port' }
        $protocol = [string]$servers[0].protocol
        if ($protocol -and $protocol.ToLowerInvariant() -ne 'tcp') { throw 'This isolation mode requires Manager TCP connection' }
        $connected = @(Get-NetTCPConnection -State Established -RemotePort $port -ErrorAction SilentlyContinue |
            Where-Object { $_.RemoteAddress -eq $manager })
        if ($connected.Count -lt 1) { throw 'No live TCP connection to Wazuh Manager; refusing isolation' }

        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { $_.Name -in @('Domain','Private','Public') } | ForEach-Object {
            [ordered]@{
                Name = [string]$_.Name; Enabled = [bool]$_.Enabled
                DefaultInboundAction = [string]$_.DefaultInboundAction
                DefaultOutboundAction = [string]$_.DefaultOutboundAction
            }
        })
        if ($profiles.Count -ne 3) { throw 'Cannot snapshot all 3 firewall profiles' }
        New-Item -ItemType Directory -Path $stateDir -Force -ErrorAction Stop | Out-Null
        $ttlMinutes = 15
        $state = [ordered]@{ version = 1; created_utc = [DateTime]::UtcNow.ToString('o'); expires_utc = [DateTime]::UtcNow.AddMinutes($ttlMinutes).ToString('o'); manager_ip = $manager; manager_port = $port; profiles = $profiles }
        $tmp = Join-Path $stateDir ('isolation-' + [guid]::NewGuid().ToString('N') + '.tmp')
        ($state | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $tmp -Encoding UTF8 -ErrorAction Stop
        Move-Item -LiteralPath $tmp -Destination $stateFile -ErrorAction Stop

        # Safety timer MUST exist before firewall is touched. Runs as SYSTEM even if Agent disconnects.
        try {
            $exe = Join-Path $PSHOME 'powershell.exe'
            $scriptPath = Join-Path $PSScriptRoot 'isolate-host.ps1'
            $taskAction = New-ScheduledTaskAction -Execute $exe -Argument ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -RestoreFromTimer' -f $scriptPath)
            $taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($ttlMinutes)
            Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -User 'SYSTEM' -RunLevel Highest -Force -ErrorAction Stop | Out-Null
            $createdTask = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            if ($createdTask.State -eq 'Disabled') { throw 'Auto-restore task is disabled' }
            New-NetFirewallRule -DisplayName $ruleName -Group 'AI-SOC-WindowsAR-Isolation' -Direction Outbound -Action Allow -RemoteAddress $manager -RemotePort $port -Protocol TCP -Profile Any -Enabled True -ErrorAction Stop | Out-Null
            Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block -ErrorAction Stop
            $verified = @(Get-NetFirewallProfile | Where-Object { $_.Name -in @('Domain','Private','Public') })
            if ($verified.Count -ne 3 -or @($verified | Where-Object { -not $_.Enabled -or $_.DefaultOutboundAction -ne 'Block' }).Count -gt 0) {
                throw 'Isolation firewall post-check failed'
            }
            Write-AISocARLog 'win_isolate_host' "Firewall default-deny applied; Manager TCP $manager`:$port allowed; auto-restore in $ttlMinutes minutes. Existing allow rules may remain effective."
        } catch {
            $reason = $_.Exception.Message
            # Best-effort restore on partial application, retaining state/timer if recovery fails.
            $restoreOk = $true
            foreach ($profile in $profiles) {
                try { Set-NetFirewallProfile -Profile $profile.Name -DefaultInboundAction $profile.DefaultInboundAction -DefaultOutboundAction $profile.DefaultOutboundAction -Enabled ([bool]$profile.Enabled) -ErrorAction Stop }
                catch { $restoreOk = $false }
            }
            try { Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Where-Object { $_.Group -eq 'AI-SOC-WindowsAR-Isolation' } | Remove-NetFirewallRule -ErrorAction Stop }
            catch { $restoreOk = $false }
            if ($restoreOk) {
                Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            }
            throw "Isolation failed ($reason); rollback restored=$restoreOk"
        }
    } catch {
        Write-AISocARLog 'win_isolate_host' "ERROR: $($_.Exception.Message)"
        exit 1
    } finally {
        if ($lockAcquired) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}
