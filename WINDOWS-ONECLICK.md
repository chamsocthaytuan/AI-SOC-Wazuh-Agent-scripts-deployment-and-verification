# Windows Agent Active Response — OneClick v0.1 (lab)

**Máy Windows mới chưa có Wazuh Agent/Suricata?** Xem [hướng dẫn cài đặt từ đầu (Windows, tiếng Việt)](docs/FRESH_WINDOWS_AGENT_WAZUH_SURICATA_ONECLICK.md).

- [Download ZIP](windows/oneclick-v0.1/AI-SOC-Windows-AR-OneClick-v0.1.zip)
- [Installer source and documentation](windows/oneclick-v0.1/README.md)

After installing an existing Wazuh Windows Agent, unzip the package and run PowerShell **as Administrator**:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-AISOCWindowsAR.ps1 -Apply
```

This installs the three Windows Active Response script families to the local Agent and backs up overwritten files. **It does not register Manager commands, automatically execute defenses, or emit Verification V2 evidence.** Review the included README and test only on a console-accessible lab VM before any production rollout.

## Windows Wazuh MSI 1603 troubleshooting (9 Nov 2026)

When `Setup-AISOCWindowsPrerequisites.ps1 -Apply` reports `1603`, it means **fatal MSI installation failure**. `3010` means **successful installation requiring restart**; never confuse the two. The installer now writes a verbose MSI log to `$env:ProgramData\AI-SOC\InstallerLogs`, reports the exact log filename, warns about pending Windows restart, and preserves any pre-existing Wazuh Agent keys/password. It never clears pending reboot flags.

From the existing repo on a new Windows/FlareVM endpoint, open Windows PowerShell 5.1 **as Administrator**:

```powershell
git pull --ff-only origin script-windows
& .\windows\oneclick-v0.1\Setup-AISOCWindowsPrerequisites.ps1 -Apply -ManagerIP 10.0.70.12
```

If `1603` returns, collect the relevant local log lines (redact any environment-specific sensitive values before sharing):

```powershell
$log=Get-ChildItem "$env:ProgramData\AI-SOC\InstallerLogs\wazuh-agent-*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Select-String -Path $log.FullName -Pattern 'Return value 3|LaunchConditions|MsiSystemRebootPending|Error 1603' -Context 5,2
```

Do not delete existing Wazuh keys, agent enrollment, or Windows Installer registry entries to work around `1603`. Use the MSI log to identify the failing action. A pending restart is one possible cause, not a confirmed diagnosis for a specific endpoint. If the MSI returns `3010`, restart Windows and re-run OneClick to resume configuration.

You can smoke-test the Windows PowerShell parser and dry-run without modifying the endpoint:

```powershell
& .\tests\windows\Test-WindowsMsiDiagnostics.ps1
```

