# Windows Agent Active Response — OneClick v0.1 (lab)

**Máy Windows mới chưa có Wazuh Agent/Suricata?** Xem [hướng dẫn cài đặt từ đầu (Windows, tiếng Việt)](docs/FRESH_WINDOWS_AGENT_WAZUH_SURICATA_ONECLICK.md).

- [Download ZIP](windows/oneclick-v0.1/AI-SOC-Windows-AR-OneClick-v0.1.zip)
- [Installer source and documentation](windows/oneclick-v0.1/README.md)

After installing an existing Wazuh Windows Agent, unzip the package and run PowerShell **as Administrator**:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-AISOCWindowsAR.ps1 -Apply
```

This installs the three Windows Active Response script families to the local Agent and backs up overwritten files. **It does not register Manager commands, automatically execute defenses, or emit Verification V2 evidence.** Review the included README and test only on a console-accessible lab VM before any production rollout.
