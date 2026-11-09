# AI-SOC Windows Agent Active Response — one-command deployment (lab v0.1)

**Scope:** Install Windows Active Response scripts on an *already installed* Wazuh Agent. This is not a Wazuh Agent MSI installer, and it does **not** automatically register commands on the Wazuh Manager or enable auto-defense. Intended for authorized FlareVM / lab machines first.

## One command on the Windows Agent

1. Unzip this package anywhere on FlareVM / Windows Agent.
2. Open **Windows PowerShell 5.1 as Administrator** in this package's folder.
3. Run exactly one command:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-AISOCWindowsAR.ps1 -Apply
```

The installer automatically finds the Wazuh Agent install, installs all **nine** payload files (the 7 original script/wrapper names, plus one common helper and one process policy file) to its `active-response\bin` folder, backs up overwritten files, checks SHA-256 of copies, and restarts Wazuh Agent if it was already running.

For preview only:

```powershell
.\Install-AISOCWindowsAR.ps1
```

For non-destructive post-install verification:

```powershell
.\Test-AISOCWindowsAR.ps1
```

You will see `INSTALL_OK` on success and a backup path like `<AGENT_ROOT>\active-response\ai-soc-installer-backups\<timestamp>`.

If you need to restore the old scripts (copy the backup path printed by the installer):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Restore-AISOCWindowsAR.ps1 -BackupPath 'C:\Program Files (x86)\ossec-agent\active-response\ai-soc-installer-backups\<timestamp>' -Apply
```

The restore script refuses to overwrite files changed after installation and refuses to run during a currently tracked isolation.

## Changes to the submitted scripts

- **CMD wrapper fix:** `kill-process-win.cmd` correctly calls `kill-process-win.ps1`; all three `.cmd` launchers pass a non-interactive PowerShell host and its process exit code.
- **Correct stdin:** Wazuh Active Response sends one JSON message per line; script reads `Console.In.ReadLine()` instead of `ReadToEnd()` (which can hang if Wazuh keeps its pipe open).
- **Block IP:** validates actual IP address, creates a specifically owned inbound firewall rule, re-checks it, and removes *only* a matching AI-SOC-owned rule on `delete`.
- **Isolate Host:** reads the single Manager IP and TCP port from `ossec.conf`, captures the three original firewall profile settings, registers a SYSTEM scheduled restore task **before** modifying the firewall, preserves the Wazuh Manager TCP connection exception, and restores exactly the saved settings on `delete` or 15-minute safety timer. Refuses new isolation while existing isolation state is active.
- **Kill Process:** validates PID format, excludes system processes, uses an explicit **lab-only allowlist** (`ai-soc-ar-policy.json` initially allows `notepad` only), calls the selected process object's `.Kill()` and `WaitForExit()` before writing a success log; `kill-process.ps1` is retained as a compatibility forwarding alias.
- **Logs:** continue in `<WAZUH_AGENT_ROOT>\active-response\active-responses.log`.

## Important limitations / precautions

1. **Do not run an Isolate Host test over RDP/SSH alone.** Use VM console and snapshot; a firewall change may drop your remote session. This implementation leaves pre-existing Windows Firewall allow rules in place, so it verifies default-deny configuration, **not guaranteed complete L3/L4 isolation**. It is not production-certified.
2. **Auto-restore is local Windows Task Scheduler**, separate from Wazuh. If scheduling fails the script refuses to isolate. Nevertheless, test restoration on a lab VM before relying on it; Windows Task Scheduler, OS firewall, and Wazuh Agent behavior have not been end-to-end tested with this delivered package.
3. For now, **Kill Process is allowlist-only**, allowing `notepad` on lab machines. To allow another approved application, change `ai-soc-ar-policy.json` after security review. Do not allow broad patterns or system executables.
4. Manager address must be a **single numeric IPv4/IPv6 literal** in `ossec.conf`, with TCP transport. The script deliberately fails closed otherwise.
5. These scripts emit traditional `active-responses.log` text, **not** Version 2 `schema_version=1.0` endpoint JSONL evidence. This package does **not** make Verification V2 / rule `119910` end-to-end ready.
6. The Wazuh Manager must register each command once. Template: `manager/wazuh-manager-commands.xml`. To avoid manually editing 3 blocks, use the included optional **Manager-side one-command registrar** on the Ubuntu host against the ACTUAL bind-mounted `ossec.conf` (see below). It intentionally does **not** configure automatic rule-based triggering or blanket `location=all` isolation.
7. Manager-side command registration and Wazuh Agent copying are separate operations on separate machines. One Windows command installs every Agent script; it does not silently edit your Ubuntu Wazuh Manager.

## Wazuh references

- https://documentation.wazuh.com/current/user-manual/capabilities/active-response/how-to-configure.html
- https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html
- https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/commands.html

## Validation performed for this release

- Package structural/static checks from Linux, including file/wrapper names and ZIP integrity.
- Windows PowerShell syntax is additionally parsed by the installer **when run on Windows**; no claims are made that this package was executed on a real Windows VM or integrated with a live Wazuh Manager.

## Optional — Manager-side command registrar (Ubuntu host)

Once all Windows Agent scripts are deployed, use the following against the **real Manager ossec.conf on the Ubuntu host** (not against an arbitrary sample file):

```bash
python3 manager/register-manager-commands.py --config /ACTUAL/HOST/PATH/ossec.conf --apply
```

This takes a timestamped backup and adds the 3 `<command>` definitions idempotently. Omit `--apply` to preview. It does **not** add any `<active-response>` triggers or restart the Manager. Validate your running Manager's configuration, then restart the Manager container/service under your normal change-control procedure. If this config is Docker-mounted, make sure the container really uses the specified host file.
