# AI-SOC Linux Agent — OneClick v0.1

Install from the repository root on an authorized Linux Wazuh Agent (not the Manager). Wazuh Agent and Linux firewall dependencies must already be installed.

## Commands

Preview without making changes:
```bash
bash scripts/install-oneclick.sh --dry-run
```

Install Block IP, Isolate Host and JSONL evidence writer:
```bash
sudo bash scripts/install-oneclick.sh --apply
```

Verify script contents and file ownership/permissions:
```bash
sudo bash scripts/install-oneclick.sh --verify
```

To additionally install the hardened Kill Process implementation at the existing `kill-process0` command name, a pre-existing root-owned nonempty allowlist is required. For a NEW allowlist on an isolated lab, specify one explicitly approved disposable process name:
```bash
sudo bash scripts/install-oneclick.sh --apply --with-kill-process --allow-process aisockill2
```

To verify the optional Kill Process install, add `--with-kill-process` to `--verify`. An existing policy is never overwritten. Do not allowlist privileged system services, the Wazuh agent or management daemons.

## Safety and scope

- Uses the existing `scripts/install.sh` for the actual Agent file installation, including syntax checks, backup, root checks, existing-isolation refusal, Manager TCP 1514 / IP compatibility and dependency checks.
- No firewall rule is installed, no host is isolated, no process is killed and no AR is dispatched during installation.
- The installer does not enable auto-defence, edit Wazuh Agent/Manager configuration, or restart services.
- The current Isolate script is tied to lab Manager IP `192.168.100.192`; review the source before applying to an Agent pointing elsewhere.
- Agent-side file installation is not complete Wazuh / Verification V2 integration. The Manager must separately register commands and provide the `ai-soc-linux` group JSONL localfile configuration to support rule `119910`.
- The hardened Kill Process is not yet fully correlated with the Verification V2 evidence pipeline.
- No claim of live E2E testing on Kali/Ubuntu has been made for this wrapper. Validate with console access, a safe test target and a rollback plan.
