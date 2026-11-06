# AI-SOC — Wazuh Linux Agent Scripts

Endpoint-side Active Response scripts for [chamsocthaytuan/ai_soc](https://github.com/chamsocthaytuan/ai_soc). This repository holds the **Linux agent package only**. The Orchestrator, Verification Worker, PostgreSQL migrations, Indexer rule 119910 and Manager configuration remain in the main AI-SOC repository.

> **Status: lab-validated, not production-certified.** The isolate runtime was tested on Wazuh Agent `008` (Kali, 2026-11-02), with a 60-second safety TTL. An independent Orchestrator → Agent → Indexer → Worker → PostgreSQL E2E remains pending.

## Files

- `active-response/block-ip.py` — Linux Block IP, nftables/iptables backends, execution ownership, rollback and JSONL evidence.
- `active-response/isolate.sh` — IPv4/IPv6 host isolation with a Manager TCP 1514 exception, persistent state, automatic TTL expiry and rollback.
  Provides read-only `--inspect <execution_id>` for a fresh, separately invoked kernel/firewall snapshot; emits `STATE_SNAPSHOT` with `event.step=independent_endpoint_inspection`, and never reapplies isolation or renews TTL.
- `active-response/ai_soc_evidence.py` — versioned, validated JSONL endpoint evidence writer.
- `active-response/kill-process0` — **original deployed Kali script** (997 bytes, SHA-256 `5e9bc0e03b94584838dd97a64aab8906b168243c7bda2cf700803060cf24b3da`), preserved unchanged for audit; **never installed by this installer**.
- `active-response/kill-process-safe.py` — hardened, default-deny, allowlisted Linux Kill Process requiring PIDFD-based signaling and post-signal observation.
- `config/agent.conf` — **Manager-side group configuration example** for collecting the endpoint JSONL (not an endpoint `ossec.conf` replacement).
- `scripts/install.sh` — explicit `--apply` agent file installer; defaults to dry-run. It does not change Wazuh configuration or firewall state.
- `tests/unit/` — non-destructive tests, including original endpoint tests ported from AI-SOC.

## Cài đặt từ máy Linux mới (chưa có Wazuh Agent/Suricata)

Xem [hướng dẫn từ đầu: Wazuh Agent 4.x + Suricata + OneClick + Manager evidence](docs/FRESH_LINUX_AGENT_WAZUH_SURICATA_ONECLICK.md) (tiếng Việt, triển khai lab single-server). **Không cài Agent mới đè lên một Agent đã đăng ký**.

## OneClick installer (Linux Agent)

On an authorized Wazuh Linux Agent, preview with `bash scripts/install-oneclick.sh --dry-run`, install the standard Block IP / Isolate Host / JSONL evidence files with `sudo bash scripts/install-oneclick.sh --apply`, then verify using `sudo bash scripts/install-oneclick.sh --verify`.

Opt-in hardened Kill Process requires a pre-approved root-owned policy or `--with-kill-process --allow-process <lab-process-name>` to create a new single-process lab allowlist. The installer does **not** configure the Manager or enable Active Response. See [Linux OneClick guide](docs/linux-oneclick.md).

## Compatibility and deployment

Linux and Wazuh Agent, Python 3, `bash`, `flock`, `ss`, `iptables`/`ip6tables`, `iptables-save`/`ip6tables-save`, `systemd-run` and `systemctl`. Block IP additionally supports native nftables or explicit iptables variants.

```bash
bash scripts/install.sh          # review only; no changes
sudo bash scripts/install.sh --apply
```

Before deployment, back up and review the existing Agent install. The installer backs up replaced scripts and checks for an active isolation execution. **By default it installs only** `block-ip.py`, `isolate.sh`, and `ai_soc_evidence.py`. Installing the hardened Kill Process at the Manager's existing executable name `kill-process0` requires the extra explicit flag `--with-kill-process` **plus a root-owned, nonempty allowlist policy**. The legacy script is never installed by the installer. It **does not** register Wazuh commands, configure the Manager, restart the Wazuh Agent, change `ossec.conf`, or enable auto-execution.

**Required external integration:** in the AI-SOC Manager, register `isolate.sh` and `block-ip.py` as explicit-agent custom Active Response commands; configure the dedicated `ai-soc-linux` group `agent.conf` JSON localfile and rule 119910 / Indexer ingestion. Do not configure a broad/unfiltered automatic isolation trigger. The exact command registration and evidence routing must match the main AI-SOC deployment.

**Manager IP:** `isolate.sh` is currently a lab-specific script with default Manager IP `192.168.100.192`. The script checks the actual Wazuh `client/server` address, port and TCP protocol, and fails closed when mismatched. **Do not deploy this version at a different Manager IP without explicitly configuring and validating `AI_SOC_WAZUH_MANAGER_IP` in the Active Response process environment or updating the packaged script via a reviewed deployment configuration.** Setting it in a manual shell alone does not guarantee Wazuh Active Response inherits it.

## Kill Process — preserved legacy and opt-in hardening

Existing Kali Agent `008` has an old script at `/var/ossec/active-response/bin/kill-process0`. Its original 997-byte source is preserved unchanged in `active-response/kill-process0` for byte-level provenance; tests confirm its original SHA-256.

**Never deploy the original legacy script as a production control**: it runs `pkill -TERM -x <process_name>` with an unvalidated regex from the alert, no critical-process protection, no unique PID binding, and no termination verification. The old code stays in the repo only for review.

The replacement `active-response/kill-process-safe.py` is *not deployed by default*. It:
- Reads `parameters.alert.data.process_name` or `processname` from the Wazuh Active Response JSON; accepts only `command=add` and ignores `delete`.
- Requires an exact literal executable name (Linux `comm`, maximum 15 ASCII characters), a root-owned allowlist policy, and denies known critical processes.
- Enumerates `/proc` and rejects ambiguous names (multiple matching PIDs), zero matches, or PID/start-time identity changes.
- Sends `SIGTERM` with Linux `pidfd_open` / `pidfd_send_signal` instead of regex-based `pkill`.
- Audits approval, SIGTERM dispatch and independent post-signal observation; a dispatched signal is **not** automatically recorded as verified termination.
- Never escalates to SIGKILL and never auto-enables a Wazuh Manager response rule.

### Explicit opt-in installation on a lab endpoint

On a reviewed Linux Wazuh Agent (run from the cloned repo):

```bash
bash scripts/install.sh --dry-run
sudo install -d -o root -g root -m 0750 /var/ossec/etc/ai-soc
sudo install -o root -g root -m 0640 config/kill-process-policy.example.json /var/ossec/etc/ai-soc/kill-process-policy.json
sudoedit /var/ossec/etc/ai-soc/kill-process-policy.json
```

Manually set `allowed_process_names` to **specific, non-critical executable names** after approving the affected application and its identity. An empty list is intentionally rejected. For an isolated lab with a process named `aisockill2`, the reviewed JSON would be `{"allowed_process_names":["aisockill2"]}`. Do not approve common system executables such as `python3`, `bash`, `sshd` or Wazuh processes.

```bash
sudo python3 active-response/kill-process-safe.py --check-policy
sudo bash scripts/install.sh --apply --with-kill-process
```

That last command installs all three standard scripts and backs up/replaces the endpoint's `kill-process0` with the hardened one. No Wazuh Manager change or process termination is performed by the installer. The existing `!kill-process0` Manager command remains compatible, but Wazuh Manager **ACK is not endpoint termination verification**. This script does not yet emit an execution-correlated V2 evidence event, so end-to-end operational verification is still pending. See [issue #1](https://github.com/chamsocthaytuan/AI-SOC-Wazuh-Agent-scripts-deployment-and-verification/issues/1) for integration gates.

The policy and control need review for each deployment. Restrict Manager API access, dispatch on exact agent ID, and avoid enabling broad unattended process termination. The script blocks a known critical-name set, but that list is not a universal service dependency analysis.

## Evidence and verification

The endpoint emits events to `/var/ossec/logs/ai-soc-verification.json`, which the Wazuh Manager / Indexer must ingest with a provenance-checked rule. Event identifiers and execution identifiers are used for durable correlation. Execution success alone is not an operational verdict.

The live Kali lab demonstrated:
- `EXECUTION_STARTED`, `STATE_SNAPSHOT`, `EXECUTION_COMPLETED` for isolation.
- A transient systemd timer and automatic rollback after the configured 60-second TTL.
- `TTL_AUTO_EXPIRED`, `expired` persistent state, IPv4 and IPv6 isolation rules removed and Agent TCP 1514 restored/preserved after expiry.

This was **a direct endpoint invocation**. The lab execution ID `956f5ab8-411c-48bc-a3aa-6de908bede93` was not a committed execution in the production Orchestrator DB, so it cannot establish an end-to-end Worker verdict.

## Read-only isolation inspection (for tomorrow's lab)

From the **Kali console only**, after an authorized isolate execution with a durable execution ID and while TTL is still active, run:

```bash
sudo bash /var/ossec/active-response/bin/isolate.sh --inspect <execution_id>
```

The command cannot install or renew firewall rules. It captures both IPv4 and IPv6 rules, requires the correct live Manager connection, current `boot_id`, matching active execution, unexpired TTL, and emits an independent follow-up `STATE_SNAPSHOT`. If the state is no longer active, its evidence carries `exit_code=1` and the command fails closed. The execution must be committed in the AI-SOC database for the worker to accept its event.

The command can also be issued to the Wazuh Agent via the existing `!isolate.sh` custom Active Response route with `--inspect` in `parameters.extra_args`, scoped to one explicit agent. This is a **read-only** observation, not a replay of the original isolation action.

## Tests

```bash
python3 -m pytest -q tests/unit
```

The tests use fake firewall runners, mock procfs/pidfd operations and a fake legacy `pkill`; they neither isolate the test host nor terminate real processes. Run a controlled manual isolation test only on an authorized lab VM with console access and an independently validated rollback path.

## Compatibility policy

- Evidence JSON schema version `1.0`.
- Support deployment from a **single AI-SOC server** managing ordinary Wazuh Agents; no third network-probe host is required for this package.
- Independent firewall-state verification and pre-dispatch semantic validation are under development in the **main AI-SOC** Verification Worker.
- No secrets, Wazuh `client.keys`, local runtime state, captured alerts or private keys should be committed here.
- The Agent scripts remain mirrored in the main repo until integration and packaging regression are completed. Do not remove them prematurely.

## Source and provenance

Initial files imported from `chamsocthaytuan/ai_soc`, branch `feat/v113-integration`. The legacy `kill-process0` was imported from the user-provided Kali Agent 008 source and verified against its original SHA-256. `isolate.sh` contains three Kali runtime compatibility fixes from 2026-11-02: multi-root `ossec.conf`, four-field `ss -H` output and normalized iptables rule comparisons. Their isolated package tests are included in this repository.

