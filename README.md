# AI-SOC — Wazuh Linux Agent Scripts

Endpoint-side Active Response scripts for [chamsocthaytuan/ai_soc](https://github.com/chamsocthaytuan/ai_soc). This repository holds the **Linux agent package only**. The Orchestrator, Verification Worker, PostgreSQL migrations, Indexer rule 119910 and Manager configuration remain in the main AI-SOC repository.

> **Status: lab-validated, not production-certified.** The isolate runtime was tested on Wazuh Agent `008` (Kali, 2026-11-02), with a 60-second safety TTL. An independent Orchestrator → Agent → Indexer → Worker → PostgreSQL E2E remains pending.

## Files

- `active-response/block-ip.py` — Linux Block IP, nftables/iptables backends, execution ownership, rollback and JSONL evidence.
- `active-response/isolate.sh` — IPv4/IPv6 host isolation with a Manager TCP 1514 exception, persistent state, automatic TTL expiry and rollback.
- `active-response/ai_soc_evidence.py` — versioned, validated JSONL endpoint evidence writer.
- `config/agent.conf` — **Manager-side group configuration example** for collecting the endpoint JSONL (not an endpoint `ossec.conf` replacement).
- `scripts/install.sh` — explicit `--apply` agent file installer; defaults to dry-run. It does not change Wazuh configuration or firewall state.
- `tests/unit/` — non-destructive tests, including original endpoint tests ported from AI-SOC.

## Compatibility and deployment

Linux and Wazuh Agent, Python 3, `bash`, `flock`, `ss`, `iptables`/`ip6tables`, `iptables-save`/`ip6tables-save`, `systemd-run` and `systemctl`. Block IP additionally supports native nftables or explicit iptables variants.

```bash
bash scripts/install.sh          # review only; no changes
sudo bash scripts/install.sh --apply
```

Before deployment, back up and review the existing Agent install. The installer backs up any replaced script, checks for an active isolation execution, and places executable files in `/var/ossec/active-response/bin/`. It **does not** register Wazuh commands, configure the Manager, restart the Wazuh Agent, change `ossec.conf`, or enable auto-execution.

**Required external integration:** in the AI-SOC Manager, register `isolate.sh` and `block-ip.py` as explicit-agent custom Active Response commands; configure the dedicated `ai-soc-linux` group `agent.conf` JSON localfile and rule 119910 / Indexer ingestion. Do not configure a broad/unfiltered automatic isolation trigger. The exact command registration and evidence routing must match the main AI-SOC deployment.

**Manager IP:** `isolate.sh` is currently a lab-specific script with default Manager IP `192.168.100.192`. The script checks the actual Wazuh `client/server` address, port and TCP protocol, and fails closed when mismatched. **Do not deploy this version at a different Manager IP without explicitly configuring and validating `AI_SOC_WAZUH_MANAGER_IP` in the Active Response process environment or updating the packaged script via a reviewed deployment configuration.** Setting it in a manual shell alone does not guarantee Wazuh Active Response inherits it.

## Evidence and verification

The endpoint emits events to `/var/ossec/logs/ai-soc-verification.json`, which the Wazuh Manager / Indexer must ingest with a provenance-checked rule. Event identifiers and execution identifiers are used for durable correlation. Execution success alone is not an operational verdict.

The live Kali lab demonstrated:
- `EXECUTION_STARTED`, `STATE_SNAPSHOT`, `EXECUTION_COMPLETED` for isolation.
- A transient systemd timer and automatic rollback after the configured 60-second TTL.
- `TTL_AUTO_EXPIRED`, `expired` persistent state, IPv4 and IPv6 isolation rules removed and Agent TCP 1514 restored/preserved after expiry.

This was **a direct endpoint invocation**. The lab execution ID `956f5ab8-411c-48bc-a3aa-6de908bede93` was not a committed execution in the production Orchestrator DB, so it cannot establish an end-to-end Worker verdict.

## Tests

```bash
python3 -m pytest -q tests/unit
```

The tests use fake firewall runners and do not isolate the test host. Run a controlled manual isolation test only on an authorized lab VM with console access and an independently validated rollback path.

## Compatibility policy

- Evidence JSON schema version `1.0`.
- Support deployment from a **single AI-SOC server** managing ordinary Wazuh Agents; no third network-probe host is required for this package.
- Independent firewall-state verification and pre-dispatch semantic validation are under development in the **main AI-SOC** Verification Worker.
- No secrets, Wazuh `client.keys`, local runtime state, captured alerts or private keys should be committed here.
- The Agent scripts remain mirrored in the main repo until integration and packaging regression are completed. Do not remove them prematurely.

## Source and provenance

Initial files imported from `chamsocthaytuan/ai_soc`, branch `feat/v113-integration`. `isolate.sh` contains three Kali runtime compatibility fixes from 2026-11-02: multi-root `ossec.conf`, four-field `ss -H` output and normalized iptables rule comparisons. Their isolated package tests are included in this repository.

