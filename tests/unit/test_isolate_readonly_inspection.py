"""Non-disruptive contract tests for read-only Isolate inspection."""
from pathlib import Path
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "active-response" / "isolate.sh"


def parser():
    s = SCRIPT.read_text()
    begin = s.index("parse_request() {")
    end = s.index("\n}\n", begin)
    return s[begin:end+2] + "\nparse_request\n"


def test_inspect_active_response_mode_parses_existing_execution_id():
    message = {
        "command": "add",
        "parameters": {"extra_args": [
            "--execution-id", "956f5ab8-411c-48bc-a3aa-6de908bede93",
            "--inspect",
        ]},
        "alert": {"data": {"srcip": "192.168.100.140"}},
    }
    result = subprocess.run(
        ["bash", "-c", parser()],
        input=json.dumps(message), capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    parts = result.stdout.splitlines()
    assert parts[:3] == [
        "add", "inspect", "956f5ab8-411c-48bc-a3aa-6de908bede93"
    ]


def test_inspect_never_mutates_firewall_or_ttl():
    source = SCRIPT.read_text()
    start = source.index("inspect_execution() {")
    end = source.index("\n}\n", start)
    block = source[start:end]
    assert 'read_state_context "$execution_id"' in block
    assert 'capture_state' in block
    assert 'verify_firewall_active "$post_state" "$STATE_PRE"' in block
    assert "independent_endpoint_inspection" in block
    assert 'emit_evidence "STATE_SNAPSHOT"' in block
    assert 'STATE_STATUS" == "active"' in block
    assert 'STATE_BOOT_ID" == "$current_boot"' in block
    for forbidden in (
        "build_firewall", "rollback_firewall", "iptables -", "ip6tables -",
        "start_expiry_timer", "renew_execution", "expire_execution",
        "write_state", "mark_inactive", "systemd-run",
    ):
        assert forbidden not in block


def test_inspection_wazuh_and_shell_entrypoint():
    source = SCRIPT.read_text()
    assert 'if item in ("--rollback", "--renew", "--check-boot", "--inspect"):' in source
    assert '        inspect) inspect_execution "$execution_id" ;;' in source
    assert '            inspect_execution "$2"' in source
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
