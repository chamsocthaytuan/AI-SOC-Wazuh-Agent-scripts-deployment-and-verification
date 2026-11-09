"""Static and parser-contract checks for the Linux host-isolation script.

These tests do not execute iptables or apply isolation on the test host.
"""

import ast
import json
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "active-response" / "isolate.sh"


def _embedded_python_blocks(source: str):
    return re.findall(r"<<'PY'\n(.*?)\nPY", source, flags=re.DOTALL)


def test_isolate_script_has_valid_bash_syntax():
    script_bytes = SCRIPT.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    subprocess.run(["bash", "-n"], input=script_bytes, check=True)


def test_embedded_python_helpers_are_valid_python():
    source = SCRIPT.read_text(encoding="utf-8")
    blocks = _embedded_python_blocks(source)
    assert len(blocks) >= 5
    for index, block in enumerate(blocks):
        ast.parse(block, filename="isolate.sh:embedded-python-{}".format(index))


def test_wazuh_extra_args_are_parsed_from_stdin_not_shell_positionals(tmp_path):
    source = SCRIPT.read_text(encoding="utf-8")
    start = source.index("parse_request() {")
    end = source.index("\n}\n", start) + 3
    parser_function = source[start:end]
    harness = tmp_path / "parse-request.sh"
    harness.write_text(
        parser_function + '\nprintf "%s\\n" "$1" | parse_request\n',
        encoding="utf-8",
    )
    payload = {
        "command": "add",
        "parameters": {
            "extra_args": [
                "--execution-id", "11111111-1111-4111-8111-111111111111",
                "--plan-id", "PLAN-1", "--action-id", "ACTION-1", "--ttl", "900",
            ]
        },
        "alert": {"data": {"srcip": "192.168.100.217"}},
    }
    result = subprocess.run(
        ["bash", str(harness), json.dumps(payload)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.splitlines() == [
        "add", "", "11111111-1111-4111-8111-111111111111",
        "PLAN-1", "ACTION-1", "900", "192.168.100.217",
    ]


def test_isolation_has_durable_ttl_and_reboot_recovery_contract():
    source = SCRIPT.read_text(encoding="utf-8")
    required = (
        'ISOLATION_TIMEOUT_SECONDS="${AI_SOC_ISOLATION_TIMEOUT_SECONDS:-900}"',
        "MIN_TTL_SECONDS=60",
        "MAX_TTL_SECONDS=3600",
        "/var/lib/ai-soc-isolation",
        "ai-soc-isolation-boot-check.service",
        "--expire-now",
        "--renew",
        "ISOLATION_LOST_ON_REBOOT",
        "TTL_AUTO_EXPIRED",
        "TTL_RENEWED",
        "flock -x 9",
        "generation",
    )
    for fragment in required:
        assert fragment in source


def test_manager_whitelist_is_static_ipv4_tcp_1514_and_fail_closed():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "if ! validate_manager_settings; then" in source
    assert "Wazuh Agent must use only the configured static Manager IPv4/TCP address" in source
    assert '--sport "$WAZUH_MANAGER_PORT" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' in source
    assert '--dport "$WAZUH_MANAGER_PORT" -j ACCEPT' in source
    # The static Manager IP is resolved from the enrolled Agent's ossec.conf;
    # a hardcoded address from an old lab would strand the host on isolation.
    assert 'WAZUH_MANAGER_IP="${AI_SOC_WAZUH_MANAGER_IP:-}"' in source
    assert 'if [[ -z "$WAZUH_MANAGER_IP" ]]; then' in source
    assert 'expected exactly one Wazuh client/server' in source
    assert 'require a literal IPv4 Manager on TCP 1514' in source
    assert 'AI_SOC_WAZUH_MANAGER_IP:-192.168.100.192' not in source
    assert 'AI_SOC_WAZUH_MANAGER_PORT:-1514' in source


def test_firewall_is_dedicated_and_exact_rules_are_checked():
    source = SCRIPT.read_text(encoding="utf-8")
    for chain in (
        "AI_SOC_ISO_IN", "AI_SOC_ISO_OUT", "AI_SOC_ISO_FWD",
        "AI_SOC_ISO6_IN", "AI_SOC_ISO6_OUT", "AI_SOC_ISO6_FWD",
    ):
        assert chain in source
    assert '"$binary" -w 5 -N "$chain"' in source
    assert "verify_firewall_active" in source
    assert 'hook_rules = {name: [] for name in hooks}' in source
    assert 'hook_rules[0] != ["-j", name]' in source
    assert 'rules_sha256' in source
    assert 'rule[index] in ("-j", "--jump")' in source
    assert "iptables -P INPUT DROP" not in source
    assert "iptables -P OUTPUT DROP" not in source
    assert '"$IPTABLES_BIN" -w 5 -F INPUT' not in source
    assert '"$IP6TABLES_BIN" -w 5 -F INPUT' not in source


def test_jsonl_evidence_contract_and_required_event_types():
    source = SCRIPT.read_text(encoding="utf-8")
    for event_type in (
        "EXECUTION_STARTED", "EXECUTION_COMPLETED", "EXECUTION_FAILED",
        "STATE_SNAPSHOT", "ROLLBACK_STARTED", "ROLLBACK_COMPLETED",
        "ROLLBACK_FAILED", "TTL_RENEWED", "TTL_AUTO_EXPIRED",
        "ISOLATION_LOST_ON_REBOOT",
    ):
        assert event_type in source
    assert '"schema_version":"1.0"' in source
    assert '"event_id":str(uuid.uuid4())' in source
    assert '"execution_id":execution' in source
    assert '"host":{"boot_id":boot' in source
    assert 'python3 "$EVIDENCE_WRITER"' in source
    assert 'reserved_chains_absent "$pre_state"' in source
    assert 'verify_firewall_active "$post_state" "$pre_state"' in source


def _embedded_block_in_function(source: str, function_name: str) -> str:
    marker = function_name + "() {"
    start = source.index(marker)
    heredoc = source.index("<<'PY'\n", start) + len("<<'PY'\n")
    end = source.index("\nPY\n", heredoc)
    return source[heredoc:end]


def _run_embedded_python(block: str, *args: str):
    return subprocess.run(
        [__import__("sys").executable, "-", *args],
        input=block,
        check=True,
        capture_output=True,
        text=True,
    )


def test_capture_state_records_manager_listener_and_firewall_snapshots(tmp_path):
    source = SCRIPT.read_text(encoding="utf-8")
    block = _embedded_block_in_function(source, "capture_state")
    boot_id = tmp_path / "boot_id"
    boot_id.write_text("11111111-1111-4111-8111-111111111111\n", encoding="ascii")
    ss = tmp_path / "ss"
    ss.write_text(
        "#!/bin/sh\n"
        "case \"$*\" in\n"
        "  *established*) echo 'ESTAB 0 0 192.168.100.217:52144 192.168.100.192:1514' ;;\n"
        "  *) echo 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*' ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    ss.chmod(0o755)

    v4save = tmp_path / "iptables-save"
    v4save.write_text(
        "#!/bin/sh\ncat <<'RULES'\n"
        "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n"
        ":AI_SOC_ISO_IN - [0:0]\n-A INPUT -p tcp --dport 8443 -j AI_SOC_ISO_IN\n"
        "COMMIT\nRULES\n",
        encoding="utf-8",
    )
    v4save.chmod(0o755)
    v6save = tmp_path / "ip6tables-save"
    v6save.write_text(
        "#!/bin/sh\ncat <<'RULES'\n"
        "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\nRULES\n",
        encoding="utf-8",
    )
    v6save.chmod(0o755)

    result = _run_embedded_python(
        block, str(boot_id), str(ss), str(v4save), str(v6save),
        "192.168.100.192", "1514",
    )
    snapshot = json.loads(result.stdout)
    assert snapshot["manager_tcp_connection_reachable"] is True
    assert snapshot["manager_connection_remote_port"] == 1514
    assert snapshot["listening_tcp_ports"] == [22]
    assert snapshot["ipv4_firewall"]["policies"] == {
        "INPUT": "ACCEPT", "OUTPUT": "ACCEPT", "FORWARD": "ACCEPT"
    }
    # A conditional jump to a reserved chain is still a collision; do not flush it.
    assert snapshot["ipv4_firewall"]["owned_jumps"]["INPUT->AI_SOC_ISO_IN"] is True
    assert snapshot["ipv4_firewall"]["chain_rules_json"]["AI_SOC_ISO_IN"] == "[]"
    assert snapshot["ipv6_firewall"]["available"] is True
    # Chat 4's writer rejects lists of objects and nested arrays in evidence.
    json.dumps(snapshot, allow_nan=False)
    for family in ("ipv4_firewall", "ipv6_firewall"):
        for value in snapshot[family]["chain_rules_json"].values():
            assert isinstance(value, str)


def test_firewall_verifier_requires_exact_chains_top_jumps_and_manager_session():
    source = SCRIPT.read_text(encoding="utf-8")
    block = _embedded_block_in_function(source, "verify_firewall_active")
    manager = "192.168.100.192"
    port = "1514"

    def family(prefix, is_v6=False):
        names = [prefix + suffix for suffix in ("_IN", "_OUT", "_FWD")]
        if is_v6:
            rules = [
                [["-i", "lo", "-j", "ACCEPT"], ["-j", "DROP"]],
                [["-o", "lo", "-j", "ACCEPT"], ["-j", "DROP"]],
                [["-j", "DROP"]],
            ]
        else:
            rules = [
                [["-i", "lo", "-j", "ACCEPT"],
                 ["-s", manager, "-p", "tcp", "--sport", port, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], ["-j", "DROP"]],
                [["-o", "lo", "-j", "ACCEPT"],
                 ["-d", manager, "-p", "tcp", "--dport", port, "-j", "ACCEPT"], ["-j", "DROP"]],
                [["-j", "DROP"]],
            ]
        hooks = ["INPUT", "OUTPUT", "FORWARD"]
        return {
            "available": True,
            "policies": {hook: "ACCEPT" for hook in hooks},
            "owned_chains": {name: True for name in names},
            "owned_jumps": {hook + "->" + name: True for hook, name in zip(hooks, names)},
            "chain_rules_json": {name: json.dumps(rule, separators=(",", ":")) for name, rule in zip(names, rules)},
            "hook_rules_json": {hook: json.dumps([["-j", name]], separators=(",", ":")) for hook, name in zip(hooks, names)},
        }

    pre = {
        "ipv4_firewall": {"available": True, "policies": {h: "ACCEPT" for h in ("INPUT", "OUTPUT", "FORWARD")}},
        "ipv6_firewall": {"available": True, "policies": {h: "ACCEPT" for h in ("INPUT", "OUTPUT", "FORWARD")}},
    }
    post = {
        "manager_tcp_connection_reachable": True,
        "ipv4_firewall": family("AI_SOC_ISO"),
        "ipv6_firewall": family("AI_SOC_ISO6", is_v6=True),
    }
    args = [json.dumps(post), json.dumps(pre), manager, port]
    _run_embedded_python(block, *args)

    altered = json.loads(json.dumps(post))
    altered_rules = json.loads(altered["ipv4_firewall"]["chain_rules_json"]["AI_SOC_ISO_OUT"])
    altered_rules[-1] = ["-j", "ACCEPT"]
    altered["ipv4_firewall"]["chain_rules_json"]["AI_SOC_ISO_OUT"] = json.dumps(altered_rules, separators=(",", ":"))
    rejected_altered = subprocess.run(
        [__import__("sys").executable, "-", json.dumps(altered), json.dumps(pre), manager, port],
        input=block, capture_output=True, text=True,
    )
    assert rejected_altered.returncode != 0
    altered["manager_tcp_connection_reachable"] = False
    rejected_manager = subprocess.run(
        [__import__("sys").executable, "-", json.dumps(altered), json.dumps(pre), manager, port],
        input=block, capture_output=True, text=True,
    )
    assert rejected_manager.returncode != 0


def test_snapshot_shape_is_compatible_with_chat4_jsonl_writer(tmp_path):
    source = SCRIPT.read_text(encoding="utf-8")
    block = _embedded_block_in_function(source, "capture_state")
    boot_id = tmp_path / "boot_id"
    boot_id.write_text("11111111-1111-4111-8111-111111111111\n", encoding="ascii")
    ss = tmp_path / "ss"
    ss.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    ss.chmod(0o755)
    v4 = tmp_path / "iptables-save"
    v4.write_text("#!/bin/sh\necho '*filter'; echo ':INPUT ACCEPT [0:0]'; echo ':OUTPUT ACCEPT [0:0]'; echo ':FORWARD ACCEPT [0:0]'; echo COMMIT\n", encoding="utf-8")
    v4.chmod(0o755)
    v6 = tmp_path / "ip6tables-save"
    v6.write_text(v4.read_text(encoding="utf-8"), encoding="utf-8")
    v6.chmod(0o755)
    result = _run_embedded_python(block, str(boot_id), str(ss), str(v4), str(v6), "192.168.100.192", "1514")
    snapshot = json.loads(result.stdout)

    def assert_writer_compatible(value):
        if isinstance(value, dict):
            for child in value.values():
                assert_writer_compatible(child)
        elif isinstance(value, list):
            assert all(not isinstance(child, (dict, list)) for child in value)
            for child in value:
                assert_writer_compatible(child)

    assert_writer_compatible(snapshot)
    assert "manager_connections" not in snapshot
    assert "chain_rules_json" in snapshot["ipv4_firewall"]
    assert "hook_rules_json" in snapshot["ipv6_firewall"]


def test_state_context_loads_record_in_one_deserialization_pass():
    source = SCRIPT.read_text(encoding="utf-8")
    start = source.index("read_state_context() {")
    end = source.index("\n}\n", start)
    function = source[start:end]
    assert "parsed=\"$(python3 - \"$STATE_FILE\"" in function
    assert "mapfile -t state_fields" in function
    assert "state_get" not in function


def test_wazuh_rollback_and_renew_arguments_are_parsed_from_extra_args(tmp_path):
    source = SCRIPT.read_text(encoding="utf-8")
    start = source.index("parse_request() {")
    end = source.index("\n}\n", start) + 3
    harness = tmp_path / "parse-request.sh"
    harness.write_text(
        source[start:end] + '\nprintf "%s\\n" "$1" | parse_request\n',
        encoding="utf-8",
    )
    execution_id = "11111111-1111-4111-8111-111111111111"
    cases = (
        ({"command": "add", "parameters": {"extra_args": ["--rollback", "--execution-id", execution_id]}}, "rollback"),
        ({"command": "add", "parameters": {"extra_args": ["--renew", "--ttl", "1200", "--execution-id", execution_id]}}, "renew"),
    )
    for payload, expected_mode in cases:
        result = subprocess.run(
            ["bash", str(harness), json.dumps(payload)], check=True,
            capture_output=True, text=True,
        )
        fields = result.stdout.splitlines()
        assert fields[1] == expected_mode
        assert fields[2] == execution_id
        if expected_mode == "renew":
            assert fields[5] == "1200"


def test_manager_config_validator_rejects_dns_and_non_tcp_manager(tmp_path):
    source = SCRIPT.read_text(encoding="utf-8")
    block = _embedded_block_in_function(source, "validate_manager_settings")
    config = tmp_path / "ossec.conf"
    config.write_text(
        "<ossec_config><client><server><address>192.168.100.192</address>"
        "<port>1514</port><protocol>tcp</protocol></server></client></ossec_config>",
        encoding="utf-8",
    )
    _run_embedded_python(block, "192.168.100.192", "1514", str(config))
    config.write_text(
        "<ossec_config><client><server><address>wazuh-manager</address>"
        "<port>1514</port><protocol>tcp</protocol></server></client></ossec_config>",
        encoding="utf-8",
    )
    rejected_dns = subprocess.run(
        [__import__("sys").executable, "-", "192.168.100.192", "1514", str(config)],
        input=block, capture_output=True, text=True,
    )
    assert rejected_dns.returncode != 0
    config.write_text(
        "<ossec_config><client><server><address>192.168.100.192</address>"
        "<port>1514</port><protocol>udp</protocol></server></client></ossec_config>",
        encoding="utf-8",
    )
    rejected_udp = subprocess.run(
        [__import__("sys").executable, "-", "192.168.100.192", "1514", str(config)],
        input=block, capture_output=True, text=True,
    )
    assert rejected_udp.returncode != 0


def test_preflight_failures_are_reported_as_execution_failed_events():
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'emit_evidence "EXECUTION_FAILED" "$step" "failed" "1"' in source
    assert 'report_execution_failure "validate_manager_channel_and_firewall_baseline"' in source
    assert 'report_execution_failure "start_independent_safety_timer"' in source
