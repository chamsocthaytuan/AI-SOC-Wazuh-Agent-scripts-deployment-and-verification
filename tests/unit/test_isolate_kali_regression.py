"""Regressions for real Kali Agent 008 isolation fixes (2026-11-02).

These tests do not execute firewall commands or isolate the host.
"""
from pathlib import Path
import ast
import ipaddress
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "active-response" / "isolate.sh"


def embedded(function):
    source = SCRIPT.read_text(encoding="utf-8")
    start = source.index(function + "() {")
    begin = source.index("<<'PY'\n", start) + len("<<'PY'\n")
    end = source.index("\nPY\n", begin)
    return source[begin:end]


def test_multi_root_config_with_exact_tcp_manager(tmp_path):
    validator = embedded("validate_manager_settings")
    config = tmp_path / "ossec.conf"
    config.write_text(
        "<ossec_config><client><server><address>192.168.100.192</address>"
        "<port>1514</port><protocol>tcp</protocol></server></client></ossec_config>"
        "<ossec_config><localfile><location>/var/log/syslog</location>"
        "<log_format>syslog</log_format></localfile></ossec_config>"
    )
    args = [sys.executable, "-", "192.168.100.192", "1514", str(config)]
    result = subprocess.run(args, input=validator, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    config.write_text(config.read_text().replace("<protocol>tcp</protocol>", "<protocol>udp</protocol>"))
    rejected = subprocess.run(args, input=validator, text=True, capture_output=True)
    assert rejected.returncode != 0


def test_ss_four_column_established_output_is_supported():
    source = embedded("capture_state")
    assert "if len(fields) < 4:" in source
    assert 'local, remote = endpoint(fields[-2]), endpoint(fields[-1])' in source


def test_iptables_save_equivalent_tokens_do_not_mask_a_changed_target():
    tree = ast.parse(embedded("verify_firewall_active"))
    fn = next(
        item for item in tree.body
        if isinstance(item, ast.FunctionDef) and item.name == "normalize_rule"
    )
    ns = {"ipaddress": ipaddress}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "<test>", "exec"), ns)
    normalize = ns["normalize_rule"]

    expected = (
        "-s 192.168.100.192 -p tcp --sport 1514 "
        "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    ).split()
    observed = (
        "-s 192.168.100.192/32 -p tcp -m tcp --sport 1514 "
        "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    ).split()

    assert normalize(expected) == normalize(observed)
    assert normalize(expected) != normalize(observed[:-1] + ["DROP"])
    assert normalize(expected) != normalize(
        [("192.168.100.193" if x == "192.168.100.192/32" else x) for x in observed]
    )
