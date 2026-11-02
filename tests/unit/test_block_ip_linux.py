"""Unit tests for the Linux Block IP Wazuh Active Response script.

No test in this module invokes the host firewall. Backend commands are handled
by in-memory fake command runners so CI remains non-disruptive.
"""

import importlib.util
import json
import pathlib
import sys
import uuid

import pytest

SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "active-response" / "block-ip.py"
SPEC = importlib.util.spec_from_file_location("ai_soc_block_ip", SCRIPT)
block = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = block
SPEC.loader.exec_module(block)

EXECUTION_ID = "3d7a1f9e-1c1a-4e17-b6c9-0b2b5ca0a110"


def request(**overrides):
    value = {
        "plan_id": "plan-test-01",
        "action_id": "action-test-01",
        "execution_id": EXECUTION_ID,
        "target_ip": "203.0.113.25",
        "ip_version": 4,
        "direction": "INPUT",
        "operation": "apply",
        "backend": "nftables",
    }
    value.update(overrides)
    return value


def result(rc=0, stdout="", stderr=""):
    return block.CommandResult(rc, stdout, stderr)


class FakeNft:
    def __init__(self):
        self.table = False
        self.chains = {}
        self.next_handle = 100
        self.calls = []

    def __call__(self, argv, timeout):
        args = list(argv[1:])
        self.calls.append(args)
        if args[:2] == ["list", "ruleset"]:
            return result(stdout="")
        if args[:2] == ["list", "table"]:
            return result(stdout="table inet ai_soc_block_ip {}\n") if self.table else result(1, stderr="No such file")
        if args[:2] == ["add", "table"]:
            self.table = True
            return result()
        if args and args[0] == "-a":
            args = args[1:]
        if args[:2] == ["list", "chain"]:
            hook = args[-1]
            chain = self.chains.get(hook)
            if not chain:
                return result(1, stderr="No such file or directory")
            lines = [
                "table inet ai_soc_block_ip {",
                # Match real 'nft -a list chain' where the CHAIN itself
                # has a handle; that must not be counted as a rule position.
                " chain {} {{ # handle 1".format(hook),
                "   type filter hook {} priority filter - 100; policy accept;".format(hook),
            ]
            lines.extend(chain["rules"])
            return result(stdout="\n".join(lines) + "\n")
        if args[:2] == ["add", "chain"]:
            hook = args[4]
            self.chains.setdefault(hook, {"rules": []})
            return result()
        if args[:2] in (["add", "rule"], ["insert", "rule"]):
            hook = args[4]
            family, field, target = args[5], args[6], args[7]
            # The real nft CLI parses expressions, not Python argv tokens.
            # Unquoted comments containing ':' produce nft syntax errors.
            raw_comment = args[-1]
            if not (raw_comment.startswith('"') and raw_comment.endswith('"')):
                return result(1, stderr="syntax error: nft comment must be quoted")
            marker = raw_comment[1:-1]
            self.next_handle += 1
            line = (
                "  {} {} {} counter packets 0 bytes 0 drop comment \"{}\" # handle {}"
                .format(family, field, target, marker, self.next_handle)
            )
            if args[0] == "insert":
                self.chains[hook]["rules"].insert(0, line)
            else:
                self.chains[hook]["rules"].append(line)
            return result()
        if args[:2] == ["delete", "rule"]:
            hook = args[4]
            handle = int(args[6])
            chain = self.chains.get(hook)
            if not chain:
                return result(1, stderr="No such chain")
            chain["rules"] = [
                line for line in chain["rules"]
                if not ("handle {}".format(handle) in line)
            ]
            return result()
        return result(1, stderr="unhandled fake nft command: {}".format(args))


class FakeIptables:
    def __init__(self):
        self.chains = {4: {}, 6: {}}
        self.hooks = {
            4: {"INPUT": ["-A INPUT -j EXISTING_ALLOW"], "OUTPUT": [], "FORWARD": []},
            6: {"INPUT": [], "OUTPUT": [], "FORWARD": []},
        }
        self.calls = []

    @staticmethod
    def _line(chain, args):
        return "-A {} {}".format(chain, " ".join(args))

    def __call__(self, argv, timeout):
        binary = argv[0]
        version = 6 if "ip6tables" in binary else 4
        args = list(argv[1:])
        self.calls.append((version, args))
        if args[:2] == ["-w", "5"]:
            args = args[2:]
        if args == ["-V"]:
            return result(stdout="iptables v1.8.9 (nf_tables)\n")
        if args == ["-S"]:
            return result(stdout="")
        if args and args[0] == "-S":
            chain = args[1]
            if chain in self.hooks[version]:
                return result(stdout="\n".join(self.hooks[version][chain]) + "\n")
            if chain in self.chains[version]:
                return result(stdout="\n".join(self.chains[version][chain]) + "\n")
            return result(1, stderr="iptables: No chain/target/match by that name")
        if args and args[0] == "-N":
            chain = args[1]
            if chain in self.chains[version]:
                return result(1, stderr="Chain already exists")
            self.chains[version][chain] = []
            return result()
        if args and args[0] == "-C":
            chain = args[1]
            expected = self._line(chain, args[2:])
            rows = self.hooks[version].get(chain, self.chains[version].get(chain, []))
            return result() if expected in rows else result(1, stderr="Rule does not exist")
        if args and args[0] == "-I":
            chain = args[1]
            index = int(args[2]) - 1
            rows = self.hooks[version].get(chain, self.chains[version].get(chain))
            if rows is None:
                return result(1, stderr="No such chain")
            rows.insert(index, self._line(chain, args[3:]))
            return result()
        if args and args[0] == "-A":
            chain = args[1]
            self.chains[version][chain].append(self._line(chain, args[2:]))
            return result()
        if args and args[0] == "-D":
            chain = args[1]
            expected = self._line(chain, args[2:])
            rows = self.hooks[version].get(chain, self.chains[version].get(chain, []))
            if expected not in rows:
                return result(1, stderr="Rule does not exist")
            rows.remove(expected)
            return result()
        return result(1, stderr="unhandled fake iptables command: {}".format(args))


def test_wazuh_message_extracts_extra_args_not_shell_arguments():
    args = [
        "--plan-id", "plan-1", "--action-id", "action-1",
        "--execution-id", EXECUTION_ID, "--target-ip", "198.51.100.8",
        "--direction", "inbound",
    ]
    raw = json.dumps({
        "version": 1,
        "command": "add",
        "parameters": {"extra_args": args, "alert": {"data": {"srcip": "198.51.100.8"}}},
    })
    command, extracted = block.parse_wazuh_message(raw)
    parsed = block.parse_request(command, extracted)
    assert parsed["target_ip"] == "198.51.100.8"
    assert parsed["direction"] == "INPUT"
    assert parsed["execution_id"] == EXECUTION_ID



def test_explicit_rollback_can_be_dispatched_by_direct_custom_script_api():
    parsed = block.parse_request("add", [
        "--plan-id", "plan-1", "--action-id", "action-1",
        "--execution-id", EXECUTION_ID, "--target-ip", "203.0.113.25",
        "--direction", "inbound", "--operation", "rollback", "--backend", "nftables",
    ])
    assert parsed["operation"] == "rollback"


def test_rollback_and_inspect_reject_iptables_alias_without_persisted_variant():
    for operation in ("rollback", "inspect"):
        with pytest.raises(block.BlockIPError, match="exact persisted firewall_tool"):
            block.parse_request("add", [
                "--plan-id", "plan-1", "--action-id", "action-1",
                "--execution-id", EXECUTION_ID, "--target-ip", "203.0.113.25",
                "--direction", "inbound", "--operation", operation, "--backend", "iptables",
            ])


def test_missing_execution_id_and_malformed_ip_fail_closed():
    with pytest.raises(block.BlockIPError, match="execution_id"):
        block.parse_request("add", [
            "--plan-id", "p", "--action-id", "a", "--target-ip", "203.0.113.1",
            "--direction", "inbound",
        ])
    with pytest.raises(block.BlockIPError, match="valid IPv4 or IPv6"):
        block.validate_target("203.0.113.999")
    with pytest.raises(block.BlockIPError, match="unspecified"):
        block.validate_target("0.0.0.0")
    with pytest.raises(block.BlockIPError, match="loopback"):
        block.validate_target("::1")
    with pytest.raises(block.BlockIPError, match="zone-qualified"):
        block.validate_target("fe80::1%eth0")


def test_native_nftables_apply_inspect_and_rollback_only_execution_rule():
    fake = FakeNft()
    backend = block.NftablesBackend("nft", fake)
    req = request(direction="INPUT")

    state = backend.apply(req)
    assert state["rule_present"] is True
    assert state["expected_rule_count"] == 1
    # Regression: with a base-chain header '# handle 1', the actual first
    # firewall rule must still report chain_rule_position:1, not position 2.
    assert state["rule_positions"] == ["hook_priority:-100;chain_rule_position:1"]
    input_chain = fake.chains["input"]
    assert len(input_chain["rules"]) == 1
    assert 'ip saddr 203.0.113.25' in input_chain["rules"][0]
    assert 'comment "aisoc:{}"'.format(EXECUTION_ID) in input_chain["rules"][0]
    assert any("priority -100" in " ".join(call) for call in fake.calls)
    assert any(
        call[:2] == ["insert", "rule"]
        and call[-2] == "comment"
        and call[-1] == '"aisoc:{}"'.format(EXECUTION_ID)
        for call in fake.calls
    )

    # A foreign rule in the same AI-SOC table must survive rollback.
    input_chain["rules"].append(
        'ip saddr 198.51.100.3 counter packets 9 bytes 900 drop comment "other-owner" # handle 999'
    )
    removed = backend.remove(req)
    assert removed["rule_present"] is False
    assert len(input_chain["rules"]) == 1
    assert "other-owner" in input_chain["rules"][0]


def test_nftables_inserts_execution_drop_before_existing_accept():
    fake = FakeNft()
    fake.table = True
    fake.chains["input"] = {"rules": ["  accept comment \"legacy-allow\" # handle 91"]}
    backend = block.NftablesBackend("nft", fake)
    state = backend.apply(request())
    assert state["rule_present"] is True
    assert " drop " in fake.chains["input"]["rules"][0]
    assert "legacy-allow" in fake.chains["input"]["rules"][1]


def test_nftables_ipv6_outbound_uses_destination_match():
    fake = FakeNft()
    backend = block.NftablesBackend("nft", fake)
    req = request(
        target_ip="2001:db8::10", ip_version=6, direction="OUTPUT",
        execution_id="5be2d2a8-5bf2-4cdb-b923-0812f9b6351c",
    )
    state = backend.apply(req)
    assert state["rule_present"] is True
    line = fake.chains["output"]["rules"][0]
    assert "ip6 daddr 2001:db8::10" in line
    assert "ip6 saddr" not in line


def test_iptables_backend_places_owned_jump_first_and_preserves_foreign_rules():
    fake = FakeIptables()
    backend = block.IptablesBackend("iptables", "ip6tables", fake, "iptables-nft")
    req = request(direction="INPUT")
    # Simulate an unexpected permissive rule left in the dedicated chain.
    fake.chains[4]["AI_SOC_BIP_IN"] = ["-A AI_SOC_BIP_IN -j ACCEPT"]

    state = backend.apply(req)
    assert state["rule_present"] is True
    assert fake.hooks[4]["INPUT"][0] == "-A INPUT -j AI_SOC_BIP_IN"
    assert len(fake.chains[4]["AI_SOC_BIP_IN"]) == 2
    assert "--comment aisoc:{}".format(EXECUTION_ID) in fake.chains[4]["AI_SOC_BIP_IN"][0]
    assert fake.chains[4]["AI_SOC_BIP_IN"][1] == "-A AI_SOC_BIP_IN -j ACCEPT"

    # Keep an unrelated rule in the dedicated chain; remove only this execution.
    fake.chains[4]["AI_SOC_BIP_IN"].append(
        "-A AI_SOC_BIP_IN -s 198.51.100.9 -m comment --comment other-owner -j DROP"
    )
    removed = backend.remove(req)
    assert removed["rule_present"] is False
    assert len(fake.chains[4]["AI_SOC_BIP_IN"]) == 2
    assert fake.chains[4]["AI_SOC_BIP_IN"][0] == "-A AI_SOC_BIP_IN -j ACCEPT"
    assert "other-owner" in fake.chains[4]["AI_SOC_BIP_IN"][1]


def test_iptables_repositions_own_jump_if_an_accept_rule_precedes_it():
    fake = FakeIptables()
    backend = block.IptablesBackend("iptables", "ip6tables", fake)
    req = request()
    backend.apply(req)
    hook_lines = fake.hooks[4]["INPUT"]
    assert hook_lines[0] == "-A INPUT -j AI_SOC_BIP_IN"
    assert hook_lines[1] == "-A INPUT -j EXISTING_ALLOW"

    # Simulate external drift placing a permissive rule above our jump.
    jump = hook_lines.pop(0)
    hook_lines.insert(0, "-A INPUT -j THIRD_PARTY_ACCEPT")
    hook_lines.insert(1, jump)
    backend.apply(req)
    assert fake.hooks[4]["INPUT"][0] == "-A INPUT -j AI_SOC_BIP_IN"


def test_execution_marker_cannot_be_reused_for_another_direction():
    nft_fake = FakeNft()
    nft_backend = block.NftablesBackend("nft", nft_fake)
    first = request(direction="INPUT")
    nft_backend.apply(first)
    conflicting = request(direction="OUTPUT")
    with pytest.raises(block.BlockIPError, match="unexpected nftables INPUT direction"):
        nft_backend.inspect(conflicting)

    ipt_fake = FakeIptables()
    ipt_backend = block.IptablesBackend("iptables", "ip6tables", ipt_fake)
    ipt_backend.apply(first)
    with pytest.raises(block.BlockIPError, match="unexpected iptables INPUT direction"):
        ipt_backend.inspect(conflicting)


def test_both_direction_creates_two_independent_hooks():
    fake = FakeNft()
    backend = block.NftablesBackend("nft", fake)
    req = request(direction="BOTH")
    state = backend.apply(req)
    assert state["rule_present"] is True
    assert state["rule_count"] == 2
    assert len(fake.chains["input"]["rules"]) == 1
    assert len(fake.chains["output"]["rules"]) == 1


def test_same_execution_apply_and_rollback_are_idempotent():
    fake = FakeNft()
    backend = block.NftablesBackend("nft", fake)
    req = request()
    assert backend.apply(req)["rule_count"] == 1
    assert backend.apply(req)["rule_count"] == 1
    assert len(fake.chains["input"]["rules"]) == 1
    assert backend.remove(req)["rule_present"] is False
    assert backend.remove(req)["rule_present"] is False


def test_backend_detection_requires_persisted_iptables_tool_to_match_runtime():
    def fake_which(name):
        return "/usr/sbin/" + name if name in {"iptables", "ip6tables"} else None

    def fake_runner(argv, timeout):
        if argv[-1:] == ["-V"]:
            return result(stdout="iptables v1.8.9 (nf_tables)")
        return result(stdout="")

    with pytest.raises(block.BlockIPError, match="persisted firewall_tool"):
        block.detect_backend("iptables-legacy", fake_runner, fake_which)


def test_connection_inspection_is_read_only_and_reports_available_tools(monkeypatch):
    monkeypatch.setattr(block.shutil, "which", lambda name: "/usr/sbin/" + name)
    calls = []

    def fake_runner(argv, timeout):
        calls.append(list(argv))
        if argv[-1:] == ["--state"]:
            return result(stdout="running\n")
        if argv[-1:] == ["-h"]:
            return result(stdout="-D, --delete\n-K, --kill\n")
        if argv[0].endswith("conntrack"):
            return result(stdout=(
                "tcp 6 431999 ESTABLISHED src=203.0.113.25 dst=192.0.2.5\n"
                "tcp 6 431999 ESTABLISHED src=203.0.113.250 dst=192.0.2.5\n"
            ))
        if argv[0].endswith("ss") and "-Htn" in argv:
            return result(stdout=(
                "ESTAB 0 0 192.0.2.5:443 203.0.113.25:51234\n"
                "ESTAB 0 0 192.0.2.5:443 203.0.113.250:51234\n"
            ))
        return result()

    observed = block.inspect_existing_connections("203.0.113.25", fake_runner)
    assert observed["conntrack_available"] is True
    assert observed["firewalld_active"] is True
    assert observed["conntrack_delete_available"] is True
    assert observed["conntrack_entries"] == 1
    assert observed["ss_available"] is True
    assert observed["ss_kill_available"] is True
    assert observed["established_socket_count"] == 1
    assert not any("-D" in call or "-K" in call for call in calls)


def test_backend_detection_prefers_native_nftables():
    def fake_which(name):
        return "/usr/sbin/" + name if name in {"nft", "iptables", "ip6tables"} else None

    def fake_runner(argv, timeout):
        if argv[-2:] == ["list", "ruleset"]:
            return result(stdout="")
        raise AssertionError("iptables fallback should not be probed")

    backend = block.detect_backend("auto", fake_runner, fake_which)
    assert isinstance(backend, block.NftablesBackend)
    assert backend.tool == "nft"


def test_backend_detection_rejects_mixed_ipv4_ipv6_iptables_backends():
    def fake_which(name):
        return "/usr/sbin/" + name if name in {"iptables", "ip6tables"} else None

    def fake_runner(argv, timeout):
        if argv[-1:] == ["-V"]:
            if "ip6tables" in argv[0]:
                return result(stdout="ip6tables v1.8.9 (legacy)")
            return result(stdout="iptables v1.8.9 (nf_tables)")
        return result(stdout="")

    with pytest.raises(block.BlockIPError, match="different backends"):
        block.detect_backend("iptables", fake_runner, fake_which)


def test_evidence_event_carries_database_and_endpoint_correlation_contract():
    req = request()
    state = {
        "rule_present": True,
        "firewall_backend": "linux_netfilter",
        "firewall_tool": "nft",
        "ip_version": 4,
        "direction": "INPUT",
        "packet_count": 2,
        "byte_count": 128,
    }
    event = block.make_evidence_event(
        req, "EXECUTION_COMPLETED", "install_rule", "success", 0,
        state, {"rule_present": False}, state,
        block.NftablesBackend(),
    )
    assert str(uuid.UUID(event["event_id"])) == event["event_id"]
    assert event["execution_id"] == EXECUTION_ID
    assert event["plan_id"] == "plan-test-01"
    assert event["action_id"] == "action-test-01"
    assert event["action"]["firewall_backend"] == "linux_netfilter"
    assert event["action"]["firewall_tool"] == "nft"
    assert event["event"]["type"] == "EXECUTION_COMPLETED"
    assert event["post_state"]["rule_present"] is True


def test_evidence_writer_failure_does_not_change_successful_action_result():
    fake = FakeNft()
    backend = block.NftablesBackend("nft", fake)
    emitted = []
    exit_code = block.execute_request(
        request(), backend, "apply",
        evidence_writer=lambda event: emitted.append(event) or False,
        connection_inspector=lambda _ip: {"conntrack_available": False, "ss_available": False},
        lock_dir="/tmp/ai-soc-block-ip-unit-locks",
    )
    assert exit_code == 0
    assert any(item["event"]["type"] == "EXECUTION_COMPLETED" for item in emitted)
    assert backend.inspect(request())["rule_present"] is True


def test_evidence_writer_exception_never_changes_firewall_action_result():
    fake = FakeNft()
    backend = block.NftablesBackend("nft", fake)

    def broken_writer(_event):
        raise OSError("evidence volume unavailable")

    exit_code = block.execute_request(
        request(), backend, "apply",
        evidence_writer=broken_writer,
        connection_inspector=lambda _ip: {},
        lock_dir="/tmp/ai-soc-block-ip-unit-locks",
    )
    assert exit_code == 0
    assert backend.inspect(request())["rule_present"] is True


def test_failed_second_hook_cleans_up_partial_both_direction_apply():
    class FailOutputNft(FakeNft):
        def __call__(self, argv, timeout):
            args = list(argv[1:])
            if args[:2] == ["insert", "rule"] and len(args) > 4 and args[4] == "output":
                return result(1, stderr="simulated output hook failure")
            return super().__call__(argv, timeout)

    fake = FailOutputNft()
    backend = block.NftablesBackend("nft", fake)
    emitted = []
    exit_code = block.execute_request(
        request(direction="BOTH"), backend, "apply",
        evidence_writer=lambda event: emitted.append(event) or True,
        connection_inspector=lambda _ip: {},
        lock_dir="/tmp/ai-soc-block-ip-unit-locks",
    )
    assert exit_code == 1
    assert all("aisoc:{}".format(EXECUTION_ID) not in line for line in fake.chains["input"]["rules"])
    failed = [event for event in emitted if event["event"]["type"] == "EXECUTION_FAILED"]
    assert failed
    assert failed[-1]["post_state"]["partial_apply_cleanup_succeeded"] is True


def test_iptables_apply_failure_emits_execution_failed_not_completed():
    class FailingIptables(FakeIptables):
        def __call__(self, argv, timeout):
            args = list(argv[1:])
            if args[:2] == ["-w", "5"]:
                command = args[2:]
                if command and command[0] == "-I" and len(command) > 1 and command[1] == "AI_SOC_BIP_IN":
                    return result(1, stderr="permission denied")
            return super().__call__(argv, timeout)

    fake = FailingIptables()
    backend = block.IptablesBackend("iptables", "ip6tables", fake)
    emitted = []
    exit_code = block.execute_request(
        request(), backend, "apply",
        evidence_writer=lambda event: emitted.append(event) or True,
        connection_inspector=lambda _ip: {},
        lock_dir="/tmp/ai-soc-block-ip-unit-locks",
    )
    assert exit_code == 1
    types = [item["event"]["type"] for item in emitted]
    assert "EXECUTION_FAILED" in types
    assert "EXECUTION_COMPLETED" not in types


def test_nftables_inspection_detects_ordering_drift_and_apply_repairs_only_own_rule():
    fake = FakeNft()
    backend = block.NftablesBackend("nft", fake)
    req = request()
    assert backend.apply(req)["rule_present"] is True

    # A later permissive statement at the head of the dedicated chain defeats
    # the rule if ordering is not checked.
    fake.chains["input"]["rules"].insert(
        0, '  accept comment "unexpected-permissive" # handle 777'
    )
    drifted = backend.inspect(req)
    assert drifted["rule_count"] == 1
    assert drifted["rule_present"] is False
    repaired = backend.apply(req)
    assert repaired["rule_present"] is True
    assert "aisoc:{}".format(EXECUTION_ID) in fake.chains["input"]["rules"][0]
    assert "unexpected-permissive" in fake.chains["input"]["rules"][1]


def test_iptables_inspection_requires_exactly_one_hook_jump_at_position_one():
    fake = FakeIptables()
    backend = block.IptablesBackend("iptables", "ip6tables", fake, tool="iptables-nft")
    req = request(backend="iptables-nft")
    backend.apply(req)
    assert backend.inspect(req)["rule_present"] is True

    jump = fake.hooks[4]["INPUT"].pop(0)
    fake.hooks[4]["INPUT"].insert(0, "-A INPUT -j THIRD_PARTY_ALLOW")
    fake.hooks[4]["INPUT"].append(jump)
    drifted = backend.inspect(req)
    assert drifted["rule_count"] == 1
    assert drifted["rule_present"] is False
    assert drifted["hook_jump_positions"]["INPUT"] == [3]

    repaired = backend.apply(req)
    assert repaired["rule_present"] is True
    assert repaired["hook_jump_positions"]["INPUT"] == [1]
    assert fake.hooks[4]["INPUT"][1] == "-A INPUT -j THIRD_PARTY_ALLOW"


def test_backend_detection_accepts_explicit_iptables_legacy_pair():
    def fake_which(name):
        return "/usr/sbin/" + name if name in {"iptables", "ip6tables"} else None

    def fake_runner(argv, timeout):
        if argv[-1:] == ["-V"]:
            return result(stdout="iptables v1.8.9 (legacy)\n")
        return result(stdout="")

    backend = block.detect_backend("iptables-legacy", fake_runner, fake_which)
    assert isinstance(backend, block.IptablesBackend)
    assert backend.tool == "iptables-legacy"


def test_backend_detection_fails_closed_when_iptables_variant_is_unknown():
    def fake_which(name):
        return "/usr/sbin/" + name if name in {"iptables", "ip6tables"} else None

    def fake_runner(argv, timeout):
        if argv[-1:] == ["-V"]:
            return result(stdout="iptables v1.8.9\n")
        return result(stdout="")

    with pytest.raises(block.BlockIPError, match="cannot identify iptables backend"):
        block.detect_backend("iptables", fake_runner, fake_which)


def test_iptables_inspection_detects_chain_rule_ordering_drift_and_repairs_own_rule():
    fake = FakeIptables()
    backend = block.IptablesBackend("iptables", "ip6tables", fake, tool="iptables-nft")
    req = request(backend="iptables-nft")
    backend.apply(req)
    chain = fake.chains[4]["AI_SOC_BIP_IN"]
    assert chain[0].startswith("-A AI_SOC_BIP_IN -s 203.0.113.25")

    chain.insert(0, "-A AI_SOC_BIP_IN -j ACCEPT")
    drifted = backend.inspect(req)
    assert drifted["rule_count"] == 1
    assert drifted["rule_present"] is False
    assert drifted["rule_positions"] == ["chain_rule_position:2"]

    repaired = backend.apply(req)
    assert repaired["rule_present"] is True
    assert repaired["rule_positions"] == ["chain_rule_position:1"]
    assert chain[1] == "-A AI_SOC_BIP_IN -j ACCEPT"


def test_nftables_inspection_rejects_changed_base_chain_priority():
    fake = FakeNft()
    backend = block.NftablesBackend("nft", fake)
    req = request()
    backend.apply(req)

    original_chain_text = backend._chain_text

    def wrong_priority(hook):
        value = original_chain_text(hook)
        if hook == "INPUT" and value:
            return value.replace("priority filter - 100", "priority filter + 100")
        return value

    backend._chain_text = wrong_priority
    state = backend.inspect(req)
    assert state["rule_count"] == 1
    assert state["rule_present"] is False
    assert state["base_chain_validity"]["INPUT"] is False


def test_execution_lock_uses_import_safe_fallback_when_fcntl_is_unavailable(monkeypatch):
    monkeypatch.setattr(block, "fcntl", None)
    with block.execution_lock(EXECUTION_ID):
        assert EXECUTION_ID in block._THREAD_LOCKS


def test_script_refuses_non_linux_execution_even_when_message_is_valid(monkeypatch):
    import io

    payload = {
        "command": "add",
        "parameters": {"extra_args": [
            "--plan-id", "plan-1", "--action-id", "action-1",
            "--execution-id", EXECUTION_ID, "--target-ip", "203.0.113.25",
            "--direction", "inbound",
        ]},
    }
    monkeypatch.setattr(block.platform, "system", lambda: "Windows")
    monkeypatch.setattr(block.sys, "stdin", io.StringIO(json.dumps(payload)))
    assert block.main() == 2


def test_nftables_chain_header_handle_does_not_shift_rule_position():
    fake = FakeNft()
    backend = block.NftablesBackend("nft", fake)
    state = backend.apply(request())
    assert state["rule_present"] is True
    text = backend._chain_text("INPUT")
    assert "chain input { # handle 1" in text
    rule_line = fake.chains["input"]["rules"][0].strip()
    assert backend._rule_position("INPUT", rule_line) == 1

    # A real preceding ACCEPT (not the chain header) MUST shift the rule to 2.
    fake.chains["input"]["rules"].insert(
        0, '  accept comment "other-owner" # handle 777'
    )
    state = backend.inspect(request())
    assert state["rule_positions"] == ["hook_priority:-100;chain_rule_position:2"]
    assert state["rule_present"] is False
