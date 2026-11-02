#!/usr/bin/env python3
"""AI-SOC Linux Block IP Active Response (Verification v2).

This script is invoked by Wazuh using the custom command form ``!block-ip.py``.
It reads the Wazuh Active Response JSON envelope from stdin and obtains its
arguments from ``parameters.extra_args``. It never uses a shell to execute
firewall commands and only creates/removes rules carrying its own execution
marker.

Supported enforcement backends:
* Native nftables: a dedicated ``inet ai_soc_block_ip`` table with base chains
  at priority -100, so a matching DROP is evaluated before ordinary filter
  chains.
* iptables/ip6tables (iptables-nft or iptables-legacy): dedicated AI-SOC chains
  jumped from the corresponding built-in hook at position 1.

Endpoint evidence is best-effort: an evidence-writer failure is reported to
stderr but never changes the firewall action's exit status.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

try:
    import fcntl
except ImportError:  # Keep unit-test imports working on Windows; main() is Linux-only.
    fcntl = None

_THREAD_LOCKS: Dict[str, threading.RLock] = {}
_THREAD_LOCKS_GUARD = threading.RLock()

EVIDENCE_WRITER_DEFAULT = "/var/ossec/active-response/bin/ai_soc_evidence.py"
NFT_TABLE = "ai_soc_block_ip"
IPTABLES_CHAINS = {
    "INPUT": "AI_SOC_BIP_IN",
    "OUTPUT": "AI_SOC_BIP_OUT",
    "FORWARD": "AI_SOC_BIP_FWD",
}
DIRECTIONS = {
    "inbound": "INPUT",
    "input": "INPUT",
    "outbound": "OUTPUT",
    "output": "OUTPUT",
    "forward": "FORWARD",
    "both": "BOTH",
}


class BlockIPError(RuntimeError):
    """A validation, capability or firewall-operation error."""


@dataclass
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


Runner = Callable[[Sequence[str], float], CommandResult]


def run_command(argv: Sequence[str], timeout: float = 10.0) -> CommandResult:
    """Run one executable without a shell; return errors as structured data."""
    try:
        proc = subprocess.run(
            list(argv),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
        return CommandResult(proc.returncode, proc.stdout or "", proc.stderr or "")
    except FileNotFoundError as exc:
        return CommandResult(127, "", str(exc))
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return CommandResult(124, stdout, stderr or "command timed out")
    except OSError as exc:
        return CommandResult(126, "", str(exc))


def _ok(result: CommandResult, operation: str) -> str:
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "no command output").strip()
        raise BlockIPError("{} failed (rc={}): {}".format(operation, result.returncode, detail[:500]))
    return result.stdout


def normalize_direction(value: str) -> str:
    direction = DIRECTIONS.get(str(value or "").strip().lower())
    if not direction:
        raise BlockIPError("direction must be inbound, outbound, forward or both")
    return direction


def validate_target(value: str) -> ipaddress._BaseAddress:
    raw_value = str(value or "").strip()
    if "%" in raw_value:
        raise BlockIPError("zone-qualified IPv6 targets are not supported; provide a canonical IP address")
    try:
        address = ipaddress.ip_address(raw_value)
    except ValueError as exc:
        raise BlockIPError("target_ip is not a valid IPv4 or IPv6 address") from exc
    if address.is_unspecified:
        raise BlockIPError("unspecified target addresses cannot be blocked")
    if address.is_loopback:
        raise BlockIPError("loopback target addresses cannot be blocked")
    if address.is_multicast:
        raise BlockIPError("multicast target addresses cannot be blocked")
    if isinstance(address, ipaddress.IPv4Address) and address == ipaddress.IPv4Address("255.255.255.255"):
        raise BlockIPError("limited broadcast address cannot be blocked")
    return address


def _required_identifier(value: Any, name: str, max_length: int = 128) -> str:
    if not isinstance(value, str):
        raise BlockIPError("{} is required".format(name))
    result = value.strip()
    if not result or len(result) > max_length or any(ord(ch) < 32 for ch in result):
        raise BlockIPError("{} must be a non-empty string of at most {} characters".format(name, max_length))
    return result


def _parse_uuid(value: Any, name: str) -> str:
    try:
        return str(uuid.UUID(_required_identifier(value, name, 64)))
    except ValueError as exc:
        raise BlockIPError("{} must be a UUID".format(name)) from exc


def parse_wazuh_message(raw: str) -> Tuple[str, List[str]]:
    """Extract Wazuh's command and arguments from parameters.extra_args."""
    try:
        message = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BlockIPError("stdin does not contain valid Wazuh Active Response JSON") from exc
    if not isinstance(message, Mapping):
        raise BlockIPError("Wazuh Active Response message must be a JSON object")
    command = message.get("command")
    if not isinstance(command, str) or command.lower() not in {"add", "delete"}:
        raise BlockIPError("Wazuh command must be add or delete")
    parameters = message.get("parameters") or {}
    if not isinstance(parameters, Mapping):
        raise BlockIPError("Wazuh parameters must be an object")
    extra_args = parameters.get("extra_args") or []
    if not isinstance(extra_args, list) or any(not isinstance(item, str) for item in extra_args):
        raise BlockIPError("parameters.extra_args must be an array of strings")
    return command.lower(), extra_args


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI-SOC Linux Block IP Active Response")
    # Validate required values after parsing so callers receive field-specific
    # BlockIPError messages instead of argparse's process-level SystemExit.
    parser.add_argument("--plan-id")
    parser.add_argument("--action-id")
    parser.add_argument("--execution-id")
    parser.add_argument("--target-ip")
    parser.add_argument("--direction", choices=("inbound", "outbound", "forward", "both"))
    parser.add_argument("--operation", choices=("apply", "rollback", "inspect"), default=None)
    parser.add_argument(
        "--backend",
        choices=("auto", "nftables", "iptables", "iptables-nft", "iptables-legacy"),
        default="auto",
    )
    return parser


def parse_request(command: str, extra_args: Sequence[str]) -> Dict[str, Any]:
    try:
        args = build_argument_parser().parse_args(list(extra_args))
    except SystemExit as exc:
        raise BlockIPError("missing or invalid Block IP Active Response arguments") from exc
    operation = args.operation or ("rollback" if command == "delete" else "apply")
    if command == "delete" and operation != "rollback":
        raise BlockIPError("Wazuh delete command can only perform rollback")
    if operation in {"rollback", "inspect"} and args.backend not in {
        "nftables", "iptables-nft", "iptables-legacy"
    }:
        raise BlockIPError(
            "rollback/inspect require the exact persisted firewall_tool; "
            "use nftables, iptables-nft or iptables-legacy"
        )
    # The Manager API's direct custom-script call reaches the endpoint as an
    # Active Response "add" event even for a separately approved rollback.
    # --operation is the authoritative explicit operation for this script.
    plan_id = _required_identifier(args.plan_id, "plan_id")
    action_id = _required_identifier(args.action_id, "action_id")
    execution_id = _parse_uuid(args.execution_id, "execution_id")
    target_ip = validate_target(_required_identifier(args.target_ip, "target_ip"))
    if not args.direction:
        raise BlockIPError("direction is required")
    return {
        "plan_id": plan_id,
        "action_id": action_id,
        "execution_id": execution_id,
        "target_ip": str(target_ip),
        "ip_version": target_ip.version,
        "direction": normalize_direction(args.direction),
        "operation": operation,
        "backend": args.backend,
    }


def direction_hooks(direction: str) -> List[str]:
    if direction == "BOTH":
        return ["INPUT", "OUTPUT"]
    return [direction]


def match_expression(direction: str, ip_version: int) -> Tuple[str, str]:
    family = "ip" if ip_version == 4 else "ip6"
    field = "daddr" if direction == "OUTPUT" else "saddr"
    return family, field


class NftablesBackend:
    """Native nftables backend with AI-SOC-owned table and per-execution comments."""

    name = "linux_netfilter"
    tool = "nft"

    def __init__(self, binary: str = "nft", runner: Runner = run_command):
        self.binary = binary
        self.runner = runner

    def _run(self, args: Sequence[str]) -> CommandResult:
        return self.runner([self.binary, *args], 10.0)

    def _table_exists(self) -> bool:
        return self._run(["list", "table", "inet", NFT_TABLE]).returncode == 0

    def _ensure_table(self) -> None:
        if self._table_exists():
            return
        result = self._run(["add", "table", "inet", NFT_TABLE])
        if result.returncode != 0 and not self._table_exists():
            _ok(result, "create AI-SOC nftables table")

    def _chain_text(self, hook: str) -> Optional[str]:
        result = self._run(["-a", "list", "chain", "inet", NFT_TABLE, hook.lower()])
        if result.returncode != 0:
            return None
        return result.stdout

    @staticmethod
    def _chain_is_expected(hook: str, text: Optional[str]) -> bool:
        if not text:
            return False
        lowered = " ".join(text.lower().split())
        hook_ok = "hook {}".format(hook.lower()) in lowered
        priority_ok = "priority -100" in lowered or "priority filter - 100" in lowered
        policy_ok = "policy accept" in lowered
        return "type filter" in lowered and hook_ok and priority_ok and policy_ok

    def _ensure_chain(self, hook: str) -> None:
        text = self._chain_text(hook)
        if text is None:
            expression = "{ type filter hook %s priority -100; policy accept; }" % hook.lower()
            result = self._run(["add", "chain", "inet", NFT_TABLE, hook.lower(), expression])
            if result.returncode != 0 and self._chain_text(hook) is None:
                _ok(result, "create AI-SOC nftables {} hook".format(hook))
            text = self._chain_text(hook)
        if not self._chain_is_expected(hook, text):
            raise BlockIPError(
                "existing inet {} {} chain is not the expected AI-SOC base chain; refusing to alter it".format(
                    NFT_TABLE, hook.lower()
                )
            )

    def _marked_rules(self, hook: str, execution_id: str) -> List[Tuple[int, str]]:
        text = self._chain_text(hook)
        if text is None:
            return []
        marker = 'comment "aisoc:{}"'.format(execution_id)
        found = []
        for line in text.splitlines():
            if marker not in line:
                continue
            match = re.search(r"\bhandle\s+(\d+)\s*$", line)
            if not match:
                raise BlockIPError("nftables rule marker exists without a readable handle")
            found.append((int(match.group(1)), line.strip()))
        return found

    @staticmethod
    def _validate_marked_rule(request: Mapping[str, Any], hook: str, line: str) -> None:
        family, field = match_expression(hook, request["ip_version"])
        expected = "{} {} {}".format(family, field, request["target_ip"])
        if expected not in line or " drop" not in line:
            raise BlockIPError("execution marker conflicts with the requested nftables target/direction")

    def _rule_position(self, hook: str, line: str) -> int:
        text = self._chain_text(hook) or ""
        # 'nft -a list chain' assigns handles to the chain declaration AND
        # individual rules.  The chain's own '# handle N' is not a firewall
        # rule and must not count as position 1.
        rule_lines = [
            stripped
            for row in text.splitlines()
            if (stripped := row.strip())
            and re.search(r"# handle \d+\s*$", stripped)
            and not stripped.startswith(("chain ", "table "))
        ]
        try:
            return next(index for index, row in enumerate(rule_lines, 1) if row == line)
        except StopIteration:
            raise BlockIPError("cannot determine nftables execution rule position")

    def inspect(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        execution_id = request["execution_id"]
        expected_hooks = direction_hooks(request["direction"])
        found: List[Dict[str, Any]] = []
        chain_validity: Dict[str, bool] = {}
        for hook in ("INPUT", "OUTPUT", "FORWARD"):
            marked = self._marked_rules(hook, execution_id)
            if marked and hook not in expected_hooks:
                raise BlockIPError("execution marker exists in unexpected nftables {} direction".format(hook))
            if len(marked) > 1:
                raise BlockIPError("multiple nftables rules use the same execution marker in {}".format(hook))
            if not marked:
                continue
            chain_validity[hook] = self._chain_is_expected(hook, self._chain_text(hook))
            for handle, line in marked:
                self._validate_marked_rule(request, hook, line)
                position = self._rule_position(hook, line)
                found.append({"hook": hook, "handle": handle, "rule": line, "position": position})
        expected_count = len(expected_hooks)
        # A marker only proves effective ordering when it is the first rule in
        # the dedicated base chain. A permissive rule inserted above it would
        # otherwise make an existing execution appear operationally active.
        present = (
            len(found) == expected_count
            and all(item["position"] == 1 for item in found)
            and all(chain_validity.get(hook, False) for hook in expected_hooks)
        )
        packets: List[int] = []
        byte_counts: List[int] = []
        for item in found:
            packet_match = re.search(r"counter packets (\d+) bytes (\d+)", item["rule"])
            if packet_match:
                packets.append(int(packet_match.group(1)))
                byte_counts.append(int(packet_match.group(2)))
        return {
            "rule_present": present,
            "rule_count": len(found),
            "expected_rule_count": expected_count,
            "rule_handles": [item["handle"] for item in found],
            "rule_positions": [
                "hook_priority:-100;chain_rule_position:{}".format(item["position"])
                for item in found
            ],
            "base_chain_validity": chain_validity,
            "packet_count": sum(packets) if len(packets) == len(found) else None,
            "byte_count": sum(byte_counts) if len(byte_counts) == len(found) else None,
            "firewall_backend": self.name,
            "firewall_tool": self.tool,
            "target_ip": request["target_ip"],
            "ip_version": request["ip_version"],
            "direction": request["direction"],
        }

    def apply(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        # Validate that this execution marker is not already tied to a different
        # hook/target before creating or changing any chain.
        self.inspect(request)
        self._ensure_table()
        execution_id = request["execution_id"]
        marker = "aisoc:{}".format(execution_id)
        # nft parses argv as a CLI expression; unlike iptables, a comment
        # containing ':' must be quoted in the nft expression itself.
        # subprocess.run(argv) does not add the shell's string quoting.
        nft_comment = '"{}"'.format(marker)
        address = request["target_ip"]
        ip_version = request["ip_version"]
        for hook in direction_hooks(request["direction"]):
            self._ensure_chain(hook)
            existing = self._marked_rules(hook, execution_id)
            family, field = match_expression(hook, ip_version)
            if existing:
                handle, line = existing[0]
                self._validate_marked_rule(request, hook, line)
                # Repair ordering drift by replacing only this execution's own
                # marked rule; a later ACCEPT in the AI-SOC chain must not
                # bypass the desired DROP.
                if self._rule_position(hook, line) == 1:
                    continue
                removed = self._run(
                    ["delete", "rule", "inet", NFT_TABLE, hook.lower(), "handle", str(handle)]
                )
                _ok(removed, "reposition nftables execution rule")
            result = self._run(
                [
                    "insert", "rule", "inet", NFT_TABLE, hook.lower(),
                    family, field, address, "counter", "drop", "comment", nft_comment,
                ]
            )
            _ok(result, "install nftables {} rule".format(hook))
        state = self.inspect(request)
        if not state["rule_present"]:
            raise BlockIPError("nftables add returned success but the execution rule is not present")
        return state

    def remove(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        self.inspect(request)  # fail closed on a marker/target/direction conflict
        execution_id = request["execution_id"]
        # Rollback only markers owned by this execution; the shared table and
        # base chains remain intact for other executions.
        for hook in direction_hooks(request["direction"]):
            for handle, line in self._marked_rules(hook, execution_id):
                self._validate_marked_rule(request, hook, line)
                result = self._run(
                    ["delete", "rule", "inet", NFT_TABLE, hook.lower(), "handle", str(handle)]
                )
                _ok(result, "remove nftables execution rule")
        return self.inspect(request)


class IptablesBackend:
    """iptables/ip6tables fallback using dedicated chains and marker comments."""

    name = "linux_netfilter"

    def __init__(
        self,
        ipv4_binary: str = "iptables",
        ipv6_binary: str = "ip6tables",
        runner: Runner = run_command,
        tool: str = "iptables-legacy",
    ):
        self.ipv4_binary = ipv4_binary
        self.ipv6_binary = ipv6_binary
        self.runner = runner
        self.tool = tool

    def _binary(self, ip_version: int) -> str:
        return self.ipv4_binary if ip_version == 4 else self.ipv6_binary

    def _run(self, ip_version: int, args: Sequence[str]) -> CommandResult:
        return self.runner([self._binary(ip_version), "-w", "5", *args], 10.0)

    def _ensure_chain(self, ip_version: int, hook: str) -> None:
        binary = self._binary(ip_version)
        chain = IPTABLES_CHAINS[hook]
        listed = self._run(ip_version, ["-S", chain])
        if listed.returncode != 0:
            created = self._run(ip_version, ["-N", chain])
            if created.returncode != 0 and self._run(ip_version, ["-S", chain]).returncode != 0:
                _ok(created, "create AI-SOC iptables chain {}".format(chain))
        # A single jump at position 1 makes this policy precede existing ACCEPTs.
        # An older AI-SOC jump that drifted below another rule is moved back to
        # position 1 by deleting only that exact jump and reinserting it.
        hook_rules = self._run(ip_version, ["-S", hook])
        _ok(hook_rules, "inspect iptables {} hook".format(hook))
        jump = "-A {} -j {}".format(hook, chain)
        action_lines = [line.strip() for line in hook_rules.stdout.splitlines() if line.strip().startswith("-A ")]
        if len(action_lines) == 1 and action_lines[0] == jump:
            return
        # Remove only duplicate/drifted jumps to our chain, then insert exactly
        # one jump at the first position. No third-party hook rule is touched.
        while self._run(ip_version, ["-C", hook, "-j", chain]).returncode == 0:
            removed = self._run(ip_version, ["-D", hook, "-j", chain])
            _ok(removed, "normalize AI-SOC {} jump".format(hook))
        inserted = self._run(ip_version, ["-I", hook, "1", "-j", chain])
        _ok(inserted, "insert AI-SOC jump at {} position 1".format(hook))

    def _rule_args(self, request: Mapping[str, Any], hook: str) -> List[str]:
        selector = "-d" if hook == "OUTPUT" else "-s"
        return [
            selector, request["target_ip"],
            "-m", "comment", "--comment", "aisoc:{}".format(request["execution_id"]),
            "-j", "DROP",
        ]

    def _chain_rule_positions(self, request: Mapping[str, Any], hook: str) -> List[Tuple[int, str]]:
        chain = IPTABLES_CHAINS[hook]
        listed = self._run(request["ip_version"], ["-S", chain])
        if listed.returncode != 0:
            return []
        action_lines = [
            line.strip() for line in listed.stdout.splitlines()
            if line.strip().startswith("-A ")
        ]
        marker = "aisoc:{}".format(request["execution_id"])
        return [
            (index, line) for index, line in enumerate(action_lines, 1)
            if marker in line
        ]

    def _marked_rule_lines(self, request: Mapping[str, Any], hook: str) -> List[str]:
        return [line for _, line in self._chain_rule_positions(request, hook)]

    def _validate_marked_rule(self, request: Mapping[str, Any], hook: str, line: str) -> None:
        selector = "-d" if hook == "OUTPUT" else "-s"
        target = request["target_ip"]
        prefix = "/32" if request["ip_version"] == 4 else "/128"
        target_match = (
            "{} {}".format(selector, target) in line
            or "{} {}{}".format(selector, target, prefix) in line
        )
        marker = "aisoc:{}".format(request["execution_id"])
        if not (target_match and marker in line and "-j DROP" in line):
            raise BlockIPError("execution marker conflicts with requested iptables target/direction")

    def _rule_exists(self, request: Mapping[str, Any], hook: str) -> bool:
        marked = self._marked_rule_lines(request, hook)
        for line in marked:
            self._validate_marked_rule(request, hook, line)
        if len(marked) > 1:
            raise BlockIPError("multiple iptables rules use the same execution marker")
        result = self._run(
            request["ip_version"],
            ["-C", IPTABLES_CHAINS[hook], *self._rule_args(request, hook)],
        )
        return result.returncode == 0

    def _hook_jump_positions(self, ip_version: int, hook: str) -> List[int]:
        chain = IPTABLES_CHAINS[hook]
        result = self._run(ip_version, ["-S", hook])
        _ok(result, "inspect iptables {} hook".format(hook))
        expected = "-A {} -j {}".format(hook, chain)
        action_lines = [
            line.strip() for line in result.stdout.splitlines()
            if line.strip().startswith("-A ")
        ]
        return [index for index, line in enumerate(action_lines, 1) if line == expected]

    def inspect(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        hooks = direction_hooks(request["direction"])
        for hook in ("INPUT", "OUTPUT", "FORWARD"):
            marked = self._marked_rule_lines(request, hook)
            if marked and hook not in hooks:
                raise BlockIPError("execution marker exists in unexpected iptables {} direction".format(hook))
            for line in marked:
                self._validate_marked_rule(request, hook, line)
            if len(marked) > 1:
                raise BlockIPError("multiple iptables rules use the same execution marker")
        chain_positions = {hook: self._chain_rule_positions(request, hook) for hook in hooks}
        found_hooks = [hook for hook in hooks if self._rule_exists(request, hook)]
        jump_positions = {hook: self._hook_jump_positions(request["ip_version"], hook) for hook in hooks}
        expected = len(hooks)
        effective = (
            len(found_hooks) == expected
            and all(
                len(chain_positions[hook]) == 1 and chain_positions[hook][0][0] == 1
                for hook in hooks
            )
            and all(jump_positions[hook] == [1] for hook in hooks)
        )
        counters = self._read_counters(request)
        return {
            "rule_present": effective,
            "rule_count": len(found_hooks),
            "expected_rule_count": expected,
            "rule_handles": [],
            "rule_positions": [
                "chain_rule_position:{}".format(chain_positions[hook][0][0])
                for hook in found_hooks if chain_positions[hook]
            ],
            "hook_jump_count": sum(len(positions) for positions in jump_positions.values()),
            "hook_jump_positions": {
                hook: positions for hook, positions in jump_positions.items()
            },
            "packet_count": counters[0],
            "byte_count": counters[1],
            "firewall_backend": self.name,
            "firewall_tool": self.tool,
            "target_ip": request["target_ip"],
            "ip_version": request["ip_version"],
            "direction": request["direction"],
        }

    def _read_counters(self, request: Mapping[str, Any]) -> Tuple[Optional[int], Optional[int]]:
        save_binary = shutil.which("ip6tables-save" if request["ip_version"] == 6 else "iptables-save")
        if not save_binary:
            return None, None
        result = self.runner([save_binary, "-c", "-t", "filter"], 10.0)
        if result.returncode != 0:
            return None, None
        marker = 'comment "aisoc:{}"'.format(request["execution_id"])
        totals = [0, 0]
        seen = 0
        for line in result.stdout.splitlines():
            if marker not in line:
                continue
            match = re.match(r"\[(\d+):(\d+)\]", line)
            if match:
                totals[0] += int(match.group(1))
                totals[1] += int(match.group(2))
                seen += 1
        return (totals[0], totals[1]) if seen else (None, None)

    def apply(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        self.inspect(request)  # reject execution-marker collisions before mutation
        ip_version = request["ip_version"]
        for hook in direction_hooks(request["direction"]):
            self._ensure_chain(ip_version, hook)
            marked = self._chain_rule_positions(request, hook)
            if marked and marked[0][0] > 1:
                # Reposition only this execution's exact rule inside the
                # dedicated chain. Do not flush or reorder other owners' rules.
                removed = self._run(
                    ip_version,
                    ["-D", IPTABLES_CHAINS[hook], *self._rule_args(request, hook)],
                )
                _ok(removed, "reposition iptables execution rule")
                marked = []
            if not marked:
                result = self._run(
                    ip_version,
                    ["-I", IPTABLES_CHAINS[hook], "1", *self._rule_args(request, hook)],
                )
                _ok(result, "install iptables {} rule".format(hook))
        state = self.inspect(request)
        if not state["rule_present"]:
            raise BlockIPError("iptables add returned success but the execution rule is not present")
        return state

    def remove(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        self.inspect(request)  # reject target/direction conflicts before rollback
        ip_version = request["ip_version"]
        for hook in direction_hooks(request["direction"]):
            chain = IPTABLES_CHAINS[hook]
            for line in self._marked_rule_lines(request, hook):
                self._validate_marked_rule(request, hook, line)
            # Delete exact marker+target matches only; leave all other entries,
            # jumps and the AI-SOC shared chains intact.
            while self._run(ip_version, ["-C", chain, *self._rule_args(request, hook)]).returncode == 0:
                result = self._run(
                    ip_version,
                    ["-D", chain, *self._rule_args(request, hook)],
                )
                _ok(result, "remove iptables execution rule")
        return self.inspect(request)


def detect_backend(
    requested: str = "auto",
    runner: Runner = run_command,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> Any:
    """Select native nftables first, otherwise an IPv4+IPv6 iptables pair."""
    if requested in {"auto", "nftables"}:
        nft = which("nft")
        if nft:
            probe = runner([nft, "list", "ruleset"], 10.0)
            if probe.returncode == 0:
                return NftablesBackend(nft, runner)
        if requested == "nftables":
            raise BlockIPError("native nftables requested but nft is unavailable or unsupported")

    if requested in {"auto", "iptables", "iptables-nft", "iptables-legacy"}:
        ipt4, ipt6 = which("iptables"), which("ip6tables")
        if ipt4 and ipt6:
            version = runner([ipt4, "-V"], 5.0)
            version6 = runner([ipt6, "-V"], 5.0)
            probe4 = runner([ipt4, "-w", "5", "-S"], 5.0)
            probe6 = runner([ipt6, "-w", "5", "-S"], 5.0)
            if version.returncode == 0 and version6.returncode == 0 and probe4.returncode == 0 and probe6.returncode == 0:
                version_text4 = (version.stdout + version.stderr).lower()
                version_text6 = (version6.stdout + version6.stderr).lower()
                def identify_tool(version_text: str, binary_name: str) -> str:
                    if "nf_tables" in version_text:
                        return "iptables-nft"
                    if "legacy" in version_text:
                        return "iptables-legacy"
                    raise BlockIPError(
                        "cannot identify {} backend from -V output; expected nf_tables or legacy".format(binary_name)
                    )

                tool4 = identify_tool(version_text4, "iptables")
                tool6 = identify_tool(version_text6, "ip6tables")
                if tool4 != tool6:
                    raise BlockIPError("IPv4 and IPv6 iptables commands use different backends; refusing mixed-family enforcement")
                if requested in {"iptables-nft", "iptables-legacy"} and requested != tool4:
                    raise BlockIPError("persisted firewall_tool {} is unavailable; detected {}".format(requested, tool4))
                return IptablesBackend(ipt4, ipt6, runner, tool4)
        if requested != "auto":
            raise BlockIPError("requested iptables backend requires working IPv4 and IPv6 iptables tools")

    raise BlockIPError("no supported Linux firewall backend found (need nft or iptables+ip6tables)")


def _line_mentions_ip(line: str, address: ipaddress._BaseAddress) -> bool:
    """Compare parsed endpoint addresses, avoiding substring/prefix matches."""
    candidates = re.findall(r"(?:src|dst)=([0-9A-Fa-f:.]+)", line)
    candidates.extend(re.findall(r"\[([0-9A-Fa-f:.]+)\]", line))
    candidates.extend(re.findall(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])", line))
    for candidate in candidates:
        try:
            if ipaddress.ip_address(candidate) == address:
                return True
        except ValueError:
            continue
    return False


def inspect_existing_connections(target_ip: str, runner: Runner = run_command) -> Dict[str, Any]:
    """Read-only snapshot of conntrack entries and established sockets.

    The script deliberately does not run conntrack -D or ss -K implicitly.
    Blocking packets and terminating application sockets are separate actions;
    endpoint operators must explicitly design and authorize any socket teardown.
    """
    address = ipaddress.ip_address(target_ip)
    conntrack = shutil.which("conntrack")
    ss = shutil.which("ss")
    result: Dict[str, Any] = {
        "privileged": hasattr(os, "geteuid") and os.geteuid() == 0,
        "conntrack_available": bool(conntrack),
        "firewalld_active": False,
        "conntrack_delete_available": False,
        "conntrack_entries": None,
        "ss_available": bool(ss),
        "ss_kill_available": False,
        "established_socket_count": None,
        "existing_connections_terminated": False,
    }
    firewall_cmd = shutil.which("firewall-cmd")
    if firewall_cmd:
        firewalld_state = runner([firewall_cmd, "--state"], 5.0)
        result["firewalld_active"] = (
            firewalld_state.returncode == 0
            and firewalld_state.stdout.strip().lower() == "running"
        )
    if conntrack:
        help_result = runner([conntrack, "-h"], 5.0)
        help_text = help_result.stdout + help_result.stderr
        result["conntrack_delete_available"] = "-D" in help_text or "--delete" in help_text
        listing = runner([conntrack, "-L", "-f", "ipv4" if address.version == 4 else "ipv6"], 8.0)
        if listing.returncode == 0:
            result["conntrack_entries"] = sum(
                1 for line in listing.stdout.splitlines() if _line_mentions_ip(line, address)
            )
    if ss:
        help_result = runner([ss, "-h"], 5.0)
        result["ss_kill_available"] = "-K" in (help_result.stdout + help_result.stderr)
        listing = runner([ss, "-Htn", "state", "established"], 8.0)
        if listing.returncode == 0:
            result["established_socket_count"] = sum(
                1 for line in listing.stdout.splitlines() if _line_mentions_ip(line, address)
            )
    return result


def make_evidence_event(
    request: Mapping[str, Any],
    event_type: str,
    step: str,
    outcome: str,
    exit_code: Optional[int],
    state: Optional[Mapping[str, Any]],
    pre_state: Optional[Mapping[str, Any]],
    post_state: Optional[Mapping[str, Any]],
    backend: Optional[Any] = None,
) -> Dict[str, Any]:
    backend_name = getattr(backend, "name", None) or (state or {}).get("firewall_backend")
    tool_name = getattr(backend, "tool", None) or (state or {}).get("firewall_tool")
    action = {
        "type": "block_ip",
        "target": request["target_ip"],
        "direction": request["direction"],
        "ip_version": request["ip_version"],
    }
    if backend_name:
        action["firewall_backend"] = backend_name
    if tool_name:
        action["firewall_tool"] = tool_name
    if state:
        for key in ("rule_count", "expected_rule_count", "rule_handles", "rule_positions", "packet_count", "byte_count"):
            value = state.get(key)
            if value is not None:
                action[key] = value
    if isinstance(state, Mapping):
        for key in (
            "privileged", "firewalld_active", "conntrack_available", "conntrack_delete_available",
            "conntrack_entries", "ss_available", "ss_kill_available",
            "established_socket_count", "existing_connections_terminated",
        ):
            if key in state and state[key] is not None:
                action[key] = state[key]
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return {
        "schema_version": "1.0",
        "event_id": str(uuid.uuid4()),
        "plan_id": request["plan_id"],
        "action_id": request["action_id"],
        "execution_id": request["execution_id"],
        "host": {"observed_at": now},
        "action": action,
        "event": {
            "type": event_type,
            "step": step,
            "outcome": outcome,
            "exit_code": exit_code,
        },
        "state": dict(state) if isinstance(state, Mapping) else None,
        "pre_state": dict(pre_state) if isinstance(pre_state, Mapping) else None,
        "post_state": dict(post_state) if isinstance(post_state, Mapping) else None,
    }


def emit_evidence(event: Mapping[str, Any], writer_path: Optional[str] = None) -> bool:
    """Best-effort call to Chat 4's writer; never masks the action result."""
    path = writer_path or os.environ.get("AI_SOC_EVIDENCE_WRITER", EVIDENCE_WRITER_DEFAULT)
    if not os.path.isfile(path):
        print("AI-SOC evidence writer unavailable at {}; evidence not written".format(path), file=sys.stderr)
        return False
    try:
        proc = subprocess.run(
            [path],
            input=json.dumps(event, separators=(",", ":"), ensure_ascii=False, allow_nan=False),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=8.0,
            check=False,
        )
    except Exception as exc:
        print("AI-SOC evidence writer failed: {}".format(exc), file=sys.stderr)
        return False
    if proc.returncode != 0:
        print("AI-SOC evidence writer rejected event: {}".format((proc.stderr or proc.stdout or "unknown")[:400]), file=sys.stderr)
        return False
    return True


def _try_emit_evidence(
    writer: Callable[[Mapping[str, Any]], bool], event: Mapping[str, Any]
) -> bool:
    """Evidence failures must never override the firewall action result."""
    try:
        return bool(writer(event))
    except Exception as exc:
        print("AI-SOC evidence writer raised an error: {}".format(exc), file=sys.stderr)
        return False


def require_root() -> None:
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise BlockIPError("Block IP Active Response must run as root")


@contextmanager
def execution_lock(execution_id: str, lock_dir: Optional[str] = None):
    """Serialize apply/rollback/inspect for one execution across AR processes."""
    if fcntl is None:
        # The script refuses to execute on non-Linux hosts. This in-process
        # fallback exists solely so Windows CI/dev can import and unit-test
        # backend logic without importing a POSIX-only module.
        with _THREAD_LOCKS_GUARD:
            lock = _THREAD_LOCKS.setdefault(execution_id, threading.RLock())
        lock.acquire()
        try:
            yield
        finally:
            lock.release()
        return

    directory = Path(lock_dir or "/run/lock")
    directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    lock_path = directory / "ai-soc-block-ip-{}.lock".format(execution_id)
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _execute_request_locked(
    request: Mapping[str, Any],
    backend: Any,
    operation: str,
    evidence_writer: Callable[[Mapping[str, Any]], bool],
    connection_inspector: Callable[[str], Dict[str, Any]],
) -> int:
    """Apply, inspect or rollback one execution ID and emit endpoint evidence."""
    pre_state = backend.inspect(request)
    try:
        pre_connections = connection_inspector(request["target_ip"])
    except Exception as exc:
        pre_connections = {
            "inspection_error": str(exc)[:400],
            "conntrack_available": False,
            "ss_available": False,
            "existing_connections_terminated": False,
        }
    pre_state = {**pre_state, "existing_connections": pre_connections}

    if operation == "apply":
        _try_emit_evidence(evidence_writer, make_evidence_event(
            request, "EXECUTION_STARTED", "install_rule", "started", None,
            pre_state, pre_state, None, backend,
        ))
        try:
            post_firewall = backend.apply(request)
            try:
                post_connections = connection_inspector(request["target_ip"])
            except Exception as conn_exc:
                post_connections = {"inspection_error": str(conn_exc)[:400]}
            post_state = {**post_firewall, "existing_connections": post_connections}
            if not post_firewall.get("rule_present"):
                raise BlockIPError("firewall state does not contain the expected execution rule")
        except Exception as exc:
            cleanup_error = None
            try:
                # BOTH may fail after the first hook was installed. Remove only
                # this execution marker so a failed partial action is not left
                # enforcing an incomplete policy.
                post_firewall = backend.remove(request)
                post_state = {
                    **post_firewall,
                    "partial_apply_cleanup_attempted": True,
                    "partial_apply_cleanup_succeeded": not post_firewall.get("rule_present"),
                }
                try:
                    post_state["existing_connections"] = connection_inspector(request["target_ip"])
                except Exception as conn_exc:
                    post_state["existing_connections"] = {"inspection_error": str(conn_exc)[:400]}
            except Exception as cleanup_exc:
                cleanup_error = str(cleanup_exc)[:400]
                try:
                    post_firewall = backend.inspect(request)
                    post_state = {
                        **post_firewall,
                        "partial_apply_cleanup_attempted": True,
                        "partial_apply_cleanup_succeeded": False,
                        "partial_apply_cleanup_error": cleanup_error,
                    }
                except Exception:
                    post_state = {
                        "partial_apply_cleanup_attempted": True,
                        "partial_apply_cleanup_succeeded": False,
                        "partial_apply_cleanup_error": cleanup_error,
                    }
            _try_emit_evidence(evidence_writer, make_evidence_event(
                request, "EXECUTION_FAILED", "install_rule", "failed", 1,
                post_state, pre_state, post_state, backend,
            ))
            print("AI-SOC Block IP failed: {}".format(exc), file=sys.stderr)
            return 1
        _try_emit_evidence(evidence_writer, make_evidence_event(
            request, "EXECUTION_COMPLETED", "install_rule", "success", 0,
            post_state, pre_state, post_state, backend,
        ))
        _try_emit_evidence(evidence_writer, make_evidence_event(
            request, "STATE_SNAPSHOT", "post_install_inspection", "observed", 0,
            post_state, pre_state, post_state, backend,
        ))
        print(json.dumps({"success": True, "execution_id": request["execution_id"], "post_state": post_state}, sort_keys=True))
        return 0

    if operation == "rollback":
        _try_emit_evidence(evidence_writer, make_evidence_event(
            request, "ROLLBACK_STARTED", "remove_execution_rule", "started", None,
            pre_state, pre_state, None, backend,
        ))
        try:
            post_firewall = backend.remove(request)
            try:
                post_connections = connection_inspector(request["target_ip"])
            except Exception as conn_exc:
                post_connections = {"inspection_error": str(conn_exc)[:400]}
            post_state = {**post_firewall, "existing_connections": post_connections}
            if post_firewall.get("rule_present"):
                raise BlockIPError("execution-specific firewall rule remains after rollback")
        except Exception as exc:
            try:
                post_firewall = backend.inspect(request)
                post_state = {**post_firewall, "existing_connections": {"inspection_error": "connection snapshot unavailable"}}
                try:
                    post_state["existing_connections"] = connection_inspector(request["target_ip"])
                except Exception as conn_exc:
                    post_state["existing_connections"] = {"inspection_error": str(conn_exc)[:400]}
            except Exception:
                post_state = None
            _try_emit_evidence(evidence_writer, make_evidence_event(
                request, "ROLLBACK_FAILED", "remove_execution_rule", "failed", 1,
                post_state, pre_state, post_state, backend,
            ))
            print("AI-SOC Block IP rollback failed: {}".format(exc), file=sys.stderr)
            return 1
        _try_emit_evidence(evidence_writer, make_evidence_event(
            request, "ROLLBACK_COMPLETED", "remove_execution_rule", "success", 0,
            post_state, pre_state, post_state, backend,
        ))
        _try_emit_evidence(evidence_writer, make_evidence_event(
            request, "STATE_SNAPSHOT", "post_rollback_inspection", "observed", 0,
            post_state, pre_state, post_state, backend,
        ))
        print(json.dumps({"success": True, "execution_id": request["execution_id"], "post_state": post_state}, sort_keys=True))
        return 0

    if operation == "inspect":
        state = {**backend.inspect(request), "existing_connections": pre_connections}
        _try_emit_evidence(evidence_writer, make_evidence_event(
            request, "STATE_SNAPSHOT", "independent_endpoint_inspection", "observed", 0,
            state, pre_state, state, backend,
        ))
        print(json.dumps({"success": bool(state.get("rule_present")), "execution_id": request["execution_id"], "state": state}, sort_keys=True))
        return 0

    raise BlockIPError("unsupported operation {}".format(operation))


def execute_request(
    request: Mapping[str, Any],
    backend: Any,
    operation: str,
    evidence_writer: Callable[[Mapping[str, Any]], bool] = emit_evidence,
    connection_inspector: Callable[[str], Dict[str, Any]] = inspect_existing_connections,
    lock_dir: Optional[str] = None,
) -> int:
    with execution_lock(request["execution_id"], lock_dir):
        return _execute_request_locked(
            request, backend, operation, evidence_writer, connection_inspector
        )


def main(argv: Optional[Sequence[str]] = None) -> int:
    del argv  # Wazuh supplies action arguments through stdin, not shell argv.
    try:
        raw = sys.stdin.read(128 * 1024)
        if len(raw.encode("utf-8")) > 128 * 1024:
            raise BlockIPError("Wazuh Active Response message exceeds 128 KiB")
        command, extra_args = parse_wazuh_message(raw)
        request = parse_request(command, extra_args)
        if platform.system() != "Linux":
            raise BlockIPError("this Active Response implementation supports Linux only")
        require_root()
        backend = detect_backend(request["backend"])
        return execute_request(request, backend, request["operation"])
    except BlockIPError as exc:
        print("AI-SOC Block IP rejected request: {}".format(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print("AI-SOC Block IP unexpected error: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
