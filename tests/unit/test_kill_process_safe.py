"""Non-destructive tests for opt-in, allowlisted Linux Kill Process.

All signal syscalls are mocked. No test can signal a real process.
"""
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import signal
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "active-response" / "kill-process-safe.py"
SPEC = importlib.util.spec_from_file_location("ai_soc_kill_process_safe", SCRIPT)
kill = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = kill
SPEC.loader.exec_module(kill)


def payload(name=None, *, alias=False, command="add"):
    data = {}
    if name is not None:
        data["processname" if alias else "process_name"] = name
    return json.dumps({"command": command, "parameters": {"alert": {"data": data}}})


@pytest.mark.parametrize("name", [
    "-TERM", "python3", "wazuh-agentd", "systemd", "kworker01", "foo.*",
    "foo[1]", "a" * 16, "x y", "a\nb", "", None, 500,
])
def test_critical_or_invalid_names_fail_closed(name):
    with pytest.raises(kill.KillError):
        kill.checked_name(name)


def test_policy_default_deny_and_exact_allowlist():
    with pytest.raises(kill.KillError, match="EMPTY_ALLOWLIST"):
        kill.validate_policy_document({"allowed_process_names": []})
    with pytest.raises(kill.KillError):
        kill.validate_policy_document({"allowed_process_names": ["aisockill2"], "allow_everything": True})
    with pytest.raises(kill.KillError):
        kill.validate_policy_document({"allowed_process_names": ["systemd"]})
    with pytest.raises(kill.KillError):
        kill.validate_policy_document({"allowed_process_names": ["aisockill2", "aisockill2"]})
    assert kill.validate_policy_document({"allowed_process_names": ["aisockill2"]}) == {"aisockill2"}


def test_parse_existing_wazuh_adapter_contract():
    assert kill.parse_wazuh_request(payload("aisockill2")) == "aisockill2"
    assert kill.parse_wazuh_request(payload("aisockill2", alias=True)) == "aisockill2"
    assert kill.parse_wazuh_request(payload(command="delete")) is None
    with pytest.raises(kill.KillError, match="CONFLICTING_PROCESS_NAMES"):
        kill.parse_wazuh_request(json.dumps({
            "command": "add", "parameters": {"alert": {
                "data": {"process_name": "aisockill2", "processname": "other"}
            }}
        }))
    for raw in ("{}", "[]", "{not-json}", "x" * (kill.MAX_INPUT_BYTES + 1)):
        with pytest.raises(kill.KillError):
            kill.parse_wazuh_request(raw)


def _create_process(proc, pid, name, *, start=123456, state="S"):
    item = proc / str(pid)
    item.mkdir(exist_ok=True, parents=True)
    (item / "comm").write_text(name + "\n")
    # /proc/PID/stat fields 3..22: state followed by 18 dummies then starttime.
    fields = [state] + ["0"] * 18 + [str(start)] + ["0"] * 3
    (item / "stat").write_text(f"{pid} ({name}) " + " ".join(fields) + "\n")
    return item


def test_proc_scan_selects_one_literal_name_and_reads_start_ticks(tmp_path, monkeypatch):
    proc = tmp_path / "proc"
    proc.mkdir()
    _create_process(proc, 412451, "aisockill2", start=321)
    _create_process(proc, 412452, "aisockill", start=654)
    monkeypatch.setattr(kill, "PROC_ROOT", proc)
    assert kill.locate_exactly_one("aisockill2") == (412451, 321)
    with pytest.raises(kill.KillError, match="PROCESS_NOT_FOUND"):
        kill.locate_exactly_one("aisockill3")
    _create_process(proc, 412453, "aisockill2", start=111)
    with pytest.raises(kill.KillError, match="AMBIGUOUS_PROCESS_NAME"):
        kill.locate_exactly_one("aisockill2")


def test_pidfd_signal_and_post_term_verification_are_required(monkeypatch):
    sent = []
    handles = []
    monkeypatch.setattr(kill.os, "pidfd_open", lambda pid, flags: handles.append(os.open(os.devnull, os.O_RDONLY)) or handles[-1])
    def fake_signal(fd, sig, *_args):
        assert fd == handles[-1]
        assert sig == signal.SIGTERM
        sent.append(fd)
    monkeypatch.setattr(kill.signal, "pidfd_send_signal", fake_signal)
    observations = iter([("aisockill2", 321, "S"), ("aisockill2", 321, "Z")])
    monkeypatch.setattr(kill, "process_snapshot", lambda _pid: next(observations))
    monkeypatch.setattr(kill, "audit", lambda *args: None)
    assert kill.terminate_verified(412451, "aisockill2", 321) == "TERMINATED_VERIFIED"
    assert len(sent) == 1


def test_changed_process_identity_is_never_signaled(monkeypatch):
    signaled = []
    monkeypatch.setattr(kill.os, "pidfd_open", lambda _pid, _flags: os.open(os.devnull, os.O_RDONLY))
    monkeypatch.setattr(kill.signal, "pidfd_send_signal", lambda *args: signaled.append(args))
    monkeypatch.setattr(kill, "process_snapshot", lambda _pid: ("other", 321, "S"))
    with pytest.raises(kill.KillError, match="PROCESS_IDENTITY_CHANGED"):
        kill.terminate_verified(412451, "aisockill2", 321)
    assert signaled == []


def test_no_pidfd_support_fails_closed(monkeypatch):
    monkeypatch.delattr(kill.signal, "pidfd_send_signal", raising=False)
    with pytest.raises(kill.KillError, match="PIDFD_UNSUPPORTED"):
        kill.terminate_verified(412451, "aisockill2", 321)


def test_missing_permission_or_unverified_termination_does_not_claim_success(monkeypatch):
    monkeypatch.setattr(kill.os, "pidfd_open", lambda _pid, _flags: os.open(os.devnull, os.O_RDONLY))
    monkeypatch.setattr(kill.signal, "pidfd_send_signal", lambda *_args: None)
    monkeypatch.setattr(kill, "process_snapshot", lambda _pid: ("aisockill2", 321, "S"))
    monkeypatch.setattr(kill, "audit", lambda *args: None)
    times = iter([100.0, 104.0])
    monkeypatch.setattr(kill.time, "monotonic", lambda: next(times))
    with pytest.raises(kill.KillError, match="TERMINATION_UNVERIFIED"):
        kill.terminate_verified(412451, "aisockill2", 321)


def test_main_has_no_signal_without_approved_policy(tmp_path, monkeypatch):
    monkeypatch.setattr(kill.LOG_PATH.__class__, "__str__", Path.__str__, raising=False) if False else None
    monkeypatch.setattr(kill, "LOG_PATH", tmp_path / "kill-process.log")
    monkeypatch.setattr(kill.os, "geteuid", lambda: 0)
    monkeypatch.setattr(kill, "load_policy", lambda: frozenset({"safeother"}))
    monkeypatch.setattr(kill.sys, "stdin", io.StringIO(payload("aisockill2") + "\n"))
    signal_calls = []
    monkeypatch.setattr(kill.signal, "pidfd_send_signal", lambda *args: signal_calls.append(args), raising=False)
    assert kill.main([]) == 1
    assert signal_calls == []
    assert "NOT_ALLOWLISTED" in kill.LOG_PATH.read_text()


def test_main_fake_process_sends_term_once_and_audits_verified(tmp_path, monkeypatch):
    proc = tmp_path / "proc"
    proc.mkdir()
    _create_process(proc, 412451, "aisockill2", start=321)
    monkeypatch.setattr(kill, "PROC_ROOT", proc)
    monkeypatch.setattr(kill, "LOG_PATH", tmp_path / "kill-process.log")
    monkeypatch.setattr(kill.os, "geteuid", lambda: 0)
    monkeypatch.setattr(kill, "load_policy", lambda: frozenset({"aisockill2"}))
    monkeypatch.setattr(kill.sys, "stdin", io.StringIO(payload("aisockill2") + "\n"))
    monkeypatch.setattr(kill.os, "pidfd_open", lambda _pid, _flags: os.open(os.devnull, os.O_RDONLY))
    def fake_sig(*_args):
        _create_process(proc, 412451, "aisockill2", start=321, state="Z")
    monkeypatch.setattr(kill.signal, "pidfd_send_signal", fake_sig)
    assert kill.main([]) == 0
    records = [json.loads(line) for line in kill.LOG_PATH.read_text().splitlines()]
    assert [e["status"] for e in records] == [
        "APPROVED", "SIGTERM_SENT", "TERMINATED_VERIFIED"
    ]
    assert all(e["pid"] == 412451 for e in records)


def test_kill_process_must_be_explicit_opt_in():
    installer = (SCRIPT.parents[1] / "scripts" / "install.sh").read_text()
    assert "kill-process-safe.py" in installer
    assert "--with-kill-process" in installer
    assert "kill-process0" in installer
