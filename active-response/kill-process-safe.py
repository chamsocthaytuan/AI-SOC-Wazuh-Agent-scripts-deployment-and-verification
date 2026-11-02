#!/usr/bin/env python3
"""Fail-closed Linux Wazuh Active Response process termination.

This program is intentionally separate from legacy kill-process0.
No signal is sent without a root-owned allowlist and unambiguous process identity.
The Wazuh Manager continues to dispatch command "!kill-process0"; the explicit
installer option places THIS script at the Agent's kill-process0 path.
"""
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time

POLICY_PATH = Path("/var/ossec/etc/ai-soc/kill-process-policy.json")
LOG_PATH = Path("/var/ossec/logs/kill-process.log")
PROC_ROOT = Path("/proc")
MAX_INPUT_BYTES = 16384
MAX_POLICY_BYTES = 4096
TERMINATION_TIMEOUT_SECONDS = 3.0
VALID_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}\Z", re.ASCII)
PROTECTED_NAMES = frozenset({
    "init", "systemd", "systemd-journal", "systemd-udevd",
    "sshd", "dbus-daemon", "NetworkManager", "cron", "crond",
    "agetty", "login", "containerd", "dockerd", "runc",
    "wazuh-agentd", "wazuh-execd", "wazuh-modulesd",
    "wazuh-logcollec", "wazuh-syscheckd", "wazuh-manager",
    "postgres", "mysqld", "python", "python3", "bash", "sh",
    "sudo", "pkill", "kill-process0", "kill-process-s",
})


class KillError(Exception):
    """Expected safety, policy, dispatch, or verification failure."""


def checked_name(value):
    if not isinstance(value, str) or not VALID_NAME.fullmatch(value):
        raise KillError("INVALID_PROCESS_NAME")
    if value in PROTECTED_NAMES or value.startswith(("wazuh-", "kworker", "systemd-")):
        raise KillError("PROTECTED_PROCESS")
    return value


def validate_policy_document(obj):
    if not isinstance(obj, dict) or set(obj) != {"allowed_process_names"}:
        raise KillError("INVALID_POLICY_SCHEMA")
    names = obj["allowed_process_names"]
    if not isinstance(names, list) or len(names) > 64 or len(names) != len(set(map(str, names))):
        raise KillError("INVALID_POLICY_ALLOWLIST")
    allowed = set()
    for name in names:
        allowed.add(checked_name(name))
    if not allowed:
        raise KillError("EMPTY_ALLOWLIST")
    return frozenset(allowed)


def load_policy(path=POLICY_PATH):
    """Read a root-controlled policy, refusing writable files and symlink tricks."""
    try:
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
            raise KillError("UNSAFE_POLICY_DIRECTORY")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise KillError("UNSAFE_POLICY_FILE")
            with os.fdopen(fd, "rb", closefd=False) as handle:
                raw = handle.read(MAX_POLICY_BYTES + 1)
            if len(raw) > MAX_POLICY_BYTES:
                raise KillError("POLICY_TOO_LARGE")
        finally:
            os.close(fd)
        return validate_policy_document(json.loads(raw))
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise KillError("POLICY_UNAVAILABLE_OR_INVALID") from exc


def audit(status, name="-", pid="-"):
    """Append concise audit records, refusing symlinked or writable log files."""
    line = json.dumps({
        "ts": int(time.time()), "status": status, "process_name": name, "pid": pid
    }, separators=(",", ":")).encode("utf-8") + b"\n"
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(LOG_PATH, flags, 0o640)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise KillError("UNSAFE_AUDIT_LOG")
        fcntl.flock(fd, fcntl.LOCK_EX)
        total = 0
        while total < len(line):
            count = os.write(fd, line[total:])
            if count <= 0:
                raise KillError("AUDIT_WRITE_FAILED")
            total += count
        os.fsync(fd)
    finally:
        os.close(fd)


def process_snapshot(pid):
    """Return (comm, start_time_ticks, state), or None only when PID vanished."""
    directory = PROC_ROOT / str(pid)
    try:
        comm = (directory / "comm").read_text(encoding="utf-8").rstrip("\n")
        raw = (directory / "stat").read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    end = raw.rfind(") ")
    if end < 0:
        raise KillError("INVALID_PROC_STAT")
    fields = raw[end + 2:].split()  # first field here is Linux stat field #3
    if len(fields) < 20:
        raise KillError("INVALID_PROC_STAT")
    return comm, int(fields[19]), fields[0]


def locate_exactly_one(name):
    matches = []
    for item in PROC_ROOT.iterdir():
        if not item.name.isdecimal():
            continue
        pid = int(item.name)
        if pid in (1, os.getpid(), os.getppid()):
            continue
        snapshot = process_snapshot(pid)
        if snapshot and snapshot[0] == name and snapshot[2] not in ("Z", "X"):
            matches.append((pid, snapshot[1]))
            if len(matches) > 1:
                raise KillError("AMBIGUOUS_PROCESS_NAME")
    if not matches:
        raise KillError("PROCESS_NOT_FOUND")
    return matches[0]


def terminate_verified(pid, name, start_ticks):
    """Signal by pidfd to prevent PID reuse; independently check termination."""
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise KillError("PIDFD_UNSUPPORTED")
    try:
        fd = os.pidfd_open(pid, 0)
    except ProcessLookupError as exc:
        raise KillError("PROCESS_DISAPPEARED") from exc
    try:
        snapshot = process_snapshot(pid)
        if snapshot is None or snapshot[0] != name or snapshot[1] != start_ticks or snapshot[2] in ("Z", "X"):
            raise KillError("PROCESS_IDENTITY_CHANGED")
        # Do not claim success from the signal syscall alone.
        signal.pidfd_send_signal(fd, signal.SIGTERM, None, 0)
        audit("SIGTERM_SENT", name, pid)
        deadline = time.monotonic() + TERMINATION_TIMEOUT_SECONDS
        while True:
            observed = process_snapshot(pid)
            if observed is None or observed[1] != start_ticks or observed[2] in ("Z", "X"):
                return "TERMINATED_VERIFIED"
            if time.monotonic() >= deadline:
                raise KillError("TERMINATION_UNVERIFIED")
            time.sleep(0.1)
    except ProcessLookupError as exc:
        raise KillError("PROCESS_DISAPPEARED_DURING_SIGNAL") from exc
    finally:
        os.close(fd)


def parse_wazuh_request(raw):
    if len(raw.encode("utf-8")) > MAX_INPUT_BYTES:
        raise KillError("OVERSIZED_REQUEST")
    try:
        data = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise KillError("INVALID_JSON") from exc
    if not isinstance(data, dict) or data.get("command") not in ("add", "delete"):
        raise KillError("INVALID_WAZUH_COMMAND")
    if data["command"] == "delete":
        return None  # A delete event must never terminate a process.
    parameters = data.get("parameters")
    alert = parameters.get("alert") if isinstance(parameters, dict) else None
    event = alert.get("data") if isinstance(alert, dict) else None
    if not isinstance(event, dict):
        raise KillError("MISSING_ALERT_DATA")
    primary, alias = event.get("process_name"), event.get("processname")
    if primary is not None and alias is not None and primary != alias:
        raise KillError("CONFLICTING_PROCESS_NAMES")
    return checked_name(primary if primary is not None else alias)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if argv == ["--check-policy"]:
        try:
            policy = load_policy()
            print("KILL_POLICY_OK: {} allowed process name(s)".format(len(policy)))
            return 0
        except KillError as exc:
            print(str(exc), file=sys.stderr)
            return 1
    if argv:
        print("Unsupported arguments", file=sys.stderr)
        return 2
    name = "-"
    pid = "-"
    try:
        if os.geteuid() != 0:
            raise KillError("ROOT_REQUIRED")
        raw = sys.stdin.readline(MAX_INPUT_BYTES + 1)
        name = parse_wazuh_request(raw)
        if name is None:
            return 0
        allowed = load_policy()
        if name not in allowed:
            raise KillError("NOT_ALLOWLISTED")
        pid, start_ticks = locate_exactly_one(name)
        audit("APPROVED", name, pid)  # Must persist audit before sending SIGTERM.
        outcome = terminate_verified(pid, name, start_ticks)
        audit(outcome, name, pid)
        return 0
    except (KillError, OSError, ValueError) as exc:
        reason = str(exc) if isinstance(exc, KillError) else "PROCESS_OPERATION_FAILED"
        try:
            audit(reason, name if isinstance(name, str) and VALID_NAME.fullmatch(name) else "-", pid)
        except (OSError, KillError):
            reason += "; AUDIT_FAILED"
        print("AI-SOC kill_process: " + reason, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
