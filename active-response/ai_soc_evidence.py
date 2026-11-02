#!/usr/bin/env python3
"""Append one validated AI-SOC verification event to the endpoint JSONL ledger.

This helper is deliberately independent from action execution. It never runs a
firewall command and it never changes the exit status of the caller's action.
The caller must provide a stable event_id and execution_id for each event.
"""

from __future__ import annotations

import argparse
import datetime as _datetime
import fcntl
import json
import math
import os
import re
import socket
import stat
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

DEFAULT_LOG_PATH = Path("/var/ossec/logs/ai-soc-verification.json")
CLIENT_KEYS_PATH = Path("/var/ossec/etc/client.keys")
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
SCHEMA_VERSION = "1.0"
MAX_EVENT_BYTES = 64 * 1024

EVENT_TYPES = frozenset(
    {
        "EXECUTION_STARTED",
        "EXECUTION_COMPLETED",
        "EXECUTION_FAILED",
        "STATE_SNAPSHOT",
        "ROLLBACK_STARTED",
        "ROLLBACK_COMPLETED",
        "ROLLBACK_FAILED",
        "TTL_RENEWED",
        "TTL_AUTO_EXPIRED",
        "ISOLATION_LOST_ON_REBOOT",
    }
)
OUTCOMES = frozenset(
    {"started", "success", "failed", "observed", "renewed", "expired", "lost", "unknown"}
)
SENSITIVE_KEY_RE = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|authorization|private[_-]?key|client[_-]?key|credential)",
    re.IGNORECASE,
)
SENSITIVE_VALUE_PATTERNS = (
    re.compile(
        r"(?i)\b(password|passwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?key|credential)\b"
        r"(\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
    ),
    re.compile(r"(?i)\bauthorization(\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+"),
)


class EvidenceError(ValueError):
    """Raised when an event cannot safely be written as endpoint evidence."""


def _utc_now() -> str:
    return (
        _datetime.datetime.now(_datetime.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _non_empty_text(value: Any, field_name: str, max_length: int = 512) -> str:
    if not isinstance(value, str):
        raise EvidenceError("{} must be a string".format(field_name))
    value = value.strip()
    if not value:
        raise EvidenceError("{} must not be empty".format(field_name))
    if len(value) > max_length:
        raise EvidenceError("{} exceeds {} characters".format(field_name, max_length))
    return value


def _resolve_agent_id(client_keys_path: Path = CLIENT_KEYS_PATH) -> str:
    """Read only the Wazuh agent ID from client.keys; never expose the key."""
    try:
        lines = client_keys_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise EvidenceError("cannot read the local Wazuh client.keys file") from exc

    candidates = []
    for line in lines:
        fields = line.split()
        if len(fields) >= 4 and fields[0].isdigit():
            candidates.append(fields[0])
    unique_ids = sorted(set(candidates))
    if len(unique_ids) != 1:
        raise EvidenceError("cannot resolve exactly one local Wazuh agent ID from client.keys")
    return unique_ids[0]


def _resolve_agent_context() -> Dict[str, str]:
    agent_id = _resolve_agent_id()
    hostname = socket.gethostname().strip()
    if not hostname:
        raise EvidenceError("cannot resolve local hostname")
    try:
        boot_id = BOOT_ID_PATH.read_text(encoding="ascii").strip()
        boot_id = str(uuid.UUID(boot_id))
    except (OSError, ValueError) as exc:
        raise EvidenceError("cannot resolve a valid Linux boot_id") from exc
    return {
        "agent_id": agent_id,
        "hostname": hostname,
        "boot_id": boot_id,
        "observed_at": _utc_now(),
    }


def _redact_text(value: str) -> str:
    result = value
    for pattern in SENSITIVE_VALUE_PATTERNS:
        if pattern.groups >= 2:
            result = pattern.sub(
                lambda match: match.group(1) + match.group(2) + "[REDACTED]",
                result,
            )
        else:
            result = pattern.sub("authorization=[REDACTED]", result)
    return result


def _sanitize_json_value(value: Any, path: str = "payload") -> Any:
    """Redact sensitive keys and reject structures Wazuh JSON decoding cannot map."""
    if value is None or isinstance(value, (str, bool, int)):
        return _redact_text(value) if isinstance(value, str) else value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise EvidenceError("{} contains a non-finite number".format(path))
        return value
    if isinstance(value, Mapping):
        cleaned = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise EvidenceError("{} contains a non-string JSON key".format(path))
            if SENSITIVE_KEY_RE.search(key):
                cleaned[key] = "[REDACTED]"
            else:
                cleaned[key] = _sanitize_json_value(item, "{}.{}".format(path, key))
        return cleaned
    if isinstance(value, list):
        for item in value:
            if isinstance(item, (Mapping, list)):
                raise EvidenceError(
                    "{} contains an array of objects/arrays; flatten it for Wazuh JSON decoding".format(path)
                )
        return [_sanitize_json_value(item, "{}[]".format(path)) for item in value]
    raise EvidenceError("{} contains an unsupported JSON value".format(path))


def _normalize_observed_at(value: Any) -> str:
    if value is None:
        return _utc_now()
    if not isinstance(value, str):
        raise EvidenceError("host.observed_at must be an ISO-8601 string")
    raw = value.strip()
    if not raw:
        raise EvidenceError("host.observed_at must not be empty")
    try:
        parsed = _datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError("host.observed_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise EvidenceError("host.observed_at must include a timezone")
    return parsed.astimezone(_datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _normalize_event(event: Mapping[str, Any], agent_context: Mapping[str, str]) -> Dict[str, Any]:
    if not isinstance(event, Mapping):
        raise EvidenceError("event payload must be a JSON object")
    if "ingestion_channel" in event:
        raise EvidenceError("ingestion_channel is assigned by the collector, not by the endpoint")

    schema_version = str(event.get("schema_version", "")).strip()
    if schema_version != SCHEMA_VERSION:
        raise EvidenceError("schema_version must be {}".format(SCHEMA_VERSION))

    try:
        event_id = str(uuid.UUID(_non_empty_text(event.get("event_id"), "event_id", 64)))
    except ValueError as exc:
        raise EvidenceError("event_id must be a UUID") from exc

    plan_id = _non_empty_text(event.get("plan_id"), "plan_id", 128)
    action_id = _non_empty_text(event.get("action_id"), "action_id", 128)
    try:
        execution_id = str(uuid.UUID(_non_empty_text(event.get("execution_id"), "execution_id", 64)))
    except ValueError as exc:
        raise EvidenceError("execution_id must be a UUID") from exc

    local_agent_id = _non_empty_text(agent_context.get("agent_id"), "local agent_id", 64)
    supplied_agent = event.get("agent") or {}
    if not isinstance(supplied_agent, Mapping):
        raise EvidenceError("agent must be a JSON object")
    supplied_agent_id = supplied_agent.get("id")
    if supplied_agent_id is not None and str(supplied_agent_id).strip() != local_agent_id:
        raise EvidenceError("agent.id does not match the local Wazuh agent identity")
    agent_hostname = _non_empty_text(agent_context.get("hostname"), "local hostname", 255)

    supplied_host = event.get("host") or {}
    if not isinstance(supplied_host, Mapping):
        raise EvidenceError("host must be a JSON object")
    local_boot_id = str(uuid.UUID(_non_empty_text(agent_context.get("boot_id"), "local boot_id", 64)))
    supplied_boot_id = supplied_host.get("boot_id")
    if supplied_boot_id is not None and str(uuid.UUID(str(supplied_boot_id))) != local_boot_id:
        raise EvidenceError("host.boot_id does not match the current endpoint boot")
    observed_at = _normalize_observed_at(supplied_host.get("observed_at"))

    action = event.get("action")
    if not isinstance(action, Mapping):
        raise EvidenceError("action must be a JSON object")
    normalized_action = dict(action)
    normalized_action.update(
        {
            "type": _non_empty_text(action.get("type"), "action.type", 128),
            "target": _non_empty_text(action.get("target"), "action.target", 512),
            "direction": _non_empty_text(action.get("direction"), "action.direction", 64),
        }
    )

    event_data = event.get("event")
    if not isinstance(event_data, Mapping):
        raise EvidenceError("event must be a JSON object")
    event_type = _non_empty_text(event_data.get("type"), "event.type", 64).upper()
    if event_type not in EVENT_TYPES:
        raise EvidenceError("unsupported event.type: {}".format(event_type))
    step = _non_empty_text(event_data.get("step"), "event.step", 128)
    outcome = _non_empty_text(event_data.get("outcome"), "event.outcome", 32).lower()
    if outcome not in OUTCOMES:
        raise EvidenceError("unsupported event.outcome: {}".format(outcome))
    exit_code = event_data.get("exit_code")
    if exit_code is not None and (isinstance(exit_code, bool) or not isinstance(exit_code, int)):
        raise EvidenceError("event.exit_code must be an integer or null")

    state_fields = {}
    for key in ("state", "pre_state", "post_state"):
        if key not in event:
            raise EvidenceError("{} is required (use null when not applicable)".format(key))
        value = event[key]
        if value is not None and not isinstance(value, Mapping):
            raise EvidenceError("{} must be a JSON object or null".format(key))
        state_fields[key] = value

    normalized: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id,
        "plan_id": plan_id,
        "action_id": action_id,
        "execution_id": execution_id,
        "agent": {"id": local_agent_id, "hostname": agent_hostname},
        "host": {"boot_id": local_boot_id, "observed_at": observed_at},
        "action": normalized_action,
        "event": {
            **dict(event_data),
            "type": event_type,
            "step": step,
            "outcome": outcome,
            "exit_code": exit_code,
        },
        "state": state_fields["state"],
        "pre_state": state_fields["pre_state"],
        "post_state": state_fields["post_state"],
        "evidence_source": "endpoint",
    }

    core_fields = set(normalized)
    for key, value in event.items():
        if key not in core_fields and key not in {"agent", "host", "action", "event"}:
            normalized[key] = value

    normalized = _sanitize_json_value(normalized)
    return normalized


def append_event(
    event: Mapping[str, Any],
    log_path: Path = DEFAULT_LOG_PATH,
    agent_context: Optional[Mapping[str, str]] = None,
) -> str:
    """Validate and append one JSON object plus newline; return its event_id.

    The target log file must already exist. The bootstrap script creates it as
    root:wazuh with mode 0640, so a missing file or unsafe permissions are
    reported rather than silently creating an unreadable or unsafe log.
    """
    context = agent_context or _resolve_agent_context()
    normalized = _normalize_event(event, context)
    try:
        line = (json.dumps(normalized, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise EvidenceError("event cannot be serialized as JSON") from exc
    if len(line) > MAX_EVENT_BYTES:
        raise EvidenceError("serialized event exceeds {} bytes".format(MAX_EVENT_BYTES))

    flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(log_path), flags)
    except OSError as exc:
        raise EvidenceError("cannot open the pre-created evidence log: {}".format(exc.strerror or exc)) from exc

    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise EvidenceError("evidence log is not a regular file")
        mode = stat.S_IMODE(info.st_mode)
        if mode != 0o640:
            raise EvidenceError("evidence log permissions must be 0640 (found {:04o})".format(mode))
        # Keep the advisory lock across the full write and optional repair.
        # os.write may return fewer bytes than requested, including EINTR.
        # Repair only a partial tail that this writer owns; never rewrite
        # earlier evidence or silently skip an ambiguous failed fsync.
        start_size = info.st_size
        total = 0
        try:
            while total < len(line):
                try:
                    written = os.write(fd, line[total:])
                except InterruptedError:
                    continue
                if written <= 0:
                    raise EvidenceError("zero-length write while appending evidence")
                total += written
        except (OSError, EvidenceError):
            if total:
                # On an exclusive cooperative writer lock the only new bytes
                # should be ours. Reject a concurrent uncooperative mutation.
                if os.fstat(fd).st_size == start_size + total:
                    os.ftruncate(fd, start_size)
                    os.fsync(fd)
            raise
        os.fsync(fd)
    except OSError as exc:
        raise EvidenceError("evidence append failed: {}".format(exc.strerror or exc)) from exc
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
    return normalized["event_id"]


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="Append one AI-SOC endpoint evidence JSON object")
    parser.add_argument("--log-path", default=str(DEFAULT_LOG_PATH), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    try:
        raw = sys.stdin.read(MAX_EVENT_BYTES + 1)
        if len(raw.encode("utf-8")) > MAX_EVENT_BYTES:
            raise EvidenceError("input event exceeds {} bytes".format(MAX_EVENT_BYTES))
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise EvidenceError("stdin does not contain one valid JSON object") from exc
        if not isinstance(event, dict):
            raise EvidenceError("stdin JSON value must be an object")
        event_id = append_event(event, Path(args.log_path))
    except (EvidenceError, OSError) as exc:
        print("AI-SOC evidence write failed: {}".format(exc), file=sys.stderr)
        return 1

    print(event_id)
    return 0


if __name__ == "__main__":
    sys.exit(main())