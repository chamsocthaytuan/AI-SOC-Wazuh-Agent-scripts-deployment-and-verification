"""Unit tests for the Linux endpoint JSONL evidence writer."""

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import uuid

import pytest

WRITER_PATH = pathlib.Path(__file__).resolve().parents[2] / "active-response" / "ai_soc_evidence.py"
SPEC = importlib.util.spec_from_file_location("ai_soc_evidence", WRITER_PATH)
writer = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(writer)

AGENT_CONTEXT = {
    "agent_id": "007",
    "hostname": "linux-lab-07",
    "boot_id": "9c6a1b9d-3a5c-4b33-a58c-9d8f12345678",
    "observed_at": "2026-10-30T03:00:00Z",
}


def make_event(**overrides):
    event = {
        "schema_version": "1.0",
        "event_id": str(uuid.uuid4()),
        "plan_id": "plan-001",
        "action_id": "action-001",
        "execution_id": "f968cc2e-b659-45d2-bfe0-2af83020641a",
        "agent": {"id": "007"},
        "host": {"boot_id": AGENT_CONTEXT["boot_id"], "observed_at": "2026-10-30T03:00:00+07:00"},
        "action": {
            "type": "block_ip",
            "target": "203.0.113.20",
            "direction": "INPUT",
            "firewall_backend": "nftables",
            "ip_version": 4,
        },
        "event": {"type": "EXECUTION_COMPLETED", "step": "install_rule", "outcome": "success", "exit_code": 0},
        "state": {"blocked": True},
        "pre_state": {"rule_present": False},
        "post_state": {"rule_present": True},
    }
    event.update(overrides)
    return event


def make_log(tmp_path, mode=0o640):
    path = tmp_path / "ai-soc-verification.json"
    path.touch()
    path.chmod(mode)
    return path


def test_valid_event_appends_one_jsonl_and_preserves_contract_fields(tmp_path):
    path = make_log(tmp_path)
    event = make_event()

    event_id = writer.append_event(event, path, AGENT_CONTEXT)

    rows = path.read_text(encoding="utf-8").splitlines()
    assert len(rows) == 1
    result = json.loads(rows[0])
    assert event_id == event["event_id"]
    assert result["event_id"] == event_id
    assert result["execution_id"] == "f968cc2e-b659-45d2-bfe0-2af83020641a"
    assert result["agent"] == {"id": "007", "hostname": "linux-lab-07"}
    assert result["host"]["boot_id"] == AGENT_CONTEXT["boot_id"]
    assert result["host"]["observed_at"] == "2026-10-29T20:00:00.000Z"
    assert result["evidence_source"] == "endpoint"
    assert result["action"]["firewall_backend"] == "nftables"
    assert result["action"]["ip_version"] == 4
    assert result["event"]["exit_code"] == 0


def test_missing_execution_id_is_rejected_without_appending(tmp_path):
    path = make_log(tmp_path)
    event = make_event()
    event.pop("execution_id")

    with pytest.raises(writer.EvidenceError, match="execution_id"):
        writer.append_event(event, path, AGENT_CONTEXT)

    assert path.read_bytes() == b""


def test_malformed_json_cli_returns_nonzero_and_does_not_append(tmp_path):
    path = make_log(tmp_path)
    proc = subprocess.run(
        [sys.executable, str(WRITER_PATH), "--log-path", str(path)],
        input='{"schema_version":',
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "valid JSON" in proc.stderr
    assert path.read_bytes() == b""


def test_duplicate_event_id_is_preserved_for_ledger_deduplication(tmp_path):
    path = make_log(tmp_path)
    event = make_event()

    writer.append_event(event, path, AGENT_CONTEXT)
    writer.append_event(event, path, AGENT_CONTEXT)

    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 2
    assert rows[0]["event_id"] == rows[1]["event_id"] == event["event_id"]
    # Ingestion must use UNIQUE(event_id) from the database contract, not agent_id.


def test_sensitive_keys_and_inline_secrets_are_redacted(tmp_path):
    path = make_log(tmp_path)
    event = make_event(
        diagnostic={
            "password": "dont-store-this",
            "detail": "request token=very-secret authorization=Bearer abc123 complete",
        }
    )

    writer.append_event(event, path, AGENT_CONTEXT)

    stored = path.read_text(encoding="utf-8")
    assert "dont-store-this" not in stored
    assert "very-secret" not in stored
    assert "abc123" not in stored
    parsed = json.loads(stored)
    assert parsed["diagnostic"]["password"] == "[REDACTED]"
    assert "[REDACTED]" in parsed["diagnostic"]["detail"]


def test_agent_id_and_boot_id_must_match_local_context(tmp_path):
    path = make_log(tmp_path)
    wrong_agent = make_event(agent={"id": "008"})
    with pytest.raises(writer.EvidenceError, match="agent.id"):
        writer.append_event(wrong_agent, path, AGENT_CONTEXT)

    wrong_boot = make_event(host={"boot_id": "11111111-1111-4111-8111-111111111111"})
    with pytest.raises(writer.EvidenceError, match="boot_id"):
        writer.append_event(wrong_boot, path, AGENT_CONTEXT)
    assert path.read_bytes() == b""


def test_invalid_json_array_shape_is_rejected_for_wazuh_json_decoder(tmp_path):
    path = make_log(tmp_path)
    event = make_event(state={"rules": [{"chain": "INPUT"}]})

    with pytest.raises(writer.EvidenceError, match="array of objects"):
        writer.append_event(event, path, AGENT_CONTEXT)
    assert path.read_bytes() == b""


def test_bad_file_mode_and_missing_file_fail_closed(tmp_path):
    bad_mode = make_log(tmp_path, mode=0o600)
    with pytest.raises(writer.EvidenceError, match="permissions must be 0640"):
        writer.append_event(make_event(), bad_mode, AGENT_CONTEXT)

    missing = tmp_path / "missing.json"
    with pytest.raises(writer.EvidenceError, match="pre-created evidence log"):
        writer.append_event(make_event(), missing, AGENT_CONTEXT)


def test_ingestion_channel_is_not_endpoint_owned(tmp_path):
    path = make_log(tmp_path)
    event = make_event(ingestion_channel="wazuh_indexer")

    with pytest.raises(writer.EvidenceError, match="assigned by the collector"):
        writer.append_event(event, path, AGENT_CONTEXT)
    assert path.read_bytes() == b""


def test_append_produces_exactly_one_line_per_event(tmp_path):
    path = make_log(tmp_path)
    for _ in range(5):
        writer.append_event(make_event(), path, AGENT_CONTEXT)

    rows = path.read_text(encoding="utf-8").splitlines()
    assert len(rows) == 5
    for row in rows:
        assert isinstance(json.loads(row), dict)


def test_nonfinite_numbers_are_rejected(tmp_path):
    path = make_log(tmp_path)
    event = make_event(state={"counter": float("nan")})
    with pytest.raises(writer.EvidenceError, match="non-finite"):
        writer.append_event(event, path, AGENT_CONTEXT)
    assert path.read_bytes() == b""


def test_writer_follows_current_log_path_after_rename_rotation(tmp_path):
    path = make_log(tmp_path)
    first = make_event()
    writer.append_event(first, path, AGENT_CONTEXT)

    rotated = tmp_path / "ai-soc-verification.json.1"
    os.replace(path, rotated)
    path.touch()
    path.chmod(0o640)

    second = make_event()
    writer.append_event(second, path, AGENT_CONTEXT)

    assert json.loads(rotated.read_text(encoding="utf-8").splitlines()[0])["event_id"] == first["event_id"]
    assert json.loads(path.read_text(encoding="utf-8").splitlines()[0])["event_id"] == second["event_id"]


def test_concurrent_appends_never_interleave_jsonl_records(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    path = make_log(tmp_path)
    events = [make_event() for _ in range(40)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda item: writer.append_event(item, path, AGENT_CONTEXT), events))

    rows = path.read_text(encoding="utf-8").splitlines()
    assert len(rows) == len(events)
    parsed = [json.loads(row) for row in rows]
    assert {row["event_id"] for row in parsed} == {item["event_id"] for item in events}


def test_non_uuid_execution_id_rejected_by_v003_contract(tmp_path):
    path = make_log(tmp_path)
    with pytest.raises(writer.EvidenceError, match="execution_id must be a UUID"):
        writer.append_event(make_event(execution_id="not-a-uuid"), path, AGENT_CONTEXT)
    assert path.read_bytes() == b""


def test_short_write_completes_one_valid_json_line(tmp_path, monkeypatch):
    path = make_log(tmp_path)
    original_write = writer.os.write
    counts = []

    def partial_write(fd, payload):
        n = max(1, len(payload) // 2)
        counts.append(n)
        return original_write(fd, payload[:n])

    monkeypatch.setattr(writer.os, "write", partial_write)
    event = make_event()
    writer.append_event(event, path, AGENT_CONTEXT)
    rows = path.read_text().splitlines()
    assert len(counts) > 1
    assert len(rows) == 1
    assert json.loads(rows[0])["event_id"] == event["event_id"]


def test_partial_write_error_repairs_only_own_tail(tmp_path, monkeypatch):
    path = make_log(tmp_path)
    old = make_event()
    writer.append_event(old, path, AGENT_CONTEXT)
    old_bytes = path.read_bytes()
    original_write = writer.os.write
    calls = 0

    def interrupt_after_partial(fd, payload):
        nonlocal calls
        calls += 1
        if calls == 1:
            return original_write(fd, payload[:17])
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(writer.os, "write", interrupt_after_partial)
    with pytest.raises(writer.EvidenceError, match="evidence append failed"):
        writer.append_event(make_event(), path, AGENT_CONTEXT)
    assert path.read_bytes() == old_bytes
