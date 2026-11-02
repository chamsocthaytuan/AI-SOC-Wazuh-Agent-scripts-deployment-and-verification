"""Regression tests for the exact deployed Kali kill-process0 script.

A private fake 'pkill' executable is injected via PATH: these tests NEVER
send a signal to a real process. This module tests the legacy implementation,
NOT its suitability for unattended/production execution.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

SOURCE = Path(__file__).resolve().parents[2] / "active-response" / "kill-process0"
EXPECTED_SHA256 = "5e9bc0e03b94584838dd97a64aab8906b168243c7bda2cf700803060cf24b3da"


def _run_fake(tmp_path, *, command="add", data=None, fake_returncode=0):
    # Substitute a temporary log path in a copy, retaining the import's source.
    text = SOURCE.read_text()
    patched = text.replace(
        'LOG = "/var/ossec/logs/kill-process.log"',
        'LOG = ' + repr(str(tmp_path / "kill-process.log")),
        1,
    )
    script = tmp_path / "kill-process0"
    script.write_text(patched)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_pkill = bin_dir / "pkill"
    fake_pkill.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$@\" > \"$AI_SOC_CAPTURE\"\n"
        "exit \"$AI_SOC_FAKE_RC\"\n"
    )
    fake_pkill.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
    env["AI_SOC_CAPTURE"] = str(tmp_path / "args.txt")
    env["AI_SOC_FAKE_RC"] = str(fake_returncode)
    payload = {"command": command, "parameters": {"alert": {"data": data or {}}}}
    result = subprocess.run(
        [sys.executable, str(script)],
        input=json.dumps(payload) + "\n",
        text=True,
        capture_output=True,
        env=env,
        timeout=5,
        check=False,
    )
    captured_path = tmp_path / "args.txt"
    args = captured_path.read_text().splitlines() if captured_path.exists() else None
    log_path = tmp_path / "kill-process.log"
    log = log_path.read_text() if log_path.exists() else ""
    return result, args, log


def test_deployed_kali_binary_exact_sha256():
    assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == EXPECTED_SHA256


def test_non_add_command_is_noop_without_pkill(tmp_path):
    result, args, log = _run_fake(tmp_path, command="delete", data={"process_name": "lab-task"})
    assert result.returncode == 0
    assert args is None
    assert log == ""


def test_process_name_routes_exact_name_to_term_pkill(tmp_path):
    result, args, log = _run_fake(tmp_path, data={"process_name": "aisockill2"})
    assert result.returncode == 0, result.stderr
    assert args == ["-TERM", "-x", "aisockill2"]
    assert "KILLED process_name=aisockill2" in log


def test_processname_alias_keeps_legacy_compatibility(tmp_path):
    result, args, log = _run_fake(tmp_path, data={"processname": "aisockill2"})
    assert result.returncode == 0
    assert args == ["-TERM", "-x", "aisockill2"]


def test_missing_process_name_fails_without_running_pkill(tmp_path):
    result, args, log = _run_fake(tmp_path, data={})
    assert result.returncode == 1
    assert args is None
    assert "ERROR: process_name not found" in log


def test_pkill_nonzero_is_not_reported_as_success(tmp_path):
    result, args, log = _run_fake(tmp_path, data={"process_name": "not-running"}, fake_returncode=1)
    assert result.returncode == 1
    assert args == ["-TERM", "-x", "not-running"]
    assert "NOT_FOUND process_name=not-running" in log
    assert "KILLED" not in log


def test_legacy_process_termination_is_not_enabled_in_default_installer():
    installer = (SOURCE.parents[1] / "scripts" / "install.sh").read_text()
    assert "install -o root -g root -m 0750" in installer
    # The legacy source is versioned, but not auto-deployed until input
    # validation, critical-process protection, and E2E are completed.
    assert 'for f in block-ip.py isolate.sh ai_soc_evidence.py; do\n  dest=' in installer
