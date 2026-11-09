"""Non-destructive CLI tests for Linux Agent one-click installer."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "install-oneclick.sh"

def call(*args):
    return subprocess.run(["bash", str(SCRIPT), *args], text=True, capture_output=True)

def test_bash_syntax():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)

def test_help():
    r = call("--help")
    assert r.returncode == 0
    assert "--with-kill-process" in r.stdout
    assert "--verify" in r.stdout

def test_allowlist_requires_explicit_kill_opt_in():
    r = call("--dry-run", "--allow-process", "aisockill2")
    assert r.returncode != 0
    assert "only valid together" in r.stderr

def test_unknown_flag_is_rejected():
    assert call("--not-a-real-flag").returncode == 2
