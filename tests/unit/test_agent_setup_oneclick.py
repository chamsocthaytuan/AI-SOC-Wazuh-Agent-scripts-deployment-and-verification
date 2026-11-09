"""Non-destructive regression tests for Linux Agent + Suricata OneClick."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "scripts" / "agent-setup.py"
SPEC = importlib.util.spec_from_file_location("aisoc_agent_setup", PATH)
setup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup)

BASE = """<ossec_config>
  <client>
    <server>
      <address>10.0.70.12</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>
</ossec_config>
"""

def test_manager_uses_agent_config_not_stale_ip():
    assert setup.manager_from(BASE) == "10.0.70.12"
    for invalid in (BASE.replace("10.0.70.12", "manager.local"),
                    BASE.replace("1514", "1515"),
                    BASE.replace("</client>", "<server><address>10.0.70.13</address></server></client>")):
        with pytest.raises(SystemExit):
            setup.manager_from(invalid)

def test_suricata_localfile_added_once():
    updated = setup.add_suricata_localfile(BASE)
    assert setup.has_suricata_localfile(updated)
    assert updated.count("/var/log/suricata/eve.json") == 1
    assert setup.add_suricata_localfile(updated) == updated

def test_conflicting_existing_suricata_format_fails_closed():
    wrong = BASE.replace("</ossec_config>", """
<localfile><location>/var/log/suricata/eve.json</location>
<log_format>syslog</log_format></localfile></ossec_config>""")
    with pytest.raises(SystemExit):
        setup.add_suricata_localfile(wrong)

def test_repoint_changes_exactly_client_address():
    text = setup.update_manager(BASE, "10.0.70.251")
    assert setup.manager_from(text) == "10.0.70.251"
    assert "<port>1514</port>" in text

def test_backups_and_permissions():
    with tempfile.TemporaryDirectory() as tmp:
        file = Path(tmp) / "ossec.conf"
        file.write_text(BASE)
        file.chmod(0o640)
        assert setup.backup_replace(file, BASE, setup.add_suricata_localfile(BASE))
        assert file.stat().st_mode & 0o777 == 0o640
        assert len(list(Path(tmp).glob("ossec.conf.bak.aisoc-*"))) == 1

def test_preview_does_not_touch_agent_or_prompt():
    result = subprocess.run(["python3", str(PATH), "--dry-run", "--manager-ip", "10.0.70.12"],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "PREVIEW_AGENT" in result.stdout
    assert "NO_CHANGES" in result.stdout

def test_oneclick_bash_parses():
    subprocess.run(["bash", "-n", str(ROOT / "scripts" / "install-oneclick.sh")], check=True)


def test_wazuh_apt_signing_key_readable_under_private_installer_umask(monkeypatch, tmp_path):
    """A new public keyring/source must be readable by apt's sandboxed _apt user."""
    key = tmp_path / "wazuh.gpg"
    source = tmp_path / "wazuh.list"
    monkeypatch.setattr(setup, "WAZUH_KEYRING", key)
    monkeypatch.setattr(setup, "WAZUH_APT_SOURCE", source)
    monkeypatch.setattr(setup.shutil, "which", lambda _: "/usr/bin/test-binary")
    commands = []

    def fake_run(*command, **kwargs):
        commands.append(command)
        if command[0] == "gpg":
            Path(command[command.index("-o") + 1]).write_bytes(b"test-only-public-keyring")

    monkeypatch.setattr(setup, "run", fake_run)
    previous_umask = os.umask(0o077)
    try:
        setup.setup_repo()
    finally:
        os.umask(previous_umask)

    assert key.is_file() and key.stat().st_mode & 0o777 == 0o644
    assert source.is_file() and source.stat().st_mode & 0o777 == 0o644
    assert "signed-by=/usr/share/keyrings/wazuh.gpg" in source.read_text()
    assert commands[-1] == ("apt-get", "update")
    assert any(command[0] == "gpg" for command in commands)


def test_wazuh_apt_setup_repairs_partial_0600_files(monkeypatch, tmp_path):
    """Interrupted attempts must not skip the keyring fix when wazuh.list exists."""
    key = tmp_path / "wazuh.gpg"
    source = tmp_path / "wazuh.list"
    key.write_bytes(b"test-only-public-keyring")
    source.write_text("deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\n")
    key.chmod(0o600)
    source.chmod(0o600)
    monkeypatch.setattr(setup, "WAZUH_KEYRING", key)
    monkeypatch.setattr(setup, "WAZUH_APT_SOURCE", source)
    monkeypatch.setattr(setup.shutil, "which", lambda _: "/usr/bin/test-binary")
    commands = []
    monkeypatch.setattr(setup, "run", lambda *args, **kwargs: commands.append(args))

    setup.setup_repo()

    assert key.stat().st_mode & 0o777 == 0o644
    assert source.stat().st_mode & 0o777 == 0o644
    assert commands == [("apt-get", "update")]


def test_wazuh_apt_setup_rejects_symlink_keyring(monkeypatch, tmp_path):
    key = tmp_path / "wazuh.gpg"
    target = tmp_path / "target"
    target.write_bytes(b"do-not-touch")
    key.symlink_to(target)
    monkeypatch.setattr(setup, "WAZUH_KEYRING", key)
    monkeypatch.setattr(setup, "WAZUH_APT_SOURCE", tmp_path / "wazuh.list")
    with pytest.raises(SystemExit, match="symlink"):
        setup.setup_repo()
    assert target.read_bytes() == b"do-not-touch"
