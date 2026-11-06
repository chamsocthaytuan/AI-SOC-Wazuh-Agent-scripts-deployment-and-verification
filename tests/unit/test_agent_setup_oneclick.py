"""Non-destructive regression tests for Linux Agent + Suricata OneClick."""
import importlib.util
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
