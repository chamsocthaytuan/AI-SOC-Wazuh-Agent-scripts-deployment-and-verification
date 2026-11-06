#!/usr/bin/env python3
"""Debian/Ubuntu/Kali Wazuh 4.8.2 + mandatory Suricata bootstrap.

Non-destructive preview and verification; no Active Response execution.
Existing Wazuh identities/keys are never replaced.
"""
import argparse
import getpass
import grp
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from xml.etree import ElementTree as ET

AGENT = Path("/var/ossec/etc/ossec.conf")
KEYS = Path("/var/ossec/etc/client.keys")
EVE = Path("/var/log/suricata/eve.json")
SURICATA = Path("/etc/suricata/suricata.yaml")
VERSION = "4.8.2-1"
DEFAULT_MANAGER = "10.0.70.12"

def fail(message):
    raise SystemExit("SETUP_FAILED: " + message)

def run(*argv, env=None, check=True):
    print("RUN:", " ".join(argv), flush=True)
    return subprocess.run(argv, check=check, env=env)

def service(name):
    return subprocess.run(["systemctl", "is-active", "--quiet", name]).returncode == 0

def xml(text):
    text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text, count=1)
    return ET.fromstring("<bundle>" + text + "</bundle>")

def manager_from(text):
    servers = xml(text).findall("./ossec_config/client/server")
    if len(servers) != 1:
        fail("Expected exactly one Wazuh client/server")
    server = servers[0]
    ip = (server.findtext("address") or "").strip()
    port = (server.findtext("port") or "1514").strip()
    protocol = (server.findtext("protocol") or "tcp").lower().strip()
    try:
        if ipaddress.ip_address(ip).version != 4:
            fail("Manager must be literal IPv4")
    except ValueError:
        fail("Manager must be literal IPv4, not hostname")
    if (port, protocol) != ("1514", "tcp"):
        fail("Manager must use TCP 1514 to support safe isolation")
    return ip

def has_suricata_localfile(text):
    for node in xml(text).findall("./ossec_config/localfile"):
        if (node.findtext("location") or "").strip() == str(EVE):
            if (node.findtext("log_format") or "").strip() != "json":
                fail("Existing Suricata localfile is not JSON")
            return True
    return False

def add_suricata_localfile(text):
    if has_suricata_localfile(text):
        return text
    if "</ossec_config>" not in text:
        fail("Missing ossec_config closing tag")
    block = "  <localfile>\n    <log_format>json</log_format>\n    <location>" + str(EVE) + "</location>\n  </localfile>\n"
    updated = text.replace("</ossec_config>", block + "</ossec_config>", 1)
    if not has_suricata_localfile(updated):
        fail("New Suricata localfile is invalid")
    return updated

def backup_replace(path, before, after):
    if before == after:
        print("CONFIG_UNCHANGED:", path)
        return False
    if path.is_symlink():
        fail("Refusing symlink config " + str(path))
    backup = path.with_name(path.name + ".bak.aisoc-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    shutil.copy2(path, backup)
    print("BACKUP:", backup)
    s = path.stat()
    fd, temp = tempfile.mkstemp(prefix=".aisoc-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            os.fchmod(f.fileno(), s.st_mode & 0o777)
            os.fchown(f.fileno(), s.st_uid, s.st_gid)
            f.write(after)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return True

def port_open(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=4):
            return True
    except OSError:
        return False

def enrolled():
    return KEYS.is_file() and KEYS.stat().st_size > 0

def new_enrollment_password():
    if not sys.stdin.isatty():
        fail("Interactive terminal required for enrollment password")
    pw = getpass.getpass("Enrollment password (hidden): ")
    if len(pw) < 16 or "\n" in pw or "\r" in pw:
        fail("Enrollment password must have at least 16 characters")
    return pw

def save_secret(password):
    path = Path("/var/ossec/etc/authd.pass")
    if path.exists() or path.is_symlink():
        fail("authd.pass already exists; refusing to replace existing credential")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        os.fchown(f.fileno(), 0, grp.getgrnam("wazuh").gr_gid)
        os.fchmod(f.fileno(), 0o640)
        f.write(password + "\n")
        f.flush()
        os.fsync(f.fileno())
    print("AUTHD_PASSWORD_SAVED: root:wazuh 0640 (password not printed)")

def setup_repo():
    if not shutil.which("apt-get"):
        fail("Supported bootstrap OS: Ubuntu/Debian/Kali with apt")
    if not shutil.which("gpg"):
        run("apt-get", "update")
        run("apt-get", "install", "-y", "ca-certificates", "gnupg")
    source = Path("/etc/apt/sources.list.d/wazuh.list")
    key = Path("/usr/share/keyrings/wazuh.gpg")
    if source.exists():
        return
    run("apt-get", "update")
    run("apt-get", "install", "-y", "curl", "ca-certificates")
    if not key.exists():
        fd, temp = tempfile.mkstemp(prefix="aisoc-wazuh-")
        os.close(fd)
        try:
            run("curl", "-fsSL", "https://packages.wazuh.com/key/GPG-KEY-WAZUH", "-o", temp)
            run("gpg", "--batch", "--yes", "--dearmor", "-o", str(key), temp)
        finally:
            Path(temp).unlink(missing_ok=True)
    source.write_text("deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\n")
    run("apt-get", "update")

def install_new_agent(ip, name, password):
    setup_repo()
    result = subprocess.run(["apt-cache", "madison", "wazuh-agent"], text=True, capture_output=True, check=True)
    versions = [part.split("|")[1].strip() for part in result.stdout.splitlines() if "|" in part]
    if VERSION not in versions:
        fail("Agent " + VERSION + " not available; do not install newer than Lab Server Wazuh 4.8.2")
    env = dict(os.environ, WAZUH_MANAGER=ip, WAZUH_REGISTRATION_SERVER=ip, WAZUH_AGENT_NAME=name)
    run("apt-get", "install", "-y", "wazuh-agent=" + VERSION, env=env)
    run("apt-mark", "hold", "wazuh-agent")
    run("systemctl", "stop", "wazuh-agent", check=False)
    save_secret(password)
    if manager_from(AGENT.read_text(encoding="utf-8-sig")) != ip:
        fail("Installed Wazuh Agent points to unexpected Manager")
    run("systemctl", "enable", "--now", "wazuh-agent")
    print("ENROLLMENT_STARTED: check agent ID/Active separately on Manager")

def update_manager(text, ip):
    pattern = re.compile(r"(<client>\s*<server>\s*<address>)([^<]*)(</address>)", re.I)
    if len(pattern.findall(text)) != 1:
        fail("Cannot safely repoint nonstandard Wazuh client/server")
    result = pattern.sub(lambda m: m.group(1) + ip + m.group(3), text, count=1)
    manager_from(result)
    return result

def ensure_agent(args):
    if AGENT.exists():
        if args.agent_name:
            fail("Agent already installed; refusing to rename existing identity")
        before = AGENT.read_text(encoding="utf-8-sig")
        current = manager_from(before)
        ip = args.manager_ip or current
        if ip != current:
            if not args.repoint_existing:
                fail("Existing Agent Manager=" + current + "; explicit --repoint-existing --manager-ip needed")
            if backup_replace(AGENT, before, update_manager(before, ip)):
                run("systemctl", "restart", "wazuh-agent")
        if not enrolled():
            if not port_open(ip, 1515):
                fail("Manager enrollment TCP 1515 unreachable at " + ip)
            save_secret(new_enrollment_password())
            run("systemctl", "enable", "--now", "wazuh-agent")
            print("ENROLLMENT_STARTED: existing unregistered Agent")
        else:
            print("AGENT_EXISTS: client.keys preserved, Manager=" + ip)
        return ip

    ip = args.manager_ip or DEFAULT_MANAGER
    name = args.agent_name
    if not name:
        if not sys.stdin.isatty():
            fail("New Agent requires --agent-name when run non-interactively")
        name = input("Agent Name: ").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name, re.ASCII):
        fail("Invalid Agent Name (1-64 ASCII letters/digits/dot/dash/underscore)")
    if not port_open(ip, 1514) or not port_open(ip, 1515):
        fail("Lab Server TCP 1514 and 1515 must be reachable before new enrollment")
    pw = new_enrollment_password()
    install_new_agent(ip, name, pw)
    del pw
    return ip

def setup_suricata(manager):
    if not shutil.which("apt-get"):
        fail("Mandatory Suricata: apt not available")
    fresh = not shutil.which("suricata")
    if fresh:
        run("apt-get", "update")
        run("apt-get", "install", "-y", "suricata", "suricata-update")
    if not SURICATA.is_file():
        fail("Suricata config missing")
    if fresh:
        if shutil.which("suricata-update"):
            run("suricata-update")
        route = subprocess.run(["ip", "-j", "route", "get", manager], check=True, capture_output=True, text=True)
        nic = json.loads(route.stdout)[0].get("dev")
        if not nic:
            fail("Cannot determine Suricata network interface")
        addresses = subprocess.run(["ip", "-j", "address", "show", "dev", nic], check=True, capture_output=True, text=True)
        networks = [str(ipaddress.ip_network(info["local"] + "/" + str(info["prefixlen"]), strict=False))
                    for entry in json.loads(addresses.stdout)
                    for info in entry.get("addr_info", [])
                    if info.get("family") == "inet" and info.get("scope") == "global"]
        if len(networks) != 1:
            fail("Ambiguous local IPv4 network for Suricata HOME_NET")
        before = SURICATA.read_text()
        matches = re.findall(r"(?m)^\s+HOME_NET\s*:.*$", before)
        if len(matches) != 1:
            fail("Could not safely update Suricata HOME_NET")
        after = before.replace(matches[0], '    HOME_NET: "[' + networks[0] + ']"', 1)
        backup_replace(SURICATA, before, after)
        defaults = Path("/etc/default/suricata")
        if defaults.is_file():
            old = defaults.read_text()
            pattern = re.compile(r"(?m)^IFACE=.*$")
            if len(pattern.findall(old)) == 1:
                backup_replace(defaults, old, pattern.sub("IFACE=" + nic, old, count=1))
        print("SURICATA_INTERFACE:", nic, "HOME_NET:", networks[0])
    run("suricata", "-T", "-c", str(SURICATA))
    run("systemctl", "enable", "--now", "suricata")
    if fresh:
        run("systemctl", "restart", "suricata")
    if not service("suricata") or not EVE.is_file():
        fail("Suricata not active or eve.json missing; check capture interface and EVE config")
    print("SURICATA_OK:", EVE)

def setup_wazuh_localfile():
    before = AGENT.read_text(encoding="utf-8-sig")
    after = add_suricata_localfile(before)
    if backup_replace(AGENT, before, after):
        try:
            run("systemctl", "restart", "wazuh-agent")
        except subprocess.CalledProcessError:
            print("Reverting ossec.conf after restart failure", file=sys.stderr)
            backup_replace(AGENT, after, before)
            run("systemctl", "restart", "wazuh-agent", check=False)
            raise
    if not service("wazuh-agent"):
        fail("Wazuh Agent service not active after config change")
    print("WAZUH_LOCALFILE_OK:", EVE)

def verify():
    if not AGENT.is_file():
        fail("Wazuh Agent missing")
    ip = manager_from(AGENT.read_text(encoding="utf-8-sig"))
    if not service("wazuh-agent"):
        fail("Wazuh Agent service stopped")
    if not service("suricata") or not EVE.is_file():
        fail("Mandatory Suricata/EVE missing")
    if not has_suricata_localfile(AGENT.read_text(encoding="utf-8-sig")):
        fail("Wazuh Agent not configured to collect Suricata JSON")
    if not enrolled():
        fail("No client.keys yet; enrollment/password/Manager may still need attention")
    print("AGENT_SETUP_OK: Wazuh+Suricata present, Manager=" + ip)
    print("NOTE: Manager-side Active status and actual log ingestion require E2E checks")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--apply", action="store_true")
    modes.add_argument("--dry-run", action="store_true")
    modes.add_argument("--verify", action="store_true")
    parser.add_argument("--manager-ip")
    parser.add_argument("--agent-name")
    parser.add_argument("--repoint-existing", action="store_true")
    args = parser.parse_args()
    if args.manager_ip:
        try:
            if ipaddress.ip_address(args.manager_ip).version != 4:
                fail("Manager must be IPv4")
        except ValueError:
            fail("Invalid Manager IPv4")
    if args.dry_run:
        print("PREVIEW_AGENT: Agent 4.8.2 if missing; mandatory Suricata; automatic eve.json ossec.conf")
        print("MANAGER:", args.manager_ip or ("from ossec.conf if Agent exists, else " + DEFAULT_MANAGER))
        print("NO_CHANGES: name/password only requested for unregistered Agent on --apply")
        return
    if args.verify:
        verify()
        return
    if os.geteuid() != 0:
        fail("Run --apply with sudo/root")
    ip = ensure_agent(args)
    setup_suricata(ip)
    setup_wazuh_localfile()
    # Enrollment is asynchronous; wait briefly for a real client.keys rather
    # than assuming systemctl 'active' means Agent enrollment succeeded.
    if not enrolled():
        for _ in range(30):
            if enrolled():
                break
            time.sleep(1)
    verify()
    print("PREPARE_OK: ready to install Active Response scripts (no defense dispatched)")

if __name__ == "__main__":
    main()
