#!/usr/bin/env bash
# Explicit opt-in agent-only installer. Dry-run by default; never alters firewall.
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="/var/ossec/active-response/bin"
EVIDENCE="/var/ossec/logs/ai-soc-verification.json"
STATE="/var/lib/ai-soc-isolation/active_execution"

MODE="preview"
WITH_KILL_PROCESS=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) MODE="preview" ;;
    --apply) MODE="apply" ;;
    --with-kill-process) WITH_KILL_PROCESS=1 ;;
    *) printf 'Usage: bash scripts/install.sh [--dry-run|--apply] [--with-kill-process]\n' >&2; exit 2 ;;
  esac
done

command -v bash >/dev/null && command -v python3 >/dev/null || {
  echo "Requires bash and Python 3" >&2
  exit 1
}
for f in block-ip.py isolate.sh ai_soc_evidence.py kill-process0 kill-process-safe.py; do
  [[ -f "$ROOT/active-response/$f" ]] || { echo "Missing source $f" >&2; exit 1; }
done
bash -n "$ROOT/active-response/isolate.sh"
python3 - "$ROOT/active-response/block-ip.py" "$ROOT/active-response/ai_soc_evidence.py" "$ROOT/active-response/kill-process0" "$ROOT/active-response/kill-process-safe.py" <<'PY'
import pathlib,sys
for name in sys.argv[1:]:
    compile(pathlib.Path(name).read_bytes(),name,"exec")
PY

echo "Mode: $MODE"
echo "Source: $ROOT/active-response"
echo "Destination: $DEST"
echo "Evidence file: $EVIDENCE"
if [[ "$WITH_KILL_PROCESS" == 1 ]]; then
  echo "Kill Process: opt-in hardened script selected; requires a root-owned nonempty allowlist"
else
  echo "Kill Process: legacy source archived, not installed (use --with-kill-process)"
fi

if [[ "$MODE" != "apply" ]]; then
  echo "No changes made. Use --apply only on an authorized Wazuh Agent."
  exit 0
fi

[[ "$(id -u)" -eq 0 ]] || { echo "Requires root for --apply" >&2; exit 1; }
[[ -d "$DEST" && -f /var/ossec/etc/ossec.conf ]] || {
  echo "Wazuh Agent missing at /var/ossec; refusing" >&2; exit 1;
}
[[ ! -e "$STATE" ]] || { echo "Active isolation detected; refusing" >&2; exit 1; }
[[ ! -L "$EVIDENCE" ]] || { echo "Evidence file symlink detected; refusing" >&2; exit 1; }
getent group wazuh >/dev/null || { echo "Missing wazuh group" >&2; exit 1; }
for tool in flock ss iptables ip6tables iptables-save ip6tables-save systemctl systemd-run; do
  command -v "$tool" >/dev/null || { echo "Missing dependency: $tool" >&2; exit 1; }
done
if iptables-save | grep -qE 'AI_SOC_ISO_(IN|OUT|FWD)'; then
  echo "Existing AI-SOC IPv4 isolation firewall state; refusing" >&2; exit 1
fi
if ip6tables-save | grep -qE 'AI_SOC_ISO6_(IN|OUT|FWD)'; then
  echo "Existing AI-SOC IPv6 isolation firewall state; refusing" >&2; exit 1
fi

# Require one static IPv4 Wazuh Manager at TCP 1514 so isolation can
# preserve its real control channel. No hardcoded IP or silent DNS fallback.
python3 - /var/ossec/etc/ossec.conf <<'PY'
from pathlib import Path
import ipaddress,re,sys,xml.etree.ElementTree as ET
data=Path(sys.argv[1]).read_text(encoding="utf-8-sig")
data=re.sub(r"^\s*<\?xml[^>]*\?>","",data,count=1)
servers=ET.fromstring("<bundle>"+data+"</bundle>").findall("./ossec_config/client/server")
if len(servers) != 1:
    raise SystemExit("Exactly one Wazuh Manager is required before --apply")
s=servers[0]
host=(s.findtext("address") or "").strip()
port=(s.findtext("port") or "1514").strip()
protocol=(s.findtext("protocol") or "tcp").strip().lower()
try:
    ip=ipaddress.ip_address(host)
except ValueError:
    raise SystemExit("Wazuh Manager must be a static IPv4 address (not DNS)")
if ip.version != 4 or port != "1514" or protocol != "tcp":
    raise SystemExit("Wazuh Manager must be one static IPv4 on TCP 1514")
print("MANAGER_OK:",host)
PY

# Never replace a live kill-process0 with legacy code. The operator must
# explicitly choose the hardened variant and provision a strict policy first.
if [[ "$WITH_KILL_PROCESS" == 1 ]]; then
  python3 -c 'import os, signal; assert hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"), "Kernel/Python PIDFD support required"'
  python3 "$ROOT/active-response/kill-process-safe.py" --check-policy
fi

if [[ -e "$EVIDENCE" ]]; then
  [[ -f "$EVIDENCE" && "$(stat -c '%u:%G:%a' "$EVIDENCE")" == "0:wazuh:640" ]] || {
    echo "Existing evidence ledger ownership/mode is unsafe; refusing to modify" >&2
    exit 1
  }
else
  install -o root -g wazuh -m 0640 /dev/null "$EVIDENCE"
fi

stamp="$(date -u +%Y%m%dT%H%M%S)-$$"
for f in block-ip.py isolate.sh ai_soc_evidence.py; do
  dest="$DEST/$f"
  tmp="$DEST/.$f.install-$stamp"
  [[ ! -L "$dest" ]] || { echo "Refusing destination symlink: $dest" >&2; exit 1; }
  if [[ -e "$dest" ]]; then
    cp -a -- "$dest" "$dest.bak-$stamp"
    echo "Backup: $dest.bak-$stamp"
  fi
  install -o root -g root -m 0750 "$ROOT/active-response/$f" "$tmp"
  mv -f -- "$tmp" "$dest"
  echo "Installed: $dest"
done
if [[ "$WITH_KILL_PROCESS" == 1 ]]; then
  dest="$DEST/kill-process0"
  tmp="$DEST/.kill-process0.install-$stamp"
  [[ ! -L "$dest" ]] || { echo "Refusing destination symlink: $dest" >&2; exit 1; }
  if [[ -e "$dest" ]]; then
    cp -a -- "$dest" "$dest.bak-$stamp"
    echo "Backup: $dest.bak-$stamp"
  fi
  install -o root -g wazuh -m 0750 "$ROOT/active-response/kill-process-safe.py" "$tmp"
  mv -f -- "$tmp" "$dest"
  echo "Installed hardened Kill Process: $dest"
fi
echo "File installation completed. No firewall action, Wazuh restart or Manager config change."
