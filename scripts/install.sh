#!/usr/bin/env bash
# Explicit opt-in agent-only installer. Dry-run by default; never alters firewall.
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="/var/ossec/active-response/bin"
EVIDENCE="/var/ossec/logs/ai-soc-verification.json"
STATE="/var/lib/ai-soc-isolation/active_execution"

case "${1:---dry-run}" in
  --dry-run) MODE="preview" ;;
  --apply) MODE="apply" ;;
  *) printf 'Usage: bash scripts/install.sh [--dry-run|--apply]\n' >&2; exit 2 ;;
esac

command -v bash >/dev/null && command -v python3 >/dev/null || {
  echo "Requires bash and Python 3" >&2
  exit 1
}
for f in block-ip.py isolate.sh ai_soc_evidence.py kill-process0; do
  [[ -f "$ROOT/active-response/$f" ]] || { echo "Missing source $f" >&2; exit 1; }
done
bash -n "$ROOT/active-response/isolate.sh"
python3 - "$ROOT/active-response/block-ip.py" "$ROOT/active-response/ai_soc_evidence.py" "$ROOT/active-response/kill-process0" <<'PY'
import pathlib,sys
for name in sys.argv[1:]:
    compile(pathlib.Path(name).read_bytes(),name,"exec")
PY

echo "Mode: $MODE"
echo "Source: $ROOT/active-response"
echo "Destination: $DEST"
echo "Evidence file: $EVIDENCE"
echo "Legacy kill-process0: bundled for review but intentionally NOT installed (security hardening pending)"

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

# The current script has a lab-default Manager IP; never install silently
# when the Wazuh Agent points at another Manager or uses DNS/UDP.
python3 - /var/ossec/etc/ossec.conf "$ROOT/active-response/isolate.sh" <<'PY'
from pathlib import Path
import re,sys,xml.etree.ElementTree as ET

data=Path(sys.argv[1]).read_text(encoding="utf-8-sig")
data=re.sub(r"^\s*<\?xml[^>]*\?>","",data,count=1)
servers=ET.fromstring("<bundle>"+data+"</bundle>").findall("./ossec_config/client/server")
actual=[((s.findtext("address") or "").strip(),
         (s.findtext("port") or "1514").strip(),
         (s.findtext("protocol") or "tcp").strip().lower()) for s in servers]
script=Path(sys.argv[2]).read_text()
match=re.search(r"AI_SOC_WAZUH_MANAGER_IP:-([0-9.]+)",script)
if not match or actual != [(match.group(1),"1514","tcp")]:
    raise SystemExit("Manager IP/protocol mismatch: review isolate.sh defaults before --apply")
PY

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
echo "File installation completed. No firewall action, Wazuh restart or Manager config change."
