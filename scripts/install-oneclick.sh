#!/usr/bin/env bash
# AI-SOC Linux Agent one-click installer; never sends Active Response.
set -Eeuo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
DEST=/var/ossec/active-response/bin
POLICY=/var/ossec/etc/ai-soc/kill-process-policy.json
MODE=preview
KILL=0
ALLOW=''

usage() {
  cat <<'HELP'
Usage: bash scripts/install-oneclick.sh [--dry-run|--apply|--verify]
                                        [--with-kill-process [--allow-process NAME]]
  --dry-run            Preview without changing the Agent (default).
  --apply              Install Block IP, Isolate Host and JSONL evidence writer.
  --verify             Compare installed files and permissions to repository.
  --with-kill-process  Additionally install hardened kill-process0 (opt-in).
  --allow-process NAME Create a NEW root-owned allowlist for one lab process.
                       Otherwise an existing approved policy is required.
HELP
}
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
root_only() { [[ "$(id -u)" == 0 ]] || fail 'Run with sudo/root.'; }
while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --dry-run) MODE=preview ;;
    --apply) MODE=apply ;;
    --verify) MODE=verify ;;
    --with-kill-process) KILL=1 ;;
    --allow-process) (($# > 1)) || fail 'Missing process name'; ALLOW="$2"; shift ;;
    *) usage >&2; printf 'Unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
  shift
done
[[ -f "$ROOT/scripts/install.sh" ]] || fail 'Missing canonical Linux installer.'
[[ -f "$ROOT/active-response/kill-process-safe.py" ]] || fail 'Missing hardened Kill Process source.'
[[ -z "$ALLOW" || "$KILL" == 1 ]] || fail '--allow-process is only valid together with --with-kill-process'
bash -n "$ROOT/scripts/install.sh"
bash -n "$ROOT/active-response/isolate.sh"

validate_name() {
  [[ -z "$ALLOW" ]] && return 0
  python3 - "$ROOT/active-response/kill-process-safe.py" "$ALLOW" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location('aisoc_kill',sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.validate_policy_document({'allowed_process_names':[sys.argv[2]]})
print('ALLOWLIST_OK:',sys.argv[2])
PY
}
verify_install() {
  root_only
  for f in block-ip.py isolate.sh ai_soc_evidence.py; do
    [[ -f "$DEST/$f" && ! -L "$DEST/$f" ]] || fail "Missing/symlinked: $f"
    cmp -s "$ROOT/active-response/$f" "$DEST/$f" || fail "Content differs: $f"
    [[ "$(stat -c '%U:%G:%a' "$DEST/$f")" == 'root:root:750' ]] || fail "Bad mode/owner: $f"
  done
  local ev=/var/ossec/logs/ai-soc-verification.json
  [[ -f "$ev" && ! -L "$ev" ]] || fail 'Evidence file is missing/symlinked'
  [[ "$(stat -c '%U:%G:%a' "$ev")" == 'root:wazuh:640' ]] || fail 'Unsafe evidence permissions'
  if ((KILL)); then
    cmp -s "$ROOT/active-response/kill-process-safe.py" "$DEST/kill-process0" || fail 'Hardened kill-process0 missing/mismatched'
    [[ ! -L "$DEST/kill-process0" ]] || fail 'Symlinked kill-process0'
    [[ "$(stat -c '%U:%G:%a' "$DEST/kill-process0")" == 'root:wazuh:750' ]] || fail 'Unsafe kill-process0 permissions'
    python3 "$ROOT/active-response/kill-process-safe.py" --check-policy
  fi
  echo 'VERIFY_OK: installed files and permissions match.'
}
create_policy() {
  [[ -z "$ALLOW" ]] && return 0
  root_only
  [[ -d "$DEST" && -f /var/ossec/etc/ossec.conf ]] || fail 'Wazuh Agent missing'
  [[ ! -e /var/lib/ai-soc-isolation/active_execution ]] || fail 'Active isolation present'
  [[ ! -e "$POLICY" && ! -L "$POLICY" ]] || fail 'Existing policy must never be overwritten'
  local dir
  dir="$(dirname "$POLICY")"
  [[ ! -L "$dir" ]] || fail 'Policy directory is a symlink'
  if [[ -e "$dir" ]]; then
    [[ -d "$dir" && "$(stat -c '%U:%a' "$dir")" =~ ^root:(700|750)$ ]] || fail 'Unsafe policy directory'
  else
    install -d -o root -g root -m 0750 "$dir"
  fi
  python3 - "$POLICY" "$ALLOW" <<'PY'
import json,os,sys
payload=(json.dumps({'allowed_process_names':[sys.argv[2]]})+'\n').encode()
fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o640)
try:
    with os.fdopen(fd,'wb') as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())
except:
    raise
print('Created lab allowlist policy:',sys.argv[1])
PY
}
validate_name
if [[ "$MODE" == verify ]]; then verify_install; exit 0; fi
if [[ "$MODE" == preview ]]; then
  if ((KILL)); then
    bash "$ROOT/scripts/install.sh" --dry-run --with-kill-process
    [[ -z "$ALLOW" ]] || echo "Would create allowlist for lab process: $ALLOW"
  else
    bash "$ROOT/scripts/install.sh" --dry-run
  fi
  echo 'PREVIEW_OK: endpoint was not modified.'
  exit 0
fi
root_only
if ((KILL)); then
  create_policy
  bash "$ROOT/scripts/install.sh" --apply --with-kill-process
else
  bash "$ROOT/scripts/install.sh" --apply
fi
verify_install
echo 'INSTALL_OK: Agent scripts installed; no AR command dispatched.'
echo 'Manager command registration and ai-soc-linux JSONL collection are separate.'
