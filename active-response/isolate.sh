#!/usr/bin/env bash
# AI-SOC Linux host isolation Active Response.
# Dedicated IPv4/IPv6 chains, persistent execution state, fenced safety TTL,
# reboot recovery and V1.13 endpoint evidence. Never changes default policies.
set -Eeuo pipefail
umask 077

INPUT_CHAIN="AI_SOC_ISO_IN"
OUTPUT_CHAIN="AI_SOC_ISO_OUT"
FORWARD_CHAIN="AI_SOC_ISO_FWD"
IP6_INPUT_CHAIN="AI_SOC_ISO6_IN"
IP6_OUTPUT_CHAIN="AI_SOC_ISO6_OUT"
IP6_FORWARD_CHAIN="AI_SOC_ISO6_FWD"
WAZUH_MANAGER_IP="${AI_SOC_WAZUH_MANAGER_IP:-192.168.100.192}"
WAZUH_MANAGER_PORT="${AI_SOC_WAZUH_MANAGER_PORT:-1514}"
ISOLATION_TIMEOUT_SECONDS="${AI_SOC_ISOLATION_TIMEOUT_SECONDS:-900}"
MIN_TTL_SECONDS=60
MAX_TTL_SECONDS=3600
STATE_DIR="${AI_SOC_ISOLATE_STATE_DIR:-/var/lib/ai-soc-isolation}"
EXECUTIONS_DIR="${STATE_DIR}/executions"
ACTIVE_FILE="${STATE_DIR}/active_execution"
LOCK_DIR="${AI_SOC_ISOLATE_RUN_DIR:-/run/ai-soc-isolation}"
LOCK_FILE="${LOCK_DIR}/lock"
AGENT_CONFIG="${AI_SOC_WAZUH_AGENT_CONFIG:-/var/ossec/etc/ossec.conf}"
BOOT_ID_FILE="${AI_SOC_BOOT_ID_FILE:-/proc/sys/kernel/random/boot_id}"
EVIDENCE_WRITER="${AI_SOC_EVIDENCE_WRITER:-/var/ossec/active-response/bin/ai_soc_evidence.py}"
LOG_FILE="${AI_SOC_ACTIVE_RESPONSE_LOG:-/var/ossec/logs/active-responses.log}"
IPTABLES_BIN="${AI_SOC_IPTABLES_BIN:-$(command -v iptables || true)}"
IP6TABLES_BIN="${AI_SOC_IP6TABLES_BIN:-$(command -v ip6tables || true)}"
IPTABLES_SAVE_BIN="${AI_SOC_IPTABLES_SAVE_BIN:-$(command -v iptables-save || true)}"
IP6TABLES_SAVE_BIN="${AI_SOC_IP6TABLES_SAVE_BIN:-$(command -v ip6tables-save || true)}"
SS_BIN="${AI_SOC_SS_BIN:-$(command -v ss || true)}"
SYSTEMCTL_BIN="${AI_SOC_SYSTEMCTL_BIN:-$(command -v systemctl || true)}"
SYSTEMD_RUN_BIN="${AI_SOC_SYSTEMD_RUN_BIN:-$(command -v systemd-run || true)}"
SCRIPT_PATH="$(readlink -f -- "${BASH_SOURCE[0]}")"
FIREWALL_OWNERSHIP_CONFIRMED=0
CREATED_CHAIN_SPECS=()
BOOT_CHECK_UNIT="${AI_SOC_ISOLATE_BOOT_CHECK_UNIT:-/etc/systemd/system/ai-soc-isolation-boot-check.service}"
BOOT_CHECK_UNIT_NAME="ai-soc-isolation-boot-check.service"

log_message() {
    printf '%s ai-soc-isolate: %s\n' "$(date --iso-8601=seconds 2>/dev/null || date)" "$1" \
        >>"$LOG_FILE" 2>/dev/null || true
}

fail() {
    log_message "ERROR: $1"
    printf 'AI-SOC isolate: %s\n' "$1" >&2
    return 1
}

require_firewall_tools() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || fail "must run as root" || return 1
    command -v python3 >/dev/null 2>&1 || fail "python3 is required" || return 1
    command -v flock >/dev/null 2>&1 || fail "flock is required for serialized state changes" || return 1
    [[ -n "$IPTABLES_BIN" && -x "$IPTABLES_BIN" ]] || fail "iptables is not executable" || return 1
    [[ -n "$IP6TABLES_BIN" && -x "$IP6TABLES_BIN" ]] || fail "ip6tables is required to prevent IPv6 bypass" || return 1
    [[ -r "$BOOT_ID_FILE" ]] || fail "kernel boot_id is unavailable" || return 1
}

require_root_and_tools() {
    require_firewall_tools || return 1
    [[ -n "$IPTABLES_SAVE_BIN" && -x "$IPTABLES_SAVE_BIN" ]] || fail "iptables-save is required for firewall baseline" || return 1
    [[ -n "$IP6TABLES_SAVE_BIN" && -x "$IP6TABLES_SAVE_BIN" ]] || fail "ip6tables-save is required for firewall baseline" || return 1
    [[ -n "$SS_BIN" && -x "$SS_BIN" ]] || fail "ss is required for listener and Manager-channel snapshots" || return 1
    [[ -n "$SYSTEMCTL_BIN" && -x "$SYSTEMCTL_BIN" ]] || fail "systemctl is required for reboot recovery" || return 1
    [[ -n "$SYSTEMD_RUN_BIN" && -x "$SYSTEMD_RUN_BIN" ]] || fail "systemd-run is required for independent safety TTL" || return 1
}

validate_ttl() {
    local ttl="$1"
    [[ "$ttl" =~ ^[0-9]+$ ]] && (( ttl >= MIN_TTL_SECONDS && ttl <= MAX_TTL_SECONDS )) || {
        fail "TTL must be between ${MIN_TTL_SECONDS} and ${MAX_TTL_SECONDS} seconds"
        return 1
    }
}

validate_manager_settings() {
    python3 - "$WAZUH_MANAGER_IP" "$WAZUH_MANAGER_PORT" "$AGENT_CONFIG" <<'PY'
import ipaddress, re, sys, xml.etree.ElementTree as ET
manager, port, path = sys.argv[1:]
try:
    address = ipaddress.ip_address(manager)
except ValueError:
    raise SystemExit("AI_SOC_WAZUH_MANAGER_IP must be a literal IPv4 address; DNS is unsafe during isolation")
if address.version != 4:
    raise SystemExit("the configured Wazuh Manager channel must use the approved IPv4 address")
if not port.isdigit() or not 1 <= int(port) <= 65535:
    raise SystemExit("invalid Wazuh Manager TCP port")
try:
    data = open(path, encoding="utf-8-sig").read()
    data = re.sub(r"^\s*<\?xml[^>]*\?>", "", data, count=1)
    root = ET.fromstring("<wazuh_bundle>" + data + "</wazuh_bundle>")
except Exception as exc:
    raise SystemExit("cannot parse Wazuh Agent ossec.conf: {}".format(exc))
servers = root.findall("./ossec_config/client/server")
if not servers:
    raise SystemExit("Wazuh Agent ossec.conf has no client/server address; refusing DNS or unknown Manager routing")
addresses = [((s.findtext("address") or "").strip(),
              (s.findtext("port") or "1514").strip(),
              (s.findtext("protocol") or "tcp").strip().lower()) for s in servers]
if addresses != [(manager, port, "tcp")]:
    raise SystemExit("Wazuh Agent must use only the configured static Manager IPv4/TCP address; found {}".format(addresses))
PY
}

acquire_lock() {
    mkdir -p "$LOCK_DIR" "$STATE_DIR" "$EXECUTIONS_DIR" || fail "cannot create state/lock directories" || return 1
    chmod 700 "$LOCK_DIR" "$STATE_DIR" "$EXECUTIONS_DIR" || return 1
    exec 9>"$LOCK_FILE"
    flock -x 9 || fail "cannot acquire isolation state lock" || return 1
}

get_boot_id() {
    local value
    value="$(tr -d '\r\n' <"$BOOT_ID_FILE")"
    python3 -c 'import sys,uuid; uuid.UUID(sys.argv[1])' "$value" >/dev/null 2>&1 || {
        fail "invalid boot_id from ${BOOT_ID_FILE}"
        return 1
    }
    printf '%s' "$value"
}

parse_request() {
    # Wazuh Active Response sends arguments in parameters.extra_args via STDIN.
    # Never assume those values arrive as shell positional parameters.
    python3 -c '
import json, re, sys
try:
    d=json.load(sys.stdin)
    command=d.get("command", "")
    p=d.get("parameters") or {}
    extra=p.get("extra_args") or []
    if not isinstance(extra, list) or not all(isinstance(x,str) for x in extra):
        raise ValueError("parameters.extra_args must be a string array")
    values={}
    mode=""
    i=0
    while i < len(extra):
        item=extra[i]
        if item in ("--rollback", "--renew", "--check-boot", "--inspect"):
            mode=item[2:]
            i += 1
        elif item.startswith("--") and "=" in item:
            k,v=item[2:].split("=",1); values[k]=v; i += 1
        elif item.startswith("--"):
            k=item[2:]
            if i+1 >= len(extra): raise ValueError("missing value for " + item)
            values[k]=extra[i+1]; i += 2
        else:
            i += 1
    alert=(d.get("alert") or {}).get("data") or {}
    target=alert.get("srcip") or alert.get("dstip") or ""
    fields=[command,mode,values.get("execution-id", ""),values.get("plan-id", ""),values.get("action-id", ""),values.get("ttl", ""),str(target)]
    if any("\n" in x or "\r" in x for x in fields): raise ValueError("newline in request field")
    print("\n".join(fields))
except Exception as exc:
    print("invalid Active Response JSON: {}".format(exc), file=sys.stderr)
    raise SystemExit(2)
'
}

state_file_for() {
    local execution_id="$1"
    [[ "$execution_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || return 1
    printf '%s/%s.json' "$EXECUTIONS_DIR" "${execution_id,,}"
}

state_get() {
    local file="$1" field="$2"
    python3 - "$file" "$field" <<'PY'
import json,sys
try:
    with open(sys.argv[1], encoding="utf-8") as f: d=json.load(f)
    v=d.get(sys.argv[2], "")
    if isinstance(v, (dict,list)): print(json.dumps(v,separators=(",",":")))
    elif v is None: print("")
    else: print(v)
except Exception:
    raise SystemExit(1)
PY
}

write_state() {
    local file="$1" status="$2" execution_id="$3" plan_id="$4" action_id="$5"
    local generation="$6" timer_unit="$7" ttl="$8" boot_id="$9" expires_at="${10}"
    local pre_state="${11}" post_state="${12}" rollback_reason="${13:-}" target="${14:-}"
    python3 - "$file" "$status" "$execution_id" "$plan_id" "$action_id" "$generation" "$timer_unit" "$ttl" "$boot_id" "$expires_at" "$pre_state" "$post_state" "$rollback_reason" "$target" <<'PY'
import json, os, sys, tempfile
(path,status,execution,plan,action,generation,timer,ttl,boot,expires,pre,post,reason,target)=sys.argv[1:]
d={}
if os.path.exists(path):
    with open(path,encoding="utf-8") as f: d=json.load(f)
d.update({"schema_version":"1.0","status":status,"execution_id":execution,"plan_id":plan,"action_id":action,
          "generation":generation,"timer_unit":timer,"ttl_seconds":int(ttl) if ttl else 0,"boot_id":boot,
          "isolation_expires_at":expires or None,"pre_state":json.loads(pre) if pre else None,
          "post_state":json.loads(post) if post else None,"rollback_reason":reason or None,"target":target or d.get("target")})
fd,tmp=tempfile.mkstemp(prefix=".state-",dir=os.path.dirname(path))
try:
    with os.fdopen(fd,"w",encoding="utf-8") as f:
        json.dump(d,f,ensure_ascii=False,separators=(",",":")); f.write("\n"); f.flush(); os.fsync(f.fileno())
    os.chmod(tmp,0o600); os.replace(tmp,path)
    dfd=os.open(os.path.dirname(path),os.O_DIRECTORY); os.fsync(dfd); os.close(dfd)
finally:
    if os.path.exists(tmp): os.unlink(tmp)
PY
}

random_uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }

capture_state() {
    python3 - "$BOOT_ID_FILE" "$SS_BIN" "$IPTABLES_SAVE_BIN" "$IP6TABLES_SAVE_BIN" "$WAZUH_MANAGER_IP" "$WAZUH_MANAGER_PORT" <<'PY'
import datetime, hashlib, ipaddress, json, shlex, subprocess, sys
boot, ss, v4save, v6save, manager, port = sys.argv[1:]

def run(args):
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=8, check=False)
        return p.returncode, p.stdout
    except Exception:
        return 127, ""

def endpoint(value):
    value = value.strip()
    if value.startswith("[") and "]:" in value:
        host, raw_port = value[1:].rsplit("]:", 1)
    elif ":" in value:
        host, raw_port = value.rsplit(":", 1)
    else:
        return None
    try:
        return str(ipaddress.ip_address(host.split("%", 1)[0])), int(raw_port)
    except ValueError:
        return None

with open(boot, encoding="ascii") as f:
    boot_id = f.read().strip()
rc, ssout = run([ss, "-H", "-tn", "state", "established"])
connections = []
if rc == 0:
    for line in ssout.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        local, remote = endpoint(fields[-2]), endpoint(fields[-1])
        if local and remote and remote[0] == manager and remote[1] == int(port):
            connections.append({"local_ip": local[0], "local_port": local[1],
                                "remote_ip": remote[0], "remote_port": remote[1]})
rc, listenout = run([ss, "-H", "-ltn"])
ports = []
if rc == 0:
    for line in listenout.splitlines():
        fields = line.split()
        if len(fields) >= 4:
            ep = endpoint(fields[-2])
            if ep:
                ports.append(ep[1])


def firewall(save, chain_names, hooks):
    rc, output = run([save])
    if rc != 0:
        return {"available": False}
    defined = set()
    policies = {}
    chain_rules = {name: [] for name in chain_names}
    hook_rules = {name: [] for name in hooks}
    for line in output.splitlines():
        if line.startswith(":"):
            fields = line[1:].split()
            if fields:
                defined.add(fields[0])
                if fields[0] in hooks and len(fields) >= 2:
                    policies[fields[0]] = fields[1]
            continue
        if not line.startswith("-A "):
            continue
        try:
            fields = shlex.split(line)
        except ValueError:
            continue
        if len(fields) < 3:
            continue
        chain = fields[1]
        rule = fields[2:]
        if chain in chain_rules:
            chain_rules[chain].append(rule)
        if chain in hook_rules:
            hook_rules[chain].append(rule)
    owned_chains = {name: name in defined for name in chain_names}
    # JSON strings preserve exact rule tokens while keeping endpoint evidence
    # compatible with Chat 4's JSONL writer (no arrays of arrays/objects).
    chain_rules_flat = {name: json.dumps(rules, separators=(",", ":")) for name, rules in chain_rules.items()}
    hook_rules_flat = {name: json.dumps(rules, separators=(",", ":")) for name, rules in hook_rules.items()}
    owned_jumps = {}
    for hook, chain in hooks.items():
        # Detect unconditional and conditional references to a reserved chain.
        owned_jumps[hook + "->" + chain] = any(
            any(rule[index] in ("-j", "--jump") and index + 1 < len(rule) and rule[index + 1] == chain
                for index in range(len(rule)))
            for rule in hook_rules.get(hook, [])
        )
    return {
        "available": True,
        "rules_sha256": hashlib.sha256(output.encode()).hexdigest(),
        "rule_count": sum(1 for line in output.splitlines() if line.startswith(("-A ", "-P "))),
        "policies": policies,
        "owned_chains": owned_chains,
        "owned_jumps": owned_jumps,
        "chain_rules_json": chain_rules_flat,
        "hook_rules_json": hook_rules_flat,
    }

v4_names = ["AI_SOC_ISO_IN", "AI_SOC_ISO_OUT", "AI_SOC_ISO_FWD"]
v6_names = ["AI_SOC_ISO6_IN", "AI_SOC_ISO6_OUT", "AI_SOC_ISO6_FWD"]
v4_hooks = {"INPUT": v4_names[0], "OUTPUT": v4_names[1], "FORWARD": v4_names[2]}
v6_hooks = {"INPUT": v6_names[0], "OUTPUT": v6_names[1], "FORWARD": v6_names[2]}
state = {
    "boot_id": boot_id,
    "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    "listening_tcp_ports": sorted(set(ports)),
    "manager_tcp_connection_reachable": bool(connections),
    "manager_connections_count": len(connections),
    "manager_connection_local_ip": connections[0]["local_ip"] if connections else None,
    "manager_connection_local_port": connections[0]["local_port"] if connections else None,
    "manager_connection_remote_ip": connections[0]["remote_ip"] if connections else None,
    "manager_connection_remote_port": connections[0]["remote_port"] if connections else None,
    "ipv4_firewall": firewall(v4save, v4_names, v4_hooks),
    "ipv6_firewall": firewall(v6save, v6_names, v6_hooks),
}
print(json.dumps(state, separators=(",", ":")))
PY
}

install_boot_check() {
    local content
    if [[ -e "$BOOT_CHECK_UNIT" ]] && ! grep -q 'X-AI-SOC-Isolation-Boot-Check=yes' "$BOOT_CHECK_UNIT"; then
        fail "${BOOT_CHECK_UNIT} exists but is not owned by AI-SOC; refusing to overwrite"
        return 1
    fi
    content="[Unit]
Description=AI-SOC isolation reboot safety reconciliation
X-AI-SOC-Isolation-Boot-Check=yes
Wants=network-online.target wazuh-agent.service
After=network-online.target wazuh-agent.service

[Service]
Type=oneshot
ExecStart=${SCRIPT_PATH} --check-boot

[Install]
WantedBy=multi-user.target
"
    printf '%s' "$content" >"$BOOT_CHECK_UNIT" || return 1
    chmod 644 "$BOOT_CHECK_UNIT" || return 1
    "$SYSTEMCTL_BIN" daemon-reload || return 1
    "$SYSTEMCTL_BIN" enable "$BOOT_CHECK_UNIT_NAME" >/dev/null || return 1
}

stop_timer_unit() {
    local unit="$1"
    [[ "$unit" =~ ^ai-soc-isolate-[0-9a-f]{32}$ ]] || return 0
    [[ -n "$SYSTEMCTL_BIN" && -x "$SYSTEMCTL_BIN" ]] || return 0
    "$SYSTEMCTL_BIN" stop "${unit}.timer" "${unit}.service" >/dev/null 2>&1 || true
    "$SYSTEMCTL_BIN" reset-failed "${unit}.timer" "${unit}.service" >/dev/null 2>&1 || true
}

start_expiry_timer() {
    local seconds="$1" execution_id="$2" generation="$3" unit="$4"
    "$SYSTEMD_RUN_BIN" --quiet --collect --unit="$unit" \
        --on-active="${seconds}s" --timer-property=AccuracySec=1s \
        "$SCRIPT_PATH" --expire-now "$execution_id" "$generation"
}

remove_jump() {
    local binary="$1" hook="$2" chain="$3"
    while "$binary" -w 5 -C "$hook" -j "$chain" >/dev/null 2>&1; do
        "$binary" -w 5 -D "$hook" -j "$chain" >/dev/null 2>&1 || break
    done
}

remove_chain() {
    local binary="$1" chain="$2"
    if "$binary" -w 5 -S "$chain" >/dev/null 2>&1; then
        "$binary" -w 5 -F "$chain" >/dev/null 2>&1 || return 1
        "$binary" -w 5 -X "$chain" >/dev/null 2>&1 || return 1
    fi
}

rollback_firewall() {
    remove_jump "$IPTABLES_BIN" OUTPUT "$OUTPUT_CHAIN"
    remove_jump "$IPTABLES_BIN" INPUT "$INPUT_CHAIN"
    remove_jump "$IPTABLES_BIN" FORWARD "$FORWARD_CHAIN"
    remove_jump "$IP6TABLES_BIN" OUTPUT "$IP6_OUTPUT_CHAIN"
    remove_jump "$IP6TABLES_BIN" INPUT "$IP6_INPUT_CHAIN"
    remove_jump "$IP6TABLES_BIN" FORWARD "$IP6_FORWARD_CHAIN"
    local failed=0
    remove_chain "$IPTABLES_BIN" "$OUTPUT_CHAIN" || failed=1
    remove_chain "$IPTABLES_BIN" "$INPUT_CHAIN" || failed=1
    remove_chain "$IPTABLES_BIN" "$FORWARD_CHAIN" || failed=1
    remove_chain "$IP6TABLES_BIN" "$IP6_OUTPUT_CHAIN" || failed=1
    remove_chain "$IP6TABLES_BIN" "$IP6_INPUT_CHAIN" || failed=1
    remove_chain "$IP6TABLES_BIN" "$IP6_FORWARD_CHAIN" || failed=1
    (( failed == 0 )) || fail "one or more AI-SOC isolation chains could not be removed"
}

verify_firewall_active() {
    local post_json="$1" pre_json="$2"
    python3 - "$post_json" "$pre_json" "$WAZUH_MANAGER_IP" "$WAZUH_MANAGER_PORT" <<'PY'
import ipaddress, json, sys
post, pre = (json.loads(sys.argv[1]), json.loads(sys.argv[2]))
manager, port = sys.argv[3:]



def normalize_rule(tokens):
    result = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token == "-m" and i + 1 < len(tokens) and tokens[i + 1] == "tcp":
            i += 2
            continue
        if token in ("-s", "-d") and i + 1 < len(tokens):
            value = tokens[i + 1]
            try:
                network = ipaddress.ip_network(value, strict=False)
                if network.prefixlen == network.max_prefixlen:
                    value = str(network.network_address)
            except ValueError:
                pass
            result.extend([token, value])
            i += 2
            continue
        if token == "--ctstate" and i + 1 < len(tokens):
            states = tokens[i + 1].split(",")
            result.extend([token, ",".join(sorted(states))])
            i += 2
            continue
        result.append(token)
        i += 1
    return result


def verify_family(key, names, expected_rules):
    current = post.get(key) or {}
    baseline = pre.get(key) or {}
    if not current.get("available") or not baseline.get("available"):
        return False
    if current.get("policies") != baseline.get("policies"):
        return False
    owned = current.get("owned_chains") or {}
    jumps = current.get("owned_jumps") or {}
    try:
        chains = {name: json.loads(value) for name, value in (current.get("chain_rules_json") or {}).items()}
        hooks = {name: json.loads(value) for name, value in (current.get("hook_rules_json") or {}).items()}
    except (TypeError, ValueError):
        return False
    for hook, name in names.items():
        if owned.get(name) is not True or jumps.get(hook + "->" + name) is not True:
            return False
        rules = chains.get(name)
        if [normalize_rule(r) for r in rules] != [normalize_rule(r) for r in expected_rules[name]]:
            return False
        hook_rules = hooks.get(hook) or []
        if not hook_rules or hook_rules[0] != ["-j", name]:
            return False
    return True

v4_names = {"INPUT": "AI_SOC_ISO_IN", "OUTPUT": "AI_SOC_ISO_OUT", "FORWARD": "AI_SOC_ISO_FWD"}
v6_names = {"INPUT": "AI_SOC_ISO6_IN", "OUTPUT": "AI_SOC_ISO6_OUT", "FORWARD": "AI_SOC_ISO6_FWD"}
v4_rules = {
    "AI_SOC_ISO_IN": [["-i", "lo", "-j", "ACCEPT"],
        ["-s", manager, "-p", "tcp", "--sport", port, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], ["-j", "DROP"]],
    "AI_SOC_ISO_OUT": [["-o", "lo", "-j", "ACCEPT"],
        ["-d", manager, "-p", "tcp", "--dport", port, "-j", "ACCEPT"], ["-j", "DROP"]],
    "AI_SOC_ISO_FWD": [["-j", "DROP"]],
}
v6_rules = {
    "AI_SOC_ISO6_IN": [["-i", "lo", "-j", "ACCEPT"], ["-j", "DROP"]],
    "AI_SOC_ISO6_OUT": [["-o", "lo", "-j", "ACCEPT"], ["-j", "DROP"]],
    "AI_SOC_ISO6_FWD": [["-j", "DROP"]],
}
if not post.get("manager_tcp_connection_reachable"):
    raise SystemExit("VERIFY_FAIL: MANAGER_SESSION")
if not verify_family("ipv4_firewall", v4_names, v4_rules):
    raise SystemExit("VERIFY_FAIL: IPV4_RULES")
if not verify_family("ipv6_firewall", v6_names, v6_rules):
    raise SystemExit("VERIFY_FAIL: IPV6_RULES")
PY
}

reserved_chains_absent() {
    local snapshot="$1"
    if ! python3 - "$snapshot" <<'PY'
import json, sys
state = json.loads(sys.argv[1])
for family in ("ipv4_firewall", "ipv6_firewall"):
    fw = state.get(family) or {}
    if not fw.get("available"):
        raise SystemExit("firewall snapshot unavailable")
    if any(fw.get("owned_chains", {}).values()):
        raise SystemExit("an AI-SOC reserved chain already exists without its execution record")
    if any(fw.get("owned_jumps", {}).values()):
        raise SystemExit("an AI-SOC reserved jump already exists without its execution record")
PY
    then
        fail "reserved AI-SOC chain/jump exists or firewall state is unavailable; refusing to overwrite unknown rules"
        return 1
    fi
}

cleanup_created_chains() {
    local index spec binary chain
    for ((index=${#CREATED_CHAIN_SPECS[@]}-1; index>=0; index--)); do
        spec="${CREATED_CHAIN_SPECS[index]}"
        IFS=: read -r binary chain <<<"$spec"
        remove_chain "$binary" "$chain" || return 1
    done
    CREATED_CHAIN_SPECS=()
}

build_firewall() {
    local binary chain
    FIREWALL_OWNERSHIP_CONFIRMED=0
    CREATED_CHAIN_SPECS=()

    # -N is the ownership boundary. If another actor creates a reserved name
    # after the snapshot, clean up only chains this invocation created.
    for spec in \
        "$IPTABLES_BIN:$INPUT_CHAIN" "$IPTABLES_BIN:$OUTPUT_CHAIN" "$IPTABLES_BIN:$FORWARD_CHAIN" \
        "$IP6TABLES_BIN:$IP6_INPUT_CHAIN" "$IP6TABLES_BIN:$IP6_OUTPUT_CHAIN" "$IP6TABLES_BIN:$IP6_FORWARD_CHAIN"; do
        IFS=: read -r binary chain <<<"$spec"
        if ! "$binary" -w 5 -N "$chain"; then
            cleanup_created_chains || log_message "ERROR: could not clean up partially created AI-SOC chains"
            fail "reserved chain ${chain} appeared during setup; no foreign chain was flushed"
            return 1
        fi
        CREATED_CHAIN_SPECS+=("$binary:$chain")
    done
    FIREWALL_OWNERSHIP_CONFIRMED=1

    # INPUT permits loopback and only established replies from Manager TCP 1514.
    # OUTPUT permits loopback and endpoint-initiated Manager TCP 1514.
    # FORWARD and all other ingress/egress are dropped. No default policy changes.
    "$IPTABLES_BIN" -w 5 -A "$INPUT_CHAIN" -i lo -j ACCEPT || return 1
    "$IPTABLES_BIN" -w 5 -A "$INPUT_CHAIN" -s "$WAZUH_MANAGER_IP" -p tcp --sport "$WAZUH_MANAGER_PORT" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || return 1
    "$IPTABLES_BIN" -w 5 -A "$INPUT_CHAIN" -j DROP || return 1
    "$IPTABLES_BIN" -w 5 -A "$OUTPUT_CHAIN" -o lo -j ACCEPT || return 1
    "$IPTABLES_BIN" -w 5 -A "$OUTPUT_CHAIN" -d "$WAZUH_MANAGER_IP" -p tcp --dport "$WAZUH_MANAGER_PORT" -j ACCEPT || return 1
    "$IPTABLES_BIN" -w 5 -A "$OUTPUT_CHAIN" -j DROP || return 1
    "$IPTABLES_BIN" -w 5 -A "$FORWARD_CHAIN" -j DROP || return 1

    # The Manager is configured as a static IPv4 peer. IPv6 is loopback-only.
    "$IP6TABLES_BIN" -w 5 -A "$IP6_INPUT_CHAIN" -i lo -j ACCEPT || return 1
    "$IP6TABLES_BIN" -w 5 -A "$IP6_INPUT_CHAIN" -j DROP || return 1
    "$IP6TABLES_BIN" -w 5 -A "$IP6_OUTPUT_CHAIN" -o lo -j ACCEPT || return 1
    "$IP6TABLES_BIN" -w 5 -A "$IP6_OUTPUT_CHAIN" -j DROP || return 1
    "$IP6TABLES_BIN" -w 5 -A "$IP6_FORWARD_CHAIN" -j DROP || return 1

    "$IPTABLES_BIN" -w 5 -I INPUT 1 -j "$INPUT_CHAIN" || return 1
    "$IPTABLES_BIN" -w 5 -I OUTPUT 1 -j "$OUTPUT_CHAIN" || return 1
    "$IPTABLES_BIN" -w 5 -I FORWARD 1 -j "$FORWARD_CHAIN" || return 1
    "$IP6TABLES_BIN" -w 5 -I INPUT 1 -j "$IP6_INPUT_CHAIN" || return 1
    "$IP6TABLES_BIN" -w 5 -I OUTPUT 1 -j "$IP6_OUTPUT_CHAIN" || return 1
    "$IP6TABLES_BIN" -w 5 -I FORWARD 1 -j "$IP6_FORWARD_CHAIN" || return 1
}

emit_evidence() {
    local event_type="$1" step="$2" outcome="$3" exit_code="$4"
    local execution_id="$5" plan_id="$6" action_id="$7" target="$8" ttl="$9"
    local state_json="${10:-null}" pre_json="${11:-null}" post_json="${12:-null}"
    if [[ ! -x "$EVIDENCE_WRITER" ]]; then
        log_message "WARNING: evidence writer unavailable; ${event_type} cannot be forwarded"
        return 1
    fi
    local payload
    payload="$(python3 - "$event_type" "$step" "$outcome" "$exit_code" "$execution_id" "$plan_id" "$action_id" "$target" "$ttl" "$state_json" "$pre_json" "$post_json" "$BOOT_ID_FILE" <<'PY'
import datetime,json,sys,uuid
(t,step,outcome,rc,execution,plan,action,target,ttl,state,pre,post,boot_file)=sys.argv[1:]
with open(boot_file,encoding="ascii") as f: boot=f.read().strip()
obj={"schema_version":"1.0","event_id":str(uuid.uuid4()),"plan_id":plan,"action_id":action,"execution_id":execution,
     "host":{"boot_id":boot,"observed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00","Z")},
     "action":{"type":"isolate_host","target":target or "unknown","direction":"BOTH","firewall_backend":"netfilter","firewall_tool":"iptables+ip6tables","ttl_seconds":int(ttl) if ttl.isdigit() else None},
     "event":{"type":t,"step":step,"outcome":outcome,"exit_code":None if rc=="null" else int(rc)},
     "state":json.loads(state),"pre_state":json.loads(pre),"post_state":json.loads(post)}
print(json.dumps(obj,separators=(",",":"),allow_nan=False))
PY
)" || {
        log_message "WARNING: could not construct ${event_type} evidence"
        return 1
    }
    printf '%s\n' "$payload" | python3 "$EVIDENCE_WRITER" >/dev/null || {
        log_message "WARNING: evidence writer rejected ${event_type}; action result remains authoritative"
        return 1
    }
}

report_execution_failure() {
    local step="$1" execution_id="$2" plan_id="$3" action_id="$4" target="$5"
    local pre_state="${6:-null}" post_state="${7:-null}" ttl="${8:-$ISOLATION_TIMEOUT_SECONDS}"
    emit_evidence "EXECUTION_FAILED" "$step" "failed" "1" "$execution_id" "$plan_id" "$action_id" "$target" "$ttl" "$pre_state" "$pre_state" "$post_state" || true
}

read_state_context() {
    local execution_id="$1" parsed
    STATE_FILE="$(state_file_for "$execution_id")" || return 1
    [[ -f "$STATE_FILE" ]] || return 1
    parsed="$(python3 - "$STATE_FILE" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)
fields = ("execution_id", "plan_id", "action_id", "boot_id", "status", "generation",
          "timer_unit", "ttl_seconds", "isolation_expires_at", "pre_state", "post_state", "target")
for key in fields:
    value = data.get(key)
    if isinstance(value, (dict, list)):
        print(json.dumps(value, separators=(",", ":")))
    elif value is None:
        print("")
    else:
        print(value)
PY
)" || return 1
    mapfile -t state_fields <<<"$parsed"
    (( ${#state_fields[@]} == 12 )) || return 1
    STATE_EXECUTION_ID="${state_fields[0]}"
    STATE_PLAN_ID="${state_fields[1]}"
    STATE_ACTION_ID="${state_fields[2]}"
    STATE_BOOT_ID="${state_fields[3]}"
    STATE_STATUS="${state_fields[4]}"
    STATE_GENERATION="${state_fields[5]}"
    STATE_TIMER_UNIT="${state_fields[6]}"
    STATE_TTL="${state_fields[7]}"
    STATE_EXPIRES="${state_fields[8]}"
    STATE_PRE="${state_fields[9]}"
    STATE_POST="${state_fields[10]}"
    STATE_TARGET="${state_fields[11]}"
}

mark_inactive() {
    local execution_id="$1"
    if [[ -r "$ACTIVE_FILE" ]] && [[ "$(cat "$ACTIVE_FILE")" == "$execution_id" ]]; then
        rm -f "$ACTIVE_FILE"
    fi
}

apply_isolation() {
    local execution_id="$1" plan_id="$2" action_id="$3" target="$4" ttl="$5"
    [[ "$execution_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || fail "execution_id must be a UUID" || return 1
    [[ -n "$plan_id" && "$plan_id" =~ ^[A-Za-z0-9._:-]{1,128}$ ]] || fail "plan_id is missing or invalid" || return 1
    [[ -n "$action_id" && "$action_id" =~ ^[A-Za-z0-9._:-]{1,128}$ ]] || fail "action_id is missing or invalid" || return 1
    if ! validate_ttl "$ttl"; then
        report_execution_failure "validate_safety_ttl" "$execution_id" "$plan_id" "$action_id" "$target"
        return 1
    fi
    if ! python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$target" >/dev/null 2>&1; then
        fail "endpoint target must be a literal IPv4 or IPv6 address"
        report_execution_failure "validate_endpoint_target" "$execution_id" "$plan_id" "$action_id" "$target"
        return 1
    fi

    if ! require_root_and_tools; then
        report_execution_failure "preflight_requirements" "$execution_id" "$plan_id" "$action_id" "$target"
        return 1
    fi
    if ! validate_manager_settings; then
        report_execution_failure "validate_manager_manager_address" "$execution_id" "$plan_id" "$action_id" "$target"
        return 1
    fi
    if ! acquire_lock; then
        report_execution_failure "acquire_execution_lock" "$execution_id" "$plan_id" "$action_id" "$target"
        return 1
    fi
    if ! check_boot_transition_locked; then
        report_execution_failure "reconcile_previous_boot_state" "$execution_id" "$plan_id" "$action_id" "$target"
        return 1
    fi
    local boot_id pre_state generation timer_unit expires_at state_file
    boot_id="$(get_boot_id)" || return 1

    if [[ -r "$ACTIVE_FILE" ]]; then
        local active_id active_file active_status
        active_id="$(cat "$ACTIVE_FILE")"
        active_file="$(state_file_for "$active_id" 2>/dev/null || true)"
        active_status="$(state_get "$active_file" status 2>/dev/null || true)"
        if [[ "$active_status" == "active" || "$active_status" == "applying" || "$active_status" == "rollback_failed" ]]; then
            fail "another AI-SOC isolation execution is already active (${active_id}); use --renew or --rollback"
            report_execution_failure "active_execution_conflict" "$execution_id" "$plan_id" "$action_id" "$target"
            return 1
        fi
        rm -f "$ACTIVE_FILE"
    fi

    # Baseline is captured before any chain/timer change. Require a real Manager
    # TCP 1514 session so isolation cannot strand an Agent using DNS or another peer.
    pre_state="$(capture_state)" || {
        fail "could not capture endpoint baseline"
        report_execution_failure "capture_pre_isolation_baseline" "$execution_id" "$plan_id" "$action_id" "$target"
        return 1
    }
    if ! python3 - "$pre_state" <<'PY'
import json,sys
s=json.loads(sys.argv[1])
if not s.get("manager_tcp_connection_reachable"):
    raise SystemExit("no established TCP connection to the configured static Wazuh Manager address/port")
if not s.get("ipv4_firewall",{}).get("available") or not s.get("ipv6_firewall",{}).get("available"):
    raise SystemExit("could not capture IPv4/IPv6 firewall baseline")
PY
    then
        fail "Manager channel or firewall baseline is not verifiable; isolation not enabled"
        report_execution_failure "validate_manager_channel_and_firewall_baseline" "$execution_id" "$plan_id" "$action_id" "$target" "$pre_state"
        return 1
    fi

    if ! reserved_chains_absent "$pre_state"; then
        report_execution_failure "reserved_chain_ownership_check" "$execution_id" "$plan_id" "$action_id" "$target" "$pre_state"
        return 1
    fi
    if ! install_boot_check; then
        fail "could not install persistent reboot safety checker"
        report_execution_failure "install_reboot_safety_checker" "$execution_id" "$plan_id" "$action_id" "$target" "$pre_state"
        return 1
    fi
    state_file="$(state_file_for "$execution_id")" || return 1
    if [[ -e "$state_file" ]]; then
        fail "execution_id already has local state; refusing to overwrite execution history"
        report_execution_failure "execution_id_reuse_guard" "$execution_id" "$plan_id" "$action_id" "$target" "$pre_state"
        return 1
    fi
    generation="$(random_uuid)"
    timer_unit="ai-soc-isolate-${generation//-/}"
    expires_at="$(python3 -c 'import datetime,sys; print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=int(sys.argv[1]))).isoformat())' "$ttl")"

    if ! write_state "$state_file" "preparing" "$execution_id" "$plan_id" "$action_id" "$generation" "$timer_unit" "$ttl" "$boot_id" "$expires_at" "$pre_state" "" "" "$target"; then
        report_execution_failure "persist_preparing_state" "$execution_id" "$plan_id" "$action_id" "$target" "$pre_state"
        return 1
    fi
    printf '%s' "$execution_id" >"$ACTIVE_FILE"
    chmod 600 "$ACTIVE_FILE"

    if ! start_expiry_timer "$ttl" "$execution_id" "$generation" "$timer_unit"; then
        write_state "$state_file" "failed" "$execution_id" "$plan_id" "$action_id" "$generation" "$timer_unit" "$ttl" "$boot_id" "$expires_at" "$pre_state" "" "safety timer start failed" || true
        mark_inactive "$execution_id"
        fail "independent safety timer could not be started; firewall was not enabled"
        report_execution_failure "start_independent_safety_timer" "$execution_id" "$plan_id" "$action_id" "$target" "$pre_state" "null" "$ttl"
        return 1
    fi

    if ! write_state "$state_file" "applying" "$execution_id" "$plan_id" "$action_id" "$generation" "$timer_unit" "$ttl" "$boot_id" "$expires_at" "$pre_state" "" ""; then
        stop_timer_unit "$timer_unit"
        mark_inactive "$execution_id"
        report_execution_failure "persist_applying_state" "$execution_id" "$plan_id" "$action_id" "$target" "$pre_state" "null" "$ttl"
        return 1
    fi
    if ! emit_evidence "EXECUTION_STARTED" "preflight_complete" "started" "null" "$execution_id" "$plan_id" "$action_id" "$target" "$ttl" "$pre_state" "$pre_state" "null"; then
        stop_timer_unit "$timer_unit"
        write_state "$state_file" "failed" "$execution_id" "$plan_id" "$action_id" "$generation" "$timer_unit" "$ttl" "$boot_id" "$expires_at" "$pre_state" "" "execution-start evidence could not be written" || true
        mark_inactive "$execution_id"
        fail "endpoint evidence writer is unavailable or rejected EXECUTION_STARTED; firewall was not enabled"
        return 1
    fi
    emit_evidence "STATE_SNAPSHOT" "pre_isolation" "observed" "0" "$execution_id" "$plan_id" "$action_id" "$target" "$ttl" "$pre_state" "$pre_state" "null" || true

    if ! build_firewall; then
        local failed_state cleanup_ok failed_status
        cleanup_ok=1
        if (( FIREWALL_OWNERSHIP_CONFIRMED )); then
            rollback_firewall || cleanup_ok=0
        fi
        failed_state="$(capture_state 2>/dev/null || printf 'null')"
        failed_status="failed"
        if (( cleanup_ok )); then
            stop_timer_unit "$timer_unit"
            mark_inactive "$execution_id"
        else
            failed_status="rollback_failed"
        fi
        write_state "$state_file" "$failed_status" "$execution_id" "$plan_id" "$action_id" "$generation" "$timer_unit" "$ttl" "$boot_id" "$expires_at" "$pre_state" "$failed_state" "firewall setup failed; cleanup_ok=${cleanup_ok}" || true
        emit_evidence "EXECUTION_FAILED" "install_isolation_rules" "failed" "1" "$execution_id" "$plan_id" "$action_id" "$target" "$ttl" "$failed_state" "$pre_state" "$failed_state" || true
        if (( cleanup_ok == 0 )); then
            emit_evidence "ROLLBACK_FAILED" "partial_setup_cleanup" "failed" "1" "$execution_id" "$plan_id" "$action_id" "$target" "$ttl" "$failed_state" "$pre_state" "$failed_state" || true
        fi
        fail "firewall setup failed; cleanup_ok=${cleanup_ok}"
        return 1
    fi

    local post_state manager_ok
    manager_ok=0
    for _ in 1 2 3 4 5; do
        post_state="$(capture_state)" || post_state="{}"
        if verify_firewall_active "$post_state" "$pre_state"; then
            manager_ok=1; break
        fi
        sleep 1
    done
    if (( manager_ok == 0 )); then
        local cleanup_ok failed_status
        cleanup_ok=1
        rollback_firewall || cleanup_ok=0
        post_state="$(capture_state 2>/dev/null || printf 'null')"
        failed_status="failed"
        if (( cleanup_ok )); then
            stop_timer_unit "$timer_unit"
            mark_inactive "$execution_id"
        else
            failed_status="rollback_failed"
        fi
        write_state "$state_file" "$failed_status" "$execution_id" "$plan_id" "$action_id" "$generation" "$timer_unit" "$ttl" "$boot_id" "$expires_at" "$pre_state" "$post_state" "post-state verification failed; cleanup_ok=${cleanup_ok}" || true
        emit_evidence "EXECUTION_FAILED" "post_isolation_safety_check" "failed" "1" "$execution_id" "$plan_id" "$action_id" "$target" "$ttl" "$post_state" "$pre_state" "$post_state" || true
        if (( cleanup_ok == 0 )); then
            emit_evidence "ROLLBACK_FAILED" "post_isolation_cleanup" "failed" "1" "$execution_id" "$plan_id" "$action_id" "$target" "$ttl" "$post_state" "$pre_state" "$post_state" || true
        fi
        fail "Manager channel or dedicated firewall verification failed; cleanup_ok=${cleanup_ok}"
        return 1
    fi

    if ! write_state "$state_file" "active" "$execution_id" "$plan_id" "$action_id" "$generation" "$timer_unit" "$ttl" "$boot_id" "$expires_at" "$pre_state" "$post_state" ""; then
        if rollback_firewall; then
            stop_timer_unit "$timer_unit"
            mark_inactive "$execution_id"
        else
            log_message "ERROR: state update failed and firewall rollback failed; safety timer remains active"
        fi
        report_execution_failure "persist_active_state_after_firewall_setup" "$execution_id" "$plan_id" "$action_id" "$target" "$pre_state" "$post_state" "$ttl"
        return 1
    fi
    emit_evidence "STATE_SNAPSHOT" "post_isolation" "observed" "0" "$execution_id" "$plan_id" "$action_id" "$target" "$ttl" "$post_state" "$pre_state" "$post_state" || true
    emit_evidence "EXECUTION_COMPLETED" "install_isolation_rules" "success" "0" "$execution_id" "$plan_id" "$action_id" "$target" "$ttl" "$post_state" "$pre_state" "$post_state" || true
    log_message "Host isolated; Manager ${WAZUH_MANAGER_IP}:${WAZUH_MANAGER_PORT} preserved; TTL ${ttl}s; execution ${execution_id}."
}

inspect_execution() {
    # Read-only new-process snapshot: never apply/rollback, start a timer or renew TTL.
    local execution_id="${1:-}" current_boot post_state exit_code=1
    [[ -n "$execution_id" ]] || { fail "inspect requires execution_id"; return 2; }
    require_root_and_tools || return 1
    validate_manager_settings || return 1
    acquire_lock || return 1
    read_state_context "$execution_id" || { fail "unknown isolation execution_id for inspection"; return 1; }
    current_boot="$(get_boot_id)" || return 1
    post_state="$(capture_state)" || { fail "inspection snapshot unavailable"; return 1; }
    # A stale ACTIVE marker or expired TTL must never certify a live isolation.
    if [[ "$STATE_STATUS" == "active" && "$STATE_BOOT_ID" == "$current_boot" \
          && -r "$ACTIVE_FILE" && "$(cat "$ACTIVE_FILE")" == "$execution_id" ]] \
          && python3 - "$STATE_EXPIRES" <<'PY'
import datetime,sys
try:
    dt = datetime.datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00"))
    if dt.tzinfo is None or dt <= datetime.datetime.now(datetime.timezone.utc):
        raise SystemExit(1)
except (TypeError,ValueError):
    raise SystemExit(1)
PY
    then
        if verify_firewall_active "$post_state" "$STATE_PRE"; then
            exit_code=0
        fi
    fi
    # Observed snapshot remains evidence of the current condition even when
    # isolation was lost. A nonzero exit_code never certifies active isolation.
    emit_evidence "STATE_SNAPSHOT" "independent_endpoint_inspection" "observed" "$exit_code" \
        "$STATE_EXECUTION_ID" "$STATE_PLAN_ID" "$STATE_ACTION_ID" \
        "$STATE_TARGET" "$STATE_TTL" "$post_state" "$STATE_PRE" "$post_state" || {
        fail "independent inspection evidence write failed"
        return 1
    }
    if (( exit_code != 0 )); then
        fail "independent inspection did not confirm active isolation"
        return 1
    fi
    log_message "Read-only independent inspection verified active isolation ${execution_id}."
    return 0
}

rollback_execution() {
    local execution_id="${1:-}"
    require_firewall_tools || return 1
    acquire_lock || return 1
    if [[ -z "$execution_id" ]]; then
        [[ -r "$ACTIVE_FILE" ]] || { log_message "No active AI-SOC isolation state; rollback is a no-op."; return 0; }
        execution_id="$(cat "$ACTIVE_FILE")"
    fi
    read_state_context "$execution_id" || { fail "no state record for execution ${execution_id}"; return 1; }
    if [[ "$STATE_STATUS" != "active" && "$STATE_STATUS" != "preparing" && "$STATE_STATUS" != "applying" && "$STATE_STATUS" != "rollback_failed" ]]; then
        log_message "Execution ${execution_id} is ${STATE_STATUS}; rollback is already terminal."
        return 0
    fi
    emit_evidence "ROLLBACK_STARTED" "remove_isolation_rules" "started" "null" "$STATE_EXECUTION_ID" "$STATE_PLAN_ID" "$STATE_ACTION_ID" "$STATE_TARGET" "$STATE_TTL" "null" "$STATE_PRE" "$STATE_POST" || true
    if ! rollback_firewall; then
        local failed_state
        failed_state="$(capture_state 2>/dev/null || printf 'null')"
        write_state "$STATE_FILE" "rollback_failed" "$STATE_EXECUTION_ID" "$STATE_PLAN_ID" "$STATE_ACTION_ID" "$STATE_GENERATION" "$STATE_TIMER_UNIT" "$STATE_TTL" "$STATE_BOOT_ID" "$STATE_EXPIRES" "$STATE_PRE" "$failed_state" "manual rollback failed" || true
        emit_evidence "ROLLBACK_FAILED" "remove_isolation_rules" "failed" "1" "$STATE_EXECUTION_ID" "$STATE_PLAN_ID" "$STATE_ACTION_ID" "$STATE_TARGET" "$STATE_TTL" "$failed_state" "$STATE_PRE" "$failed_state" || true
        return 1
    fi
    local post_state
    post_state="$(capture_state 2>/dev/null || printf 'null')"
    # Keep the safety timer until the terminal state is durable. If this
    # process crashes after deleting rules but before the journal update, the
    # timer can retry idempotent cleanup instead of leaving a false ACTIVE row.
    write_state "$STATE_FILE" "rolled_back" "$STATE_EXECUTION_ID" "$STATE_PLAN_ID" "$STATE_ACTION_ID" "$STATE_GENERATION" "$STATE_TIMER_UNIT" "$STATE_TTL" "$STATE_BOOT_ID" "$STATE_EXPIRES" "$STATE_PRE" "$post_state" "manual rollback" || return 1
    mark_inactive "$STATE_EXECUTION_ID"
    stop_timer_unit "$STATE_TIMER_UNIT"
    emit_evidence "STATE_SNAPSHOT" "post_rollback" "observed" "0" "$STATE_EXECUTION_ID" "$STATE_PLAN_ID" "$STATE_ACTION_ID" "$STATE_TARGET" "$STATE_TTL" "$post_state" "$STATE_PRE" "$post_state" || true
    emit_evidence "ROLLBACK_COMPLETED" "remove_isolation_rules" "success" "0" "$STATE_EXECUTION_ID" "$STATE_PLAN_ID" "$STATE_ACTION_ID" "$STATE_TARGET" "$STATE_TTL" "$post_state" "$STATE_PRE" "$post_state" || true
    log_message "Isolation rollback completed for execution ${STATE_EXECUTION_ID}."
}

expire_execution() {
    local execution_id="$1" generation="$2"
    require_firewall_tools || return 1
    acquire_lock || return 1
    read_state_context "$execution_id" || return 0
    [[ ( "$STATE_STATUS" == "active" || "$STATE_STATUS" == "applying" || "$STATE_STATUS" == "rollback_failed" ) && "$STATE_GENERATION" == "$generation" ]] || {
        log_message "Ignoring stale expiry callback for ${execution_id}; generation/status no longer current."
        return 0
    }
    if [[ "$STATE_BOOT_ID" != "$(get_boot_id)" ]]; then
        check_boot_transition_locked
        return $?
    fi
    if ! rollback_firewall; then
        local failed_state
        failed_state="$(capture_state 2>/dev/null || printf 'null')"
        write_state "$STATE_FILE" "rollback_failed" "$STATE_EXECUTION_ID" "$STATE_PLAN_ID" "$STATE_ACTION_ID" "$STATE_GENERATION" "$STATE_TIMER_UNIT" "$STATE_TTL" "$STATE_BOOT_ID" "$STATE_EXPIRES" "$STATE_PRE" "$failed_state" "TTL auto-expiry rollback failed" || true
        emit_evidence "ROLLBACK_FAILED" "ttl_auto_expiry" "failed" "1" "$STATE_EXECUTION_ID" "$STATE_PLAN_ID" "$STATE_ACTION_ID" "$STATE_TARGET" "$STATE_TTL" "$failed_state" "$STATE_PRE" "$failed_state" || true
        return 1
    fi
    local post_state
    post_state="$(capture_state 2>/dev/null || printf 'null')"
    write_state "$STATE_FILE" "expired" "$STATE_EXECUTION_ID" "$STATE_PLAN_ID" "$STATE_ACTION_ID" "$STATE_GENERATION" "$STATE_TIMER_UNIT" "$STATE_TTL" "$STATE_BOOT_ID" "$STATE_EXPIRES" "$STATE_PRE" "$post_state" "safety TTL elapsed" || return 1
    mark_inactive "$STATE_EXECUTION_ID"
    emit_evidence "TTL_AUTO_EXPIRED" "ttl_auto_expiry" "expired" "0" "$STATE_EXECUTION_ID" "$STATE_PLAN_ID" "$STATE_ACTION_ID" "$STATE_TARGET" "$STATE_TTL" "$post_state" "$STATE_PRE" "$post_state" || true
    log_message "Safety TTL expired; isolation chains removed for ${STATE_EXECUTION_ID}."
}

renew_execution() {
    local execution_id="$1" ttl="$2"
    validate_ttl "$ttl" || return 1
    require_root_and_tools || return 1
    acquire_lock || return 1
    if [[ -z "$execution_id" ]]; then
        [[ -r "$ACTIVE_FILE" ]] || { fail "no active execution to renew"; return 1; }
        execution_id="$(cat "$ACTIVE_FILE")"
    fi
    read_state_context "$execution_id" || { fail "no state record for execution ${execution_id}"; return 1; }
    [[ "$STATE_STATUS" == "active" ]] || { fail "only an active isolation execution can be renewed"; return 1; }
    [[ "$STATE_BOOT_ID" == "$(get_boot_id)" ]] || { fail "boot_id changed; isolation cannot be renewed after reboot"; return 1; }
    local renew_state
    renew_state="$(capture_state)" || { fail "could not inspect active firewall before TTL renewal"; return 1; }
    verify_firewall_active "$renew_state" "$STATE_PRE" || { fail "dedicated isolation chains or Manager session are no longer valid; refusing TTL renewal"; return 1; }
    local new_generation new_timer expires_at post_state
    new_generation="$(random_uuid)"
    new_timer="ai-soc-isolate-${new_generation//-/}"
    expires_at="$(python3 -c 'import datetime,sys; print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=int(sys.argv[1]))).isoformat())' "$ttl")"
    if ! start_expiry_timer "$ttl" "$execution_id" "$new_generation" "$new_timer"; then
        fail "new TTL timer could not be started; existing timer remains authoritative"
        return 1
    fi
    if ! write_state "$STATE_FILE" "active" "$STATE_EXECUTION_ID" "$STATE_PLAN_ID" "$STATE_ACTION_ID" "$new_generation" "$new_timer" "$ttl" "$STATE_BOOT_ID" "$expires_at" "$STATE_PRE" "$STATE_POST" ""; then
        stop_timer_unit "$new_timer"
        return 1
    fi
    [[ "$STATE_TIMER_UNIT" == "$new_timer" ]] || stop_timer_unit "$STATE_TIMER_UNIT"
    post_state="$(capture_state)"
    emit_evidence "TTL_RENEWED" "renew_safety_ttl" "renewed" "0" "$STATE_EXECUTION_ID" "$STATE_PLAN_ID" "$STATE_ACTION_ID" "$STATE_TARGET" "$ttl" "$post_state" "$STATE_PRE" "$post_state" || true
    log_message "Safety TTL renewed to ${ttl}s for ${STATE_EXECUTION_ID}."
}

check_boot_transition_locked() {
    local execution_id current_boot
    [[ -r "$ACTIVE_FILE" ]] || return 0
    execution_id="$(cat "$ACTIVE_FILE")"
    read_state_context "$execution_id" || { rm -f "$ACTIVE_FILE"; return 0; }
    if [[ "$STATE_STATUS" != "active" && "$STATE_STATUS" != "applying" && "$STATE_STATUS" != "rollback_failed" ]]; then
        mark_inactive "$execution_id"
        return 0
    fi
    current_boot="$(get_boot_id)" || return 1
    [[ "$STATE_BOOT_ID" != "$current_boot" ]] || return 0

    # Never assume iptables rules or transient timers survived reboot. Remove
    # any remaining AI-SOC-owned chains, report the lost isolation, and do not re-isolate.
    if ! rollback_firewall; then
        local recovery_state
        recovery_state="$(capture_state 2>/dev/null || printf 'null')"
        emit_evidence "ISOLATION_LOST_ON_REBOOT" "boot_reconciliation" "lost" "1" "$STATE_EXECUTION_ID" "$STATE_PLAN_ID" "$STATE_ACTION_ID" "$STATE_TARGET" "$STATE_TTL" "$recovery_state" "$STATE_PRE" "$recovery_state" || true
        emit_evidence "ROLLBACK_FAILED" "boot_reconciliation_cleanup" "failed" "1" "$STATE_EXECUTION_ID" "$STATE_PLAN_ID" "$STATE_ACTION_ID" "$STATE_TARGET" "$STATE_TTL" "$recovery_state" "$STATE_PRE" "$recovery_state" || true
        log_message "ERROR: stale isolation chains remain after reboot; state retained for another recovery attempt"
        return 1
    fi
    stop_timer_unit "$STATE_TIMER_UNIT"
    local post_state
    post_state="$(capture_state 2>/dev/null || printf 'null')"
    write_state "$STATE_FILE" "lost_on_reboot" "$STATE_EXECUTION_ID" "$STATE_PLAN_ID" "$STATE_ACTION_ID" "$STATE_GENERATION" "$STATE_TIMER_UNIT" "$STATE_TTL" "$current_boot" "" "$STATE_PRE" "$post_state" "endpoint reboot invalidated isolation state" || return 1
    mark_inactive "$STATE_EXECUTION_ID"
    emit_evidence "ISOLATION_LOST_ON_REBOOT" "boot_reconciliation" "lost" "0" "$STATE_EXECUTION_ID" "$STATE_PLAN_ID" "$STATE_ACTION_ID" "$STATE_TARGET" "$STATE_TTL" "$post_state" "$STATE_PRE" "$post_state" || true
    log_message "Previous isolation ${STATE_EXECUTION_ID} was lost/reconciled after endpoint reboot."
}

check_boot_transition() {
    require_firewall_tools || return 1
    acquire_lock || return 1
    check_boot_transition_locked
}

main() {
    local mode="" execution_id="" plan_id="" action_id="" ttl="$ISOLATION_TIMEOUT_SECONDS" target="" command_name=""
    case "${1:-}" in
        --rollback)
            execution_id="${2:-}"
            rollback_execution "$execution_id"
            return $?
            ;;
        --renew)
            execution_id="${2:-}"
            ttl="${3:-$ISOLATION_TIMEOUT_SECONDS}"
            renew_execution "$execution_id" "$ttl"
            return $?
            ;;
        --inspect)
            [[ $# -eq 2 ]] || { fail "usage: isolate.sh --inspect <execution_id>"; return 2; }
            inspect_execution "$2"
            return $?
            ;;
        --expire-now)
            [[ $# -eq 3 ]] || { fail "usage: isolate.sh --expire-now <execution_id> <generation>"; return 2; }
            expire_execution "$2" "$3"
            return $?
            ;;
        --check-boot)
            check_boot_transition
            return $?
            ;;
    esac

    local input_json
    IFS= read -r input_json || { fail "missing Active Response JSON"; return 1; }
    local parsed
    parsed="$(printf '%s' "$input_json" | parse_request)" || { fail "invalid Active Response JSON"; return 1; }
    mapfile -t fields <<<"$parsed"
    command_name="${fields[0]:-}"
    mode="${fields[1]:-}"
    execution_id="${fields[2]:-}"
    plan_id="${fields[3]:-}"
    action_id="${fields[4]:-}"
    [[ -n "${fields[5]:-}" ]] && ttl="${fields[5]}"
    target="${fields[6]:-}"

    case "$mode" in
        rollback) rollback_execution "$execution_id" ;;
        renew) renew_execution "$execution_id" "$ttl" ;;
        inspect) inspect_execution "$execution_id" ;;
        check-boot) check_boot_transition ;;
        *)
            case "$command_name" in
                add) apply_isolation "$execution_id" "$plan_id" "$action_id" "$target" "$ttl" ;;
                delete) rollback_execution "$execution_id" ;;
                *) fail "unsupported Active Response command '${command_name}'"; return 2 ;;
            esac
            ;;
    esac
}

main "$@"
