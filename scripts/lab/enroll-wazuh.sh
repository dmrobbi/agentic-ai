#!/bin/bash
# KA-078 lab detection loop - wazuh-agent enrollment helper for lab targets.
# MANUAL EXECUTOR ONLY; CI never runs this.
# Owner gate: --enroll refuses without KA_LAB_CONSENT=1 in its environment.
# Playbook: docs/KA-LAB-DETECTION.md (the sibling of the battery playbook).
#
# No internal addresses live in this file: every endpoint arrives through
# env or flags; values below are placeholder/package defaults.
set -u

CONSENT_VAR=KA_LAB_CONSENT

# the lab target (keyed ssh, battery-playbook pattern)
TARGET_ADDR="${KA_LAB_TARGET_ADDR:-127.0.0.1}"   # loopback default = the battery hostfwd pattern on the lab host
TARGET_PORT="${KA_LAB_TARGET_PORT:-2226}"        # the battery playbook's guest-ssh hostfwd port
TARGET_USER="${KA_LAB_TARGET_USER:-root}"        # the lab key roots every lab machine
KEYFILE="${KA_LAB_TARGET_KEY:-$HOME/verify-aai/pve-vm/pve-pilot-key}"

# the wazuh side (placeholders: set real values from the SOC inventory)
AGENT_VERSION="${WAZUH_AGENT_VERSION:-4.14.8}"   # keep equal to the manager's version
RPM_URL="https://packages.wazuh.com/4.x/yum/wazuh-agent-${AGENT_VERSION}-1.x86_64.rpm"
WAZUH_MANAGER_ADDR="${WAZUH_MANAGER_ADDR:-}"           # required for --enroll (e.g. 192.0.2.10)
WAZUH_MANAGER_PORT="${WAZUH_MANAGER_PORT:-}"           # empty = package default (1514/TCP reporting)
WAZUH_REGISTRATION_PORT="${WAZUH_REGISTRATION_PORT:-}" # empty = package default (1515/TCP authd)
WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME:-}"               # empty = the target's own computer name
WAZUH_REGISTRATION_PASSWORD="${WAZUH_REGISTRATION_PASSWORD:-}"  # only when authd demands one

say() { echo "[enroll] $*"; }
die() { say "FATAL: $*"; exit "${2:-1}"; }

SSH_OPTS=(-i "$KEYFILE" -p "$TARGET_PORT"
          -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null
          -o BatchMode=yes -o ConnectTimeout=10)
TARGET="${TARGET_USER}@${TARGET_ADDR}"

usage() {
  cat <<EOF
usage: enroll-wazuh.sh --check|--verify|--enroll [--target ADDR] [--port PORT] [--manager ADDR]
  --check     read-only preflight: lab tier + target reach + (when it knows the
              manager) authd reach from the target
  --verify    read-only post-enroll sanity (service active, log collection,
              ossec.log tail)
  --enroll    OWNER-GATED: install-or-reconfigure the wazuh agent on the target
              and start it (KA_LAB_CONSENT=1 required)
Endpoints (env; placeholders only - no internal addresses hardcoded here):
  KA_LAB_TARGET_ADDR/PORT/USER/KEY            the lab target's ssh endpoint
      (defaults = the battery playbook's hostfwd pattern on the lab host)
  WAZUH_MANAGER_ADDR                          required for --enroll (e.g. 192.0.2.10)
  WAZUH_MANAGER_PORT / WAZUH_REGISTRATION_PORT  default to the package (1514/1515)
  WAZUH_AGENT_NAME                            default = the target's own hostname
  WAZUH_REGISTRATION_PASSWORD                 only when the manager's authd demands one
Exit codes: 0 green; 1 target/step failure; 2 consent refused; 3 usage.
EOF
}

consent_refused() {
  [ "${!CONSENT_VAR:-}" = "1" ] && return 0
  say "REFUSED: --enroll needs $CONSENT_VAR=1 (owner gate; see docs/KA-LAB-DETECTION.md)"
  exit 2
}

need_manager() {
  [ -n "$WAZUH_MANAGER_ADDR" ] && return 0
  say "FATAL: set WAZUH_MANAGER_ADDR (the manager address as seen FROM the target; placeholder: 192.0.2.10)"
  exit 3
}

host_tier() {
  [ -f "$KEYFILE" ] || { say "FAIL: key missing: $KEYFILE"; return 1; }
  say "OK host tier (key present)"
}

target_tier() {
  out=$(timeout 15 ssh "${SSH_OPTS[@]}" "$TARGET" "hostname" 2>/dev/null)
  case "$out" in
    "") say "FAIL: target unreachable at $TARGET_ADDR:$TARGET_PORT"; return 1 ;;
    *)  say "OK target tier (hostname '$out' via $TARGET_ADDR:$TARGET_PORT)" ;;
  esac
}

agent_state() {
  # prints installed|absent; caller decides what those mean
  timeout 10 ssh "${SSH_OPTS[@]}" "$TARGET" \
    "test -x /var/ossec/bin/wazuh-control && echo installed || echo absent" 2>/dev/null
  return 0
}

manager_tier() {
  if [ -z "$WAZUH_MANAGER_ADDR" ]; then
    say "WARN: manager tier skipped (set WAZUH_MANAGER_ADDR for the full check)"
    return 0
  fi
  local probe="${WAZUH_REGISTRATION_PORT:-1515}"
  out=$(timeout 15 ssh "${SSH_OPTS[@]}" "$TARGET" \
    "timeout 3 bash -c '</dev/tcp/${WAZUH_MANAGER_ADDR}/${probe}' 2>/dev/null && echo authd-open || echo authd-closed" 2>/dev/null)
  case "$out" in
    authd-open)   say "OK manager tier (authd port $probe reachable from the target)" ;;
    authd-closed) say "FAIL: manager authd port $probe reachable but refusing (routing/firewall?)"; return 1 ;;
    "")           say "FAIL: could not probe the manager authd port from the target"; return 1 ;;
  esac
}

do_check() {
  host_tier   || exit 1
  target_tier || exit 1
  case "$(agent_state)" in
    installed) say "INFO: wazuh-agent already installed (--enroll reconfigures in place)" ;;
    *)         say "INFO: wazuh-agent not installed yet (expected before --enroll)" ;;
  esac
  manager_tier
  say "CHECK-OK (read-only preflight green)"
}

do_verify() {
  timeout 15 ssh "${SSH_OPTS[@]}" "$TARGET" '
    state=$(systemctl is-active wazuh-agent 2>/dev/null); echo "service: $state"
    echo "journald localfile blocks: $(grep -c "<location>journald</location>" /var/ossec/etc/ossec.conf 2>/dev/null)"
    echo "secure localfile blocks:  $(grep -c "<location>/var/log/secure</location>" /var/ossec/etc/ossec.conf 2>/dev/null)"
    echo "ossec.log tail:"; tail -n 4 /var/ossec/logs/ossec.log 2>/dev/null
    [ "X$state" = "Xactive" ]
  ' || die "agent not healthy on the target" 1
  say "VERIFY-OK"
}

do_enroll() {
  consent_refused
  need_manager
  host_tier   || exit 1
  target_tier || exit 1
  say "enroll step: install-or-reconfigure + start (timeout 300s; package $RPM_URL)"
  # pass the six values as remote positional args, shell-quoted locally
  a_mgr=$(printf '%q' "$WAZUH_MANAGER_ADDR")
  a_rpt=$(printf '%q' "${WAZUH_MANAGER_PORT:-1514}")
  a_reg=$(printf '%q' "${WAZUH_REGISTRATION_PORT:-1515}")
  a_pw=$(printf '%q'  "$WAZUH_REGISTRATION_PASSWORD")
  a_nm=$(printf '%q'  "$WAZUH_AGENT_NAME")
  a_url=$(printf '%q' "$RPM_URL")
  if ! timeout 300 ssh "${SSH_OPTS[@]}" "$TARGET" "bash -s $a_mgr $a_rpt $a_reg $a_pw $a_nm $a_url" <<'REMOTE_ENROLL'
set -u
MGR_ADDR="$1"; RPT_PORT="$2"; REG_PORT="$3"; REG_PW="$4"; AGENT_NM="$5"; RPM_URL="$6"
conf=/var/ossec/etc/ossec.conf
if [ ! -x /var/ossec/bin/wazuh-control ]; then
  echo "install: $RPM_URL"
  # env-driven headless install (the wazuh deployment variables); empty
  # values degrade to the installer's own unset behavior
  WAZUH_MANAGER="$MGR_ADDR" WAZUH_MANAGER_PORT="$RPT_PORT" \
  WAZUH_REGISTRATION_PORT="$REG_PORT" WAZUH_REGISTRATION_PASSWORD="$REG_PW" \
  WAZUH_AGENT_NAME="$AGENT_NM" \
    dnf -y install "$RPM_URL" || exit 1
  systemctl daemon-reload && systemctl enable wazuh-agent
else
  echo "agent present; reconfiguring in place"
  sed -i "s|<address>[^<]*</address>|<address>${MGR_ADDR}</address>|" "$conf"
  sed -i "s|<manager_address>[^<]*</manager_address>|<manager_address>${MGR_ADDR}</manager_address>|" "$conf"
  # first <port> = the manager reporting port; the one inside the
  # <enrollment> block = the authd port
  sed -i "0,/<port>.*<\/port>/s//<port>${RPT_PORT}<\/port>/" "$conf"
  sed -i "/<enrollment>/,/<\/enrollment>/ s|<port>.*</port>|<port>${REG_PORT}</port>|" "$conf"
  if [ -n "$REG_PW" ]; then
    umask 077
    printf '%s\n' "$REG_PW" > /var/ossec/etc/authd.pass
    chmod 640 /var/ossec/etc/authd.pass
    chown root:wazuh /var/ossec/etc/authd.pass 2>/dev/null || true
  fi
  systemctl daemon-reload && systemctl enable wazuh-agent
fi
systemctl restart wazuh-agent
sleep 12
state=$(systemctl is-active wazuh-agent); echo "service: $state"
echo "journald localfile blocks: $(grep -c '<location>journald</location>' "$conf")"
echo "secure localfile blocks:   $(grep -c '<location>/var/log/secure</location>' "$conf")"
echo "ossec.log tail:"; tail -n 5 /var/ossec/logs/ossec.log
[ "X$state" = "Xactive" ]
REMOTE_ENROLL
  then die "enroll step failed on the target" 1
  fi
  say "ENROLL-DONE - verify with --verify, then the playbook's manager-side steps (docs/KA-LAB-DETECTION.md)"
}

MODE=
while [ $# -gt 0 ]; do
  case "$1" in
    --check|--enroll|--verify) MODE="$1"; shift ;;
    --target)  TARGET_ADDR="$2"; shift 2 ;;
    --port)    TARGET_PORT="$2"; shift 2 ;;
    --manager) WAZUH_MANAGER_ADDR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)         usage; exit 3 ;;
  esac
done

case "${MODE:-}" in
  --check)  do_check ;;
  --verify) do_verify ;;
  --enroll) do_enroll ;;
  *)        usage; exit 3 ;;
esac
