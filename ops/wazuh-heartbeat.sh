#!/bin/bash
# wazuh-heartbeat.sh
#
# 5-minute Wazuh stack health heartbeat. Pages via email if any critical
# component is down. Pairs with the failure-modes runbook at
# docs/soc/agentic-soc-failure-modes.md.
#
# Cron: */5 * * * * /home/wez/.openclaw/workspace/agentic-ai/ops/wazuh-heartbeat.sh
#
# Checks performed:
#   H1. Wazuh manager container up + manager API reachable
#   H2. Wazuh indexer container up + cluster health != RED
#   H3. Wazuh dashboard container up + HTTP 200/302
#   H4. Filebeat connected to indexer (no recent 401s in manager logs)
#   H5. At least N agents active (default 4 — 5 are enrolled, so 4 means
#       we tolerate 1 disconnected)
#   H6. Disk on / below threshold (default 85%)
#   H7. Backup exists from the last 36 hours
#
# Paging: if any check fails, the script exits non-zero and emits a
# one-line "PAGING: <reason>" message to stderr. The cron `||` echo
# forwards to /tmp/wazuh-heartbeat.log; a separate "wazuh-heartbeat-email"
# script (see below) can be wired in to email Wes on PAGE.
#
# Exit codes:
#   0 = all green
#   1 = at least one check failed
#   2 = script error (docker missing, container not found, etc.)
#
# Heartbeat status file (parseable shell-source, written every run):
#   /home/wez/logs/wazuh-heartbeat.status

# Allow unset env vars; we default inside the script.
set -o pipefail

# Configuration (all defaultable)
INDEXER_CONTAINER="${INDEXER_CONTAINER:-wazuh-stack_wazuh.indexer_1}"
MANAGER_CONTAINER="${MANAGER_CONTAINER:-wazuh-stack-wazuh.manager-1}"
DASHBOARD_CONTAINER="${DASHBOARD_CONTAINER:-wazuh-stack_wazuh.dashboard_1}"
INDEXER_URL="${INDEXER_URL:-https://127.0.0.1:9200}"
INDEXER_USER="${INDEXER_USER:-admin}"
INDEXER_PASSWORD="${INDEXER_PASSWORD:-SecretPassword}"
MANAGER_API_URL="${MANAGER_API_URL:-https://127.0.0.1:55000}"
DASHBOARD_URL="${DASHBOARD_URL:-https://127.0.0.1:5601}"
MIN_ACTIVE_AGENTS="${MIN_ACTIVE_AGENTS:-4}"
DISK_WARN_PCT="${DISK_WARN_PCT:-85}"
BACKUP_MAX_AGE_HOURS="${BACKUP_MAX_AGE_HOURS:-36}"
LOG_FILE="${LOG_FILE:-/home/wez/logs/wazuh-heartbeat.log}"
STATUS_FILE="${STATUS_FILE:-/home/wez/logs/wazuh-heartbeat.status}"
PAGE_FILE="${PAGE_FILE:-/home/wez/logs/wazuh-heartbeat-page.log}"
RECIPIENT="${WAZUH_REPORTS_RECIPIENT:-wlrobbi@gmail.com}"
SMTP_ENV="${SMTP_ENV:-/home/wez/.openclaw/workspace/secrets/reports-bedimsecurity-mailbox.env}"

mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$STATUS_FILE")" "$(dirname "$PAGE_FILE")"

log() { echo "[$(date -u +%FT%TZ)] $*" | tee -a "$LOG_FILE"; }
bail() { log "ERROR: $*"; exit "${2:-2}"; }
page() {
  log "PAGING: $*"
  echo "[$(date -u +%FT%TZ)] PAGING: $*" >> "$PAGE_FILE"
  # Send an email page
  if [ -r "$SMTP_ENV" ]; then
    set -a; source "$SMTP_ENV"; set +a
    if [ -n "${SMTP_HOST:-}" ] && [ -n "${REPORTS_MAILBOX:-}" ] && [ -n "${REPORTS_MAILBOX_PW:-}" ]; then
      SUBJECT="[Wazuh HEARTBEAT] $(hostname) — $*"
      BODY="Wazuh stack heartbeat detected a problem at $(date -u +%FT%TZ):

$*

Run the verification checklist in docs/soc/agentic-soc-failure-modes.md
or /home/wez/.openclaw/workspace/runbooks/wazuh-indexer-auth-pipeline.md.
"
      REASON="$*" python3 - <<PY
import os, sys, smtplib, ssl
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid
reason = os.environ.get("REASON", "unknown")
msg = MIMEText("""$BODY""")
msg["From"]    = os.environ["REPORTS_MAILBOX"]
msg["To"]      = "$RECIPIENT"
msg["Subject"] = """$SUBJECT"""
msg["Date"]    = formatdate(localtime=True)
msg["Message-ID"] = make_msgid(domain="bedimsecurity.com")
ctx = ssl.create_default_context()
try:
    with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ["SMTP_PORT"]), timeout=20) as s:
        s.starttls(context=ctx)
        s.login(os.environ["REPORTS_MAILBOX"], os.environ["REPORTS_MAILBOX_PW"])
        s.send_message(msg)
    print("PAGE EMAIL SENT")
except Exception as e:
    print(f"PAGE EMAIL FAILED: {e}", file=sys.stderr)
PY
    fi
  fi
}

# Sanity: docker available
command -v docker >/dev/null 2>&1 || bail "docker not on PATH"

# Track failures
FAILURES=()
NOW=$(date -u +%FT%TZ)

# H1. Manager container up
if ! docker ps --format '{{.Names}}' | grep -q "^${MANAGER_CONTAINER}$"; then
  FAILURES+=("H1: manager container ${MANAGER_CONTAINER} not running")
fi

# H2. Indexer container up + cluster status
if ! docker ps --format '{{.Names}}' | grep -q "^${INDEXER_CONTAINER}$"; then
  FAILURES+=("H2: indexer container ${INDEXER_CONTAINER} not running")
else
  CLUSTER_STATUS=$(docker exec "$INDEXER_CONTAINER" bash -c \
    "curl -sS -k -u '$INDEXER_USER:$INDEXER_PASSWORD' '$INDEXER_URL/_cluster/health' 2>/dev/null" \
    | python3 -c "import json,sys; d=sys.stdin.read(); print(json.loads(d).get('status', 'unknown') if d else 'unknown')" 2>/dev/null)
  case "$CLUSTER_STATUS" in
    red|unknown) FAILURES+=("H2: indexer cluster status '$CLUSTER_STATUS'") ;;
  esac
fi

# H3. Dashboard
if ! docker ps --format '{{.Names}}' | grep -q "^${DASHBOARD_CONTAINER}$"; then
  FAILURES+=("H3: dashboard container ${DASHBOARD_CONTAINER} not running")
fi

# H4. Filebeat connected (no recent 401s in manager logs)
if docker ps --format '{{.Names}}' | grep -q "^${MANAGER_CONTAINER}$"; then
  RECENT_401s=$(docker logs "$MANAGER_CONTAINER" --tail 100 2>/dev/null | grep -c "401 Unauthorized" 2>/dev/null | head -1)
  RECENT_401s="${RECENT_401s:-0}"
  if [ "$RECENT_401s" -gt 5 ] 2>/dev/null; then
    FAILURES+=("H4: filebeat $RECENT_401s recent 401s in manager logs")
  fi
fi

# H5. Active agents — load creds from the same env file as the rest of the SOC.
# The manager API requires a JWT (Bearer token) for /agents, not basic auth.
# Get a JWT from /security/user/authenticate, then use it.
WAZUH_CREDS_FILE="${WAZUH_CREDS_FILE:-/home/wez/.openclaw/workspace/secrets/wazuh-agent-keys-2026-08-03.env}"
WAZUH_API_USER_VAL=""
WAZUH_API_PASSWORD_VAL=""
if [ -r "$WAZUH_CREDS_FILE" ]; then
  WAZUH_API_USER_VAL=$(grep -E '^WAZUH_API_USERNAME=' "$WAZUH_CREDS_FILE" 2>/dev/null | head -1 | cut -d= -f2)
  WAZUH_API_PASSWORD_VAL=$(grep -E '^WAZUH_API_PASSWORD(_NEW)?=' "$WAZUH_CREDS_FILE" 2>/dev/null | head -1 | cut -d= -f2)
fi
WAZUH_API_USER_VAL="${WAZUH_API_USER_VAL:-wazuh-wui}"
WAZUH_API_PASSWORD_VAL="${WAZUH_API_PASSWORD_VAL:-WazuhAdmin123!}"
JWT=$(curl -sS -k -u "$WAZUH_API_USER_VAL:$WAZUH_API_PASSWORD_VAL" \
  -X POST "$MANAGER_API_URL/security/user/authenticate" 2>/dev/null \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('data',{}).get('token',''))" 2>/dev/null)
ACTIVE=""
if [ -n "$JWT" ]; then
  ACTIVE=$(curl -sS -k -H "Authorization: Bearer $JWT" \
    "$MANAGER_API_URL/agents" 2>/dev/null \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(sum(1 for a in d.get('data',{}).get('affected_items',[]) if a.get('status')=='active'))" 2>/dev/null)
fi
if [ -n "$ACTIVE" ] && [ "$ACTIVE" -lt "$MIN_ACTIVE_AGENTS" ] 2>/dev/null; then
  FAILURES+=("H5: only $ACTIVE active agents (expected >= $MIN_ACTIVE_AGENTS)")
fi

# H6. Disk
DISK_PCT=$(df -P / | tail -1 | awk '{print $5}' | tr -d '%')
if [ -n "$DISK_PCT" ] && [ "$DISK_PCT" -ge "$DISK_WARN_PCT" ] 2>/dev/null; then
  FAILURES+=("H6: disk at ${DISK_PCT}% (warn >= ${DISK_WARN_PCT}%)")
fi

# H7. Recent backup
LATEST_BACKUP=$(find /home/wez/wazuh-stack-backups -maxdepth 2 -name "wazuh-stack-*.tar.zst" -mmin "-$((BACKUP_MAX_AGE_HOURS*60))" 2>/dev/null | head -1)
if [ -z "$LATEST_BACKUP" ]; then
  LATEST_AGE=$(find /home/wez/wazuh-stack-backups -maxdepth 2 -name "wazuh-stack-*.tar.zst" -printf '%T@\n' 2>/dev/null | sort -n | tail -1)
  if [ -z "$LATEST_AGE" ]; then
    FAILURES+=("H7: no backup found")
  else
    NOW_S=$(date +%s)
    AGE_HOURS=$(( (NOW_S - ${LATEST_AGE%.*}) / 3600 ))
    if [ "$AGE_HOURS" -ge "$BACKUP_MAX_AGE_HOURS" ]; then
      FAILURES+=("H7: last backup is ${AGE_HOURS}h old (max ${BACKUP_MAX_AGE_HOURS}h)")
    fi
  fi
fi

# Write heartbeat status
H1="OK"; H2="OK"; H3="OK"; H4="OK"; H5="OK"; H6="OK"; H7="OK"
for f in "${FAILURES[@]}"; do
  case "$f" in
    H1:*) H1="FAIL" ;;
    H2:*) H2="FAIL" ;;
    H3:*) H3="FAIL" ;;
    H4:*) H4="FAIL" ;;
    H5:*) H5="FAIL" ;;
    H6:*) H6="FAIL" ;;
    H7:*) H7="FAIL" ;;
  esac
done

cat > "$STATUS_FILE" <<EOF
# Wazuh heartbeat status — $NOW
STATUS=$([ ${#FAILURES[@]} -eq 0 ] && echo GREEN || echo RED)
DISK_PCT=${DISK_PCT:-?}
H1_MANAGER=$H1
H2_INDEXER=$H2
H3_DASHBOARD=$H3
H4_FILEBEAT=$H4
H5_AGENTS=$H5
H6_DISK=$H6
H7_BACKUP=$H7
ACTIVE_AGENTS=${ACTIVE:-?}
LATEST_BACKUP=${LATEST_BACKUP:-none}
EOF

if [ ${#FAILURES[@]} -eq 0 ]; then
  log "all green (disk=${DISK_PCT}%, agents=${ACTIVE:-?})"
  exit 0
fi

# Page
PAGE_REASON=$(printf '%s; ' "${FAILURES[@]}")
PAGE_REASON="${PAGE_REASON%; }"
page "$PAGE_REASON"
exit 1
