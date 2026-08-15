#!/usr/bin/env bash
# /home/wez/bin/wazuh-daily-digest.sh
# Daily Wazuh digest (cron: 0 18 * * *). Last 24 h of all alerts (L >= 3).
# Sends to RECIPIENT via reports@bedimsecurity.com.
#
# Uses the Wazuh OpenSearch indexer directly (not the manager API — that
# endpoint was removed in 4.14). Indexer creds: WAZUH_INDEXER_USERNAME,
# WAZUH_INDEXER_PASSWORD, WAZUH_INDEXER_URL.
#
# Failure mode (SOC 1.4):
#   Same selftest as morning-highlights: indexer auth + reachability +
#   non-empty 24h window. See /home/wez/bin/wazuh-indexer-selftest.sh.

set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

REPORTS_ENV=/home/wez/.openclaw/workspace/secrets/reports-bedimsecurity-mailbox.env
for f in "$REPORTS_ENV"; do
  if [[ ! -r "$f" ]]; then
    logger -t wazuh-digest "missing cred file: $f" 2>/dev/null || echo "missing $f" >&2
    exit 1
  fi
done
set -a; source "$REPORTS_ENV"; set +a

: "${SMTP_HOST:?must be set in $REPORTS_ENV}"
: "${SMTP_PORT:?must be set}"
: "${REPORTS_MAILBOX:?must be set}"
: "${REPORTS_MAILBOX_PW:?must be set}"

WAZUH_INDEXER_URL="${WAZUH_INDEXER_URL:-https://127.0.0.1:9200}"
WAZUH_INDEXER_USERNAME="${WAZUH_INDEXER_USERNAME:-admin}"
WAZUH_INDEXER_PASSWORD="${WAZUH_INDEXER_PASSWORD:-SecretPassword}"
RECIPIENT="${WAZUH_REPORTS_RECIPIENT:-wlrobbi@gmail.com}"
LOGFILE="${LOGFILE:-/home/wez/logs/wazuh-digest.log}"
mkdir -p "$(dirname "$LOGFILE")"

# Time range: last 24h UTC
SINCE_TS=$(date -u -d '24 hours ago' +%FT%T 2>/dev/null || date -u -v-24H +%FT%T)
NOW_TS=$(date -u +%FT%T)
SUBJECT_DATE=$(date +%Y-%m-%d)
HIGH_LEVEL_MIN=3   # include medium+ in this digest

# --- 0) Pre-send selftest (SOC 1.4) -------------------------------------
# Same pattern as morning-highlights: fail loudly if the indexer is
# unreachable, auth-broken, or has zero hits in 24h.
LOG_TAG="${LOG_TAG:-wazuh-daily-digest}" /home/wez/bin/wazuh-indexer-selftest.sh || {
  log "selftest FAILED — aborting daily-digest before sending summary"
  exit 1
}

log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*"; }
exec >>"$LOGFILE" 2>&1
log "==== digest run start ===="

# --- 1) Query indexer for last 24h of alerts -----------------------------
ALERTS_JSON=$(WAZUH_INDEXER_URL="$WAZUH_INDEXER_URL" WAZUH_INDEXER_USERNAME="$WAZUH_INDEXER_USERNAME" WAZUH_INDEXER_PASSWORD="$WAZUH_INDEXER_PASSWORD" python3 - "$SINCE_TS" "$NOW_TS" "$HIGH_LEVEL_MIN" <<'PY'
import os, sys, json, urllib.request, ssl, base64
since, until, lvl_min = sys.argv[1], sys.argv[2], int(sys.argv[3])

base  = os.environ["WAZUH_INDEXER_URL"]
user  = os.environ["WAZUH_INDEXER_USERNAME"]
pw    = os.environ["WAZUH_INDEXER_PASSWORD"]

auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
ctx  = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE

query = {
    "size": 500,
    "sort": [{"timestamp": {"order": "desc"}}],
    "_source": ["timestamp", "rule.level", "rule.id", "rule.description",
                "agent.id", "agent.name", "agent.ip"],
    "query": {
        "bool": {
            "filter": [
                {"range": {"timestamp": {"gte": since, "lte": until}}},
                {"range": {"rule.level":  {"gte": lvl_min}}}
            ]
        }
    }
}

req = urllib.request.Request(
    f"{base}/wazuh-alerts-*/_search",
    data=json.dumps(query).encode(),
    headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
        d = json.loads(r.read())
except Exception as e:
    sys.stderr.write(f"indexer query failed: {e}\n")
    sys.exit(1)

items = d.get("hits", {}).get("hits", [])
out = []
for h in items:
    s = h.get("_source", {})
    out.append({
        "timestamp": s.get("timestamp"),
        "level":     (s.get("rule") or {}).get("level", 0),
        "rule_id":   (s.get("rule") or {}).get("id", "?"),
        "rule_desc": (s.get("rule") or {}).get("description", "?"),
        "agent":     (s.get("agent") or {}).get("name", "?"),
        "agent_ip":  (s.get("agent") or {}).get("ip", "?"),
    })

from collections import Counter
levels   = Counter(e["level"]   for e in out)
agents   = Counter(e["agent"]   for e in out)
rules    = Counter((e["rule_id"], e["rule_desc"]) for e in out)

# Top 5 highest-severity events
top = sorted(out, key=lambda e: -int(e["level"]))[:3]

print(json.dumps({
    "window":        {"since": since, "until": until},
    "level_min":     lvl_min,
    "total_alerts":  len(out),
    "by_level":      dict(sorted(levels.items(), key=lambda kv: -kv[0])),
    "top_rules":     [{"id": k[0], "description": k[1][:80], "count": v} for k,v in rules.most_common(5)],
    "top_agents":    [{"name": n, "count": c} for n,c in agents.most_common(5)],
    "top_events":    top,
}, indent=2, default=str))
PY
)
if [[ $? -ne 0 ]]; then
  log "FAIL: indexer query"
  exit 1
fi

TOTAL_ALERTS=$(echo "$ALERTS_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['total_alerts'])")
log "indexer returned $TOTAL_ALERTS alerts since $SINCE_TS"

# --- 2) Snapshot for audit ------------------------------------------------
SNAP="/tmp/wazuh-digest-$(date -u +%FT%H%MZ).json"
printf '%s\n' "$ALERTS_JSON" > "$SNAP"
log "saved snapshot: $SNAP ($(wc -c < "$SNAP") bytes)"

# --- 3) Ask the agent for a SOC narrative --------------------------------
NARRATIVE="(agent unavailable; raw stats below)"
if command -v openclaw >/dev/null 2>&1; then
  NARRATIVE=$(openclaw ask \
    --model ollama/minimax-m3:cloud \
    --system "You are a SOC analyst writing a short daily summary for a non-technical executive. Be terse. Use 1-3 short sentences plus a bulleted list of top issues. No markdown headers. Plain text." \
    --format text --timeout 75 -- \
    "Analyse the following Wazuh alerts JSON and produce a 1-3 sentence summary plus a 3-5 bullet list of top issues / recommended actions. Keep total under 200 words.\n\n$ALERTS_JSON" \
    2>/dev/null || echo "(agent failed; falling back to raw stats)")
  log "agent narrative: $(printf '%s' "$NARRATIVE" | wc -w) words"
fi

# --- 4) Build the email --------------------------------------------------
SUBJECT="[Wazuh digest ${SUBJECT_DATE}] ${TOTAL_ALERTS} alert(s) (last 24h)"
SUBJECT=$(echo "$SUBJECT" | tr '\n' ' ' | cut -c1-200)

BODY=$(cat <<EOF
Wazuh daily digest for $SUBJECT_DATE — generated $NOW_TS UTC.

Window:  $SINCE_TS  ->  $NOW_TS UTC
Level >= $HIGH_LEVEL_MIN

--- SOC analyst summary ---

$NARRATIVE

--- Severity distribution ---

$(echo "$ALERTS_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f\"Total alerts: {d['total_alerts']}\")
for lvl, cnt in d['by_level'].items():
    bars = '#' * min(cnt, 40)
    print(f'  L{lvl:3} {cnt:5}  {bars}')
")

--- Top rules ---

$(echo "$ALERTS_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for r in d['top_rules']:
    print(f\"  rule {r['id']:>10}  x{r['count']:4}  {r['description']}\")
")

--- Top agents ---

$(echo "$ALERTS_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for a in d['top_agents']:
    print(f\"  agent {a['name']:<20}  x{a['count']:4}\")
")

--- Top 3 highest-severity events ---

$(echo "$ALERTS_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for e in d['top_events']:
    print(f\"  * L{e['level']}  rule {e['rule_id']}  agent {e['agent']} ({e['agent_ip']})  @ {e['timestamp']}\")
    print(f\"    {e['rule_desc']}\")
")

---
Generated by /home/wez/bin/wazuh-daily-digest.sh (cron 0 18 * * *).
Snapshot: $SNAP
EOF
)

# --- 5) Send -------------------------------------------------------------
log "sending digest to $RECIPIENT via $REPORTS_MAILBOX"
python3 - <<PY
import os, sys, smtplib, ssl
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

body = """${BODY//\\/\\\\}"""
body = body.replace('\\n', chr(10))

ctx = ssl.create_default_context()
msg = MIMEText(body)
msg["From"]    = os.environ["REPORTS_MAILBOX"]
msg["To"]      = "${RECIPIENT}"
msg["Subject"] = """${SUBJECT//\\/\\\\}"""
msg["Date"]    = formatdate(localtime=True)
msg["Message-ID"] = make_msgid(domain="bedimsecurity.com")
msg["X-Wazuh-Digest"] = "1"

with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ["SMTP_PORT"]), timeout=20) as s:
    s.starttls(context=ctx)
    s.login(os.environ["REPORTS_MAILBOX"], os.environ["REPORTS_MAILBOX_PW"])
    s.send_message(msg)

print("SENT")
PY
RC=$?
log "exit=$RC"
exit $RC