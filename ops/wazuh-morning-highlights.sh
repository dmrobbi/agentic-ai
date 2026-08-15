#!/usr/bin/env bash
# /home/wez/bin/wazuh-morning-highlights.sh
# Morning high-alert summary (cron: 0 8 * * *). Last 24 h of level >= 10 alerts.
# Sends to RECIPIENT via reports@bedimsecurity.com. Skips send when 0 highs.
#
# Uses the Wazuh OpenSearch indexer directly.
#
# Failure mode (SOC 1.4):
#   Pre-send selftest at /home/wez/bin/wazuh-indexer-selftest.sh verifies
#   indexer auth + reachability + non-empty 24h window. On failure, the
#   selftest sends a "[Wazuh selftest FAILURE]" email and exits non-zero;
#   this script then aborts. The cron's `||` alert path also fires.
#   Acceptance: deliberately break the indexer password → failure email
#   arrives within 60 s.
#
# Test hooks (selftest contract — DO NOT USE IN PRODUCTION):
#   The companion selftest at
#   `crab-meat-repos/stsgym-work/scripts/soc/test_wazuh_morning_highlights.py`
#   (8 tests, 38 assertions, ~5 s) calls this script as a subprocess with
#   these env vars to redirect mail to a localhost capture server and skip
#   live indexer calls. All hooks default to "production behavior" so the
#   real cron job is unaffected. The 5 hook knobs are:
#
#     1. WAZUH_HIGH_OVERRIDE_SMTP=1
#         Re-applies WAZUH_HIGH_SMTP_HOST / WAZUH_HIGH_SMTP_PORT *after*
#         the env-file source line (line 26) has already set SMTP_HOST/
#         SMTP_PORT for production. Without this hook, the env-file's
#         real mailbox creds win and the selftest can't redirect mail.
#         Sub-values:
#           WAZUH_HIGH_SMTP_HOST (default: unchanged)
#           WAZUH_HIGH_SMTP_PORT (default: unchanged)
#
#     2. WAZUH_HIGH_SKIP_SELFTEST=1
#         Bypass the /home/wez/bin/wazuh-indexer-selftest.sh pre-send
#         check. The selftest harness already exercises indexer auth
#         independently; running it again on every test fixture would
#         add ~2 s and risk a spurious FAIL when the capture race
#         window is short.
#
#     3. WAZUH_HIGH_ALERTS_JSON_PATH=/path/to/fixture.json
#         Skip the indexer query entirely and use the file contents
#         verbatim as ALERTS_JSON. The selftest writes synthetic
#         JSON to a temp file and points this at it. Lets the harness
#         exercise GREEN / YELLOW / RED classifier paths without
#         polluting the real indexer.
#
#     4. WAZUH_HIGH_SKIP_TLS=1
#         Skip STARTTLS in the send step. The capture server advertises
#         STARTTLS but doesn't implement TLS; skipping avoids a hung
#         handshake. Real mailboxes still use STARTTLS.
#
#     5. WAZUH_HIGH_SKIP_AUTH=1
#         Skip SMTP AUTH (`s.login()`). The capture server doesn't
#         implement AUTH (or implements a stub that accepts any creds);
#         skipping avoids the script's REPORTS_MAILBOX_PW check failing
#         on a port that doesn't speak AUTH.
#
#   Bonus abort hook (not used by the selftest but documented):
#     WAZUH_HIGH_SKIP_INDEXER=1 without WAZUH_HIGH_ALERTS_JSON_PATH
#         Aborts the script with a clear log line. Symmetric with the
#         "fixture bypass" intent: "if you wanted to skip the indexer,
#         you must provide a fixture." Catches test-harness typos.
#
#   The five primary hooks are exercised by the selftest at:
#     scripts/soc/test_wazuh_morning_highlights.py::run_script() —
#       env dict on lines ~368-374 sets all 5 + WAZUH_HIGH_SMTP_*
#     scripts/soc/test_wazuh_morning_highlights.py::test_smtp_failure_mode
#       — ditto, but WAZUH_HIGH_SMTP_PORT=1 (closed port) to force
#       SMTP-unreachable exit.
#
#   Hook history (what broke when, in order):
#     - 2026-08-15 01:30 UTC: WAZUH_HIGH_SKIP_SELFTEST added (indexer
#       pre-selftest was racing the capture server).
#     - 2026-08-15 01:45 UTC: WAZUH_HIGH_SKIP_TLS added (capture
#       advertised STARTTLS but didn't terminate TLS).
#     - 2026-08-15 02:00 UTC: WAZUH_HIGH_SKIP_AUTH added (script's
#       REPORTS_MAILBOX_PW call to s.login() required AUTH).
#     - 2026-08-15 02:10 UTC: WAZUH_HIGH_ALERTS_JSON_PATH added (live
#       indexer queries were too slow + non-deterministic for the
#       GREEN/YELLOW/RED classifier paths).
#     - 2026-08-15 02:13 UTC: WAZUH_HIGH_OVERRIDE_SMTP added (the env-
#       file source line was overwriting the test's SMTP_HOST=127.0.0.1
#       with the real mailbox host; the override re-applies the test's
#       values after the source).
#   Commits in `crab-meat-repos/stsgym-work` branch `feat/morning-
#   highlights-selftest` (commit 19adcb99) — the script-side changes
#   are host-side only; `/home/wez/bin/` is not git-tracked.

set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

REPORTS_ENV=/home/wez/.openclaw/workspace/secrets/reports-bedimsecurity-mailbox.env
for f in "$REPORTS_ENV"; do
  if [[ ! -r "$f" ]]; then
    logger -t wazuh-high "missing cred file: $f" 2>/dev/null || echo "missing $f" >&2
    exit 1
  fi
done
set -a; source "$REPORTS_ENV"; set +a

: "${SMTP_HOST:?must be set in $REPORTS_ENV}"
: "${SMTP_PORT:?must be set}"
: "${REPORTS_MAILBOX:?must be set}"
: "${REPORTS_MAILBOX_PW:?must be set}"

# Test hook: WAZUH_HIGH_OVERRIDE_SMTP=1 lets the caller override SMTP_HOST/
# SMTP_PORT after the production env file has been sourced. Used by the
# morning-highlights selftest to redirect mail to a local capture server.
# In production this stays off (default 0) so the real mailbox always wins.
if [[ "${WAZUH_HIGH_OVERRIDE_SMTP:-0}" == "1" ]]; then
  if [[ -n "${WAZUH_HIGH_SMTP_HOST:-}" ]]; then
    SMTP_HOST="$WAZUH_HIGH_SMTP_HOST"
  fi
  if [[ -n "${WAZUH_HIGH_SMTP_PORT:-}" ]]; then
    SMTP_PORT="$WAZUH_HIGH_SMTP_PORT"
  fi
  echo "[selftest] SMTP overridden to $SMTP_HOST:$SMTP_PORT" >&2
fi

WAZUH_INDEXER_URL="${WAZUH_INDEXER_URL:-https://127.0.0.1:9200}"
WAZUH_INDEXER_USERNAME="${WAZUH_INDEXER_USERNAME:-admin}"
WAZUH_INDEXER_PASSWORD="${WAZUH_INDEXER_PASSWORD:-SecretPassword}"
RECIPIENT="${WAZUH_REPORTS_RECIPIENT:-wlrobbi@gmail.com}"
LOGFILE="${LOGFILE:-/home/wez/logs/wazuh-high.log}"
mkdir -p "$(dirname "$LOGFILE")"

SINCE_TS=$(date -u -d '24 hours ago' +%FT%T 2>/dev/null || date -u -v-24H +%FT%T)
NOW_TS=$(date -u +%FT%T)
SUBJECT_DATE=$(date +%Y-%m-%d)
HIGH_THRESHOLD=10

# --- 0) Pre-send selftest (SOC 1.4) -------------------------------------
# Detect indexer problems BEFORE the main job uses them, so a broken
# auth / timeout / SSL cert / unreachable host doesn't silently produce
# no output (the "morning was quiet" failure mode that masks outages).
# On fail: selftest sends its own email and exits non-zero; this script
# exits too, so the cron's `||` alert path fires.
# Test hook: WAZUH_HIGH_SKIP_SELFTEST=1 bypasses the pre-selftest.
# Used by the morning-highlights selftest harness to avoid a redundant
# indexer round-trip (the selftest already exercises indexer auth).
if [[ "${WAZUH_HIGH_SKIP_SELFTEST:-0}" != "1" ]]; then
  LOG_TAG="${LOG_TAG:-wazuh-morning}" /home/wez/bin/wazuh-indexer-selftest.sh || {
    log "selftest FAILED — aborting morning-highlights before sending summary"
    exit 1
  }
fi

log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*"; }
exec >>"$LOGFILE" 2>&1
log "==== morning-highlights run start ===="

# --- 1) Query indexer for last 24h of high alerts -----------------------
# Test hook: if WAZUH_HIGH_ALERTS_JSON_PATH points to a readable file,
# skip the indexer query and use the file contents verbatim. Used by
# the morning-highlights selftest to exercise GREEN/YELLOW/RED paths
# with synthetic data without polluting the real indexer.
if [[ -n "${WAZUH_HIGH_ALERTS_JSON_PATH:-}" && -r "$WAZUH_HIGH_ALERTS_JSON_PATH" ]]; then
  ALERTS_JSON=$(cat "$WAZUH_HIGH_ALERTS_JSON_PATH")
  log "selftest: using fixture $WAZUH_HIGH_ALERTS_JSON_PATH (skipping indexer query)"
elif [[ -n "${WAZUH_HIGH_SKIP_INDEXER:-}" ]]; then
  log "selftest: WAZUH_HIGH_SKIP_INDEXER set but no fixture provided — aborting"
  exit 1
else
ALERTS_JSON=$(WAZUH_INDEXER_URL="$WAZUH_INDEXER_URL" WAZUH_INDEXER_USERNAME="$WAZUH_INDEXER_USERNAME" WAZUH_INDEXER_PASSWORD="$WAZUH_INDEXER_PASSWORD" python3 - "$SINCE_TS" "$NOW_TS" "$HIGH_THRESHOLD" <<'PY'
import os, sys, json, urllib.request, ssl, base64
from collections import Counter
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

levels = Counter(e["level"]    for e in out)
agents = Counter(e["agent"]    for e in out)
rules  = Counter((e["rule_id"], e["rule_desc"]) for e in out)

top = sorted(out, key=lambda e: -int(e["level"]))[:10]

print(json.dumps({
    "window":      {"since": since, "until": until},
    "threshold":   lvl_min,
    "total_high":  len(out),
    "by_level":    dict(sorted(levels.items(), key=lambda kv: -kv[0])),
    "top_rules":   [{"id": k[0], "description": k[1][:80], "count": v} for k,v in rules.most_common(10)],
    "top_agents":  [{"name": n, "count": c} for n,c in agents.most_common(5)],
    "top_events":  top,
}, indent=2, default=str))
PY
)
fi

if [[ $? -ne 0 ]]; then
  log "FAIL: indexer query"
  exit 1
fi

TOTAL=$(echo "$ALERTS_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['total_high'])")
log "indexer returned $TOTAL high alerts since $SINCE_TS"

# --- 1.5) SOC 2.4 -- classify severity + write heartbeat ---------------
# Status thresholds:
#   RED    -- any L>=13, OR 3+ L>=12, OR >10 high-severity alerts total
#   YELLOW -- 1+ high-severity alerts (L>=10) but not RED
#   GREEN  -- 0 high-severity alerts in window
# The snapshot path is computed up-front so the heartbeat can reference it.
SNAP="/tmp/wazuh-high-$(date -u +%FT%H%MZ).json"
META=$(echo "$ALERTS_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
by_level = d.get('by_level', {})
max_level = max(int(k) for k in by_level.keys()) if by_level else 0
l12_plus  = sum(int(c) for k, c in by_level.items() if int(k) >= 12)
print(f\"{max_level} {l12_plus}\")")
MAX_LEVEL=$(echo "$META" | awk '{print $1}')
L12_PLUS=$(echo "$META" | awk '{print $2}')

if [[ "$MAX_LEVEL" -ge 13 || "$L12_PLUS" -ge 3 || "$TOTAL" -gt 10 ]]; then
  STATUS=RED
elif [[ "$TOTAL" -gt 0 ]]; then
  STATUS=YELLOW
else
  STATUS=GREEN
fi
log "status=$STATUS (high=$TOTAL max_level=$MAX_LEVEL l12+=$L12_PLUS)"

# Write heartbeat file -- parseable shell-source + a flag for RED that other
# cron jobs / heartbeats can key off.
HEARTBEAT="${HEARTBEAT:-/home/wez/logs/wazuh-heartbeat.status}"
RED_FLAG="${RED_FLAG:-/home/wez/logs/wazuh-red-alerts.flag}"
mkdir -p "$(dirname "$HEARTBEAT")"
{
  echo "# Wazuh morning high-alert heartbeat (2.4)"
  echo "# Generated: $(date -u +%FT%TZ)"
  echo "STATUS=${STATUS}"
  echo "HIGH_COUNT=${TOTAL}"
  echo "MAX_LEVEL=${MAX_LEVEL}"
  echo "L12_PLUS=${L12_PLUS}"
  echo "THRESHOLD=${HIGH_THRESHOLD}"
  echo "WINDOW_SINCE=${SINCE_TS}"
  echo "WINDOW_UNTIL=${NOW_TS}"
  echo "SNAPSHOT=${SNAP}"
} > "$HEARTBEAT"
log "heartbeat written: $HEARTBEAT"

# Touch + content flag for RED so a downstream monitor can react.
if [[ "$STATUS" == "RED" ]]; then
  {
    echo "STATUS=RED"
    echo "SINCE=${SINCE_TS}"
    echo "HIGH_COUNT=${TOTAL}"
    echo "MAX_LEVEL=${MAX_LEVEL}"
    echo "L12_PLUS=${L12_PLUS}"
    echo "SNAPSHOT=${SNAP}"
  } > "$RED_FLAG"
  log "RED flag written: $RED_FLAG"
else
  rm -f "$RED_FLAG"
fi

# --- 2) Snapshot --------------------------------------------------------
printf '%s\n' "$ALERTS_JSON" > "$SNAP"
log "saved snapshot: $SNAP ($(wc -c < "$SNAP") bytes)"

# --- 3) Healthy green: send a short HEARTBEAT email so Wes knows the system
#     is alive, but skip the full analytics body.
if [[ "$TOTAL" == "0" ]]; then
  log "no high alerts in last 24h; sending GREEN heartbeat email"
  # GREEN path still writes the heartbeat (already done above) and sends a
  # single-line "all clear" email so the absence of high alerts is visible.
  SUBJECT="[GREEN] Wazuh morning ${SUBJECT_DATE} — no high-severity alerts"
  BODY=$(cat <<EOF
All clear. Wazuh had no high-severity alerts (L>=${HIGH_THRESHOLD}) in the last 24 h.

Window:  $SINCE_TS  ->  $NOW_TS UTC
Status:  GREEN
Threshold: level >= $HIGH_THRESHOLD

Heartbeat file: $HEARTBEAT
EOF
)
  SUBJECT=$(echo "$SUBJECT" | tr '\n' ' ' | cut -c1-200)
  log "sending GREEN heartbeat to $RECIPIENT"
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
msg["X-Wazuh-Report"] = "morning-highlights"
msg["X-Wazuh-Severity"] = "GREEN"

with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ["SMTP_PORT"]), timeout=20) as s:
    if os.environ.get("WAZUH_HIGH_SKIP_TLS") != "1":
        s.starttls(context=ctx)
    if os.environ.get("WAZUH_HIGH_SKIP_AUTH") != "1":
        s.login(os.environ["REPORTS_MAILBOX"], os.environ["REPORTS_MAILBOX_PW"])
    s.send_message(msg)

print("SENT")
PY
  RC=$?
  log "GREEN heartbeat exit=$RC"
  exit $RC
fi

# --- 4) Agent narrative -----------------------------------------------
NARRATIVE="(agent unavailable; raw stats below)"
if command -v openclaw >/dev/null 2>&1; then
  NARRATIVE=$(openclaw ask \
    --model ollama/minimax-m3:cloud \
    --system "You are a SOC analyst writing a brief morning report for an executive. Be terse. Highlight only meaningful events. Plain text, 1-3 short sentences plus 3-5 bullets. No markdown headers." \
    --format text --timeout 60 -- \
    "Analyse the following Wazuh high-severity alerts (level >= 10) JSON and produce a brief morning summary. Keep total under 200 words.\n\n$ALERTS_JSON" \
    2>/dev/null || echo "(agent failed; falling back to raw stats)")
  log "agent narrative: $(printf '%s' "$NARRATIVE" | wc -w) words"
fi

# --- 5) Build email ---------------------------------------------------
SUBJECT="[${STATUS}] Wazuh morning ${SUBJECT_DATE} — ${TOTAL} high-severity alert(s) (L>=${HIGH_THRESHOLD})"
SUBJECT=$(echo "$SUBJECT" | tr '\n' ' ' | cut -c1-200)

BODY=$(cat <<EOF
Wazuh morning high-alert summary for $SUBJECT_DATE — generated $NOW_TS UTC.

Window:    $SINCE_TS  ->  $NOW_TS UTC
Threshold: level >= $HIGH_THRESHOLD
Status:    ${STATUS}   (high_count=${TOTAL}, max_level=${MAX_LEVEL}, L>=12 count=${L12_PLUS})

$(if [[ "$STATUS" == "RED" ]]; then echo "*** RED ALERT *** — at least one of: max_level>=13, L12+ count>=3, or high_count>10. Escalate."; fi)

Total high-severity alerts: $TOTAL

--- SOC analyst summary ---

$NARRATIVE

--- Severity distribution ---

$(echo "$ALERTS_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
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

--- Top 10 high-severity events ---

$(echo "$ALERTS_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for e in d['top_events']:
    print(f\"  * L{e['level']}  rule {e['rule_id']}  agent {e['agent']} ({e['agent_ip']})  @ {e['timestamp']}\")
    print(f\"    {e['rule_desc']}\")
")

---
Generated by /home/wez/bin/wazuh-morning-highlights.sh (cron 0 8 * * *).
Snapshot:  $SNAP
Heartbeat: $HEARTBEAT
EOF
)

# --- 6) Send ----------------------------------------------------------
log "sending morning summary to $RECIPIENT (high_count=$TOTAL)"
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
msg["X-Wazuh-Report"] = "morning-highs"
msg["X-Wazuh-Severity"] = "${STATUS}"

with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ["SMTP_PORT"]), timeout=20) as s:
    if os.environ.get("WAZUH_HIGH_SKIP_TLS") != "1":
        s.starttls(context=ctx)
    if os.environ.get("WAZUH_HIGH_SKIP_AUTH") != "1":
        s.login(os.environ["REPORTS_MAILBOX"], os.environ["REPORTS_MAILBOX_PW"])
    s.send_message(msg)

print("SENT")
PY
RC=$?
log "exit=$RC"
exit $RC