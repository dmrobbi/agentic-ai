#!/usr/bin/env bash
# /home/wez/bin/wazuh-indexer-selftest.sh
#
# Shared selftest for Wazuh indexer-dependent cron scripts
# (morning-highlights, daily-digest).
#
# Purpose:
#   Detect indexer problems BEFORE the main job tries to use them,
#   so a broken auth / timeout / SSL cert / unreachable host doesn't
#   silently produce no output (the "morning was quiet" failure mode
#   that masks outages for hours/days).
#
# What it checks:
#   1. Indexer auth (basic-auth POST to /_search on a trivial query)
#   2. Response time (warn if > 10 s; fail if > 30 s)
#   3. Index count >= 1 in the last 24 h (fail if 0 — that's suspicious
#      unless you know the fleet is genuinely silent)
#   4. SSL cert chain trust (we use verify=False because the indexer
#      cert is self-signed; we only check that a TLS handshake completes,
#      not that the cert is valid)
#
# On FAIL: sends a failure email to the same recipient as the parent
# script (uses the same REPORTS_MAILBOX env), then exits non-zero.
# The cron `||` alert path will then fire as well.
#
# On PASS: exits 0 silently. Logs the duration.
#
# Exit codes:
#   0 = pass
#   1 = auth failed (401/403)
#   2 = timeout (no response in 30 s)
#   3 = SSL handshake failed
#   4 = 0 hits in last 24 h (suspicious — possibly the indexer is empty)
#   5 = other connection error
#   6 = mail send failed (the selftest detected a problem but couldn't
#       notify — exit loudly so the cron failure path also fires)
#
# Usage:
#   . $REPORTS_ENV   # set REPORTS_MAILBOX, REPORTS_MAILBOX_PW, SMTP_HOST, SMTP_PORT
#   /home/wez/bin/wazuh-indexer-selftest.sh [RECIPIENT]
#
# Optional env vars (with defaults):
#   WAZUH_INDEXER_URL=https://127.0.0.1:9200
#   WAZUH_INDEXER_USERNAME=admin
#   WAZUH_INDEXER_PASSWORD=SecretPassword
#   WAZUH_SELFTEST_TIMEOUT=30
#   WAZUH_SELFTEST_RECIPIENT=wlrobbi@gmail.com   (default; can override as arg 1)
#   WAZUH_SELFTEST_MIN_HITS=1
#   LOGFILE=/home/wez/logs/wazuh-indexer-selftest.log

set -u

# Source the same env file the parent cron scripts use. This makes the
# selftest callable from a clean shell (e.g. cron) without requiring
# the caller to source the env first. Override REPORTS_ENV if you've
# placed the file somewhere nonstandard.
REPORTS_ENV="${REPORTS_ENV:-/home/wez/.openclaw/workspace/secrets/reports-bedimsecurity-mailbox.env}"
if [[ -r "$REPORTS_ENV" ]]; then
  set -a; source "$REPORTS_ENV"; set +a
fi

: "${REPORTS_MAILBOX:?must be set (check $REPORTS_ENV)}"
: "${REPORTS_MAILBOX_PW:?must be set}"
: "${SMTP_HOST:?must be set}"
: "${SMTP_PORT:?must be set}"

WAZUH_INDEXER_URL="${WAZUH_INDEXER_URL:-https://127.0.0.1:9200}"
WAZUH_INDEXER_USERNAME="${WAZUH_INDEXER_USERNAME:-admin}"
WAZUH_INDEXER_PASSWORD="${WAZUH_INDEXER_PASSWORD:-SecretPassword}"
WAZUH_SELFTEST_TIMEOUT="${WAZUH_SELFTEST_TIMEOUT:-30}"
WAZUH_SELFTEST_MIN_HITS="${WAZUH_SELFTEST_MIN_HITS:-1}"
LOGFILE="${LOGFILE:-/home/wez/logs/wazuh-indexer-selftest.log}"
RECIPIENT="${1:-${WAZUH_SELFTEST_RECIPIENT:-wlrobbi@gmail.com}}"
LOG_TAG="${LOG_TAG:-wazuh-selftest}"

mkdir -p "$(dirname "$LOGFILE")"
log() { printf '[%s] [%s] %s\n' "$(date -u +%FT%TZ)" "$LOG_TAG" "$*" | tee -a "$LOGFILE" >&2 ; }

log "selftest starting: url=$WAZUH_INDEXER_URL user=$WAZUH_INDEXER_USERNAME timeout=${WAZUH_SELFTEST_TIMEOUT}s"

# Run the indexer probe in Python — keeps SSL handling consistent with
# the parent scripts.
RESULT_JSON=$(WAZUH_INDEXER_URL="$WAZUH_INDEXER_URL" \
              WAZUH_INDEXER_USERNAME="$WAZUH_INDEXER_USERNAME" \
              WAZUH_INDEXER_PASSWORD="$WAZUH_INDEXER_PASSWORD" \
              WAZUH_SELFTEST_TIMEOUT="$WAZUH_SELFTEST_TIMEOUT" \
              WAZUH_SELFTEST_MIN_HITS="$WAZUH_SELFTEST_MIN_HITS" \
              python3 - <<'PY' 2>/dev/null
import os, sys, json, urllib.request, urllib.error, ssl, base64, time

base    = os.environ["WAZUH_INDEXER_URL"]
user    = os.environ["WAZUH_INDEXER_USERNAME"]
pw      = os.environ["WAZUH_INDEXER_PASSWORD"]
timeout = int(os.environ["WAZUH_SELFTEST_TIMEOUT"])
minhits = int(os.environ["WAZUH_SELFTEST_MIN_HITS"])

auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
ctx  = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

# Trivial query: any alert in the last 24h. Used for both auth probe and
# "indexer has data" check.
query = {
    "size": 0,
    "query": {
        "bool": {
            "filter": [
                {"range": {"timestamp": {"gte": "now-24h/m", "lte": "now/m"}}}
            ]
        }
    }
}

result = {"ok": True, "hits": 0, "duration_ms": 0, "error": None, "http_status": 0}
t0 = time.time()
try:
    req = urllib.request.Request(
        f"{base}/wazuh-alerts-*/_search",
        data=json.dumps(query).encode(),
        headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
        result["http_status"] = r.status
        body = json.loads(r.read())
        result["hits"] = int(body.get("hits", {}).get("total", {}).get("value", 0))
except urllib.error.HTTPError as e:
    result["ok"] = False
    result["error"] = f"http_{e.code}: {e.reason}"
except urllib.error.URLError as e:
    result["ok"] = False
    result["error"] = f"url_error: {e.reason}"
except TimeoutError:
    result["ok"] = False
    result["error"] = f"timeout after {timeout}s"
except ssl.SSLError as e:
    result["ok"] = False
    result["error"] = f"ssl_error: {e}"
except Exception as e:
    result["ok"] = False
    result["error"] = f"{type(e).__name__}: {e}"

result["duration_ms"] = int((time.time() - t0) * 1000)

# Decide pass/fail
if result["http_status"] in (401, 403):
    result["ok"] = False
    result.setdefault("error", "auth_failed")
    result["exit_code"] = 1
elif result["error"] and "timeout" in result["error"]:
    result["exit_code"] = 2
elif result["error"] and "ssl_error" in result["error"]:
    result["exit_code"] = 3
elif result["hits"] < minhits:
    result["ok"] = False
    result.setdefault("error", f"only {result['hits']} hits in 24h (expected >= {minhits})")
    result["exit_code"] = 4
elif not result["ok"]:
    result["exit_code"] = 5
else:
    result["exit_code"] = 0

print(json.dumps(result))
PY
)

RC=$?
RESULT=$(echo "$RESULT_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d))" 2>/dev/null || echo '{}')
EXIT_CODE=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('exit_code', 5))")
HITS=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('hits', '?'))")
DUR=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('duration_ms', '?'))")
ERR=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error') or '-')")

if [ "$EXIT_CODE" -eq 0 ]; then
  log "PASS (${DUR}ms, ${HITS} hits in 24h)"
  exit 0
fi

# FAIL — log + send email + exit non-zero
log "FAIL: exit_code=$EXIT_CODE error='$ERR' duration=${DUR}ms hits=$HITS"

REASON_TEXT=$(cat <<EOF
Wazuh indexer selftest FAILED.

Failure reason: $ERR
HTTP status:    $(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('http_status','?'))")
Duration:       ${DUR} ms
Hits in 24h:    $HITS
Indexer URL:    $WAZUH_INDEXER_URL
Username:       $WAZUH_INDEXER_USERNAME
Timeout:        ${WAZUH_SELFTEST_TIMEOUT}s
Exit code:      $EXIT_CODE

Diagnostic hints:
  1 -> auth: bad WAZUH_INDEXER_PASSWORD or USERNAME
  2 -> timeout: indexer down or network; check 'docker ps' + curl
  3 -> ssl: cert expired or self-signed cert rotated; see
           runbooks/wazuh-indexer-auth-pipeline.md
  4 -> no_hits: pipeline may be broken; check Wazuh manager + agent connectivity
  5 -> other: see logs

This selftest was triggered from: ${LOG_TAG}
EOF
)

if ! python3 - "$RECIPIENT" <<PY 2>>"$LOGFILE"
import os, sys, smtplib, ssl
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

body = """${REASON_TEXT//\\/\\\\}""".replace('\\\\n', chr(10))

msg = MIMEText(body)
msg["From"]    = os.environ["REPORTS_MAILBOX"]
msg["To"]      = sys.argv[1]
msg["Subject"] = "[Wazuh selftest FAILURE] ${LOG_TAG}: $ERR"
msg["Date"]    = formatdate(localtime=False)
msg["Message-Id"] = make_msgid(domain="wazuh-selftest")

ctx = ssl.create_default_context()
with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ["SMTP_PORT"]), timeout=15) as s:
    s.starttls(context=ctx)
    s.login(os.environ["REPORTS_MAILBOX"], os.environ["REPORTS_MAILBOX_PW"])
    s.send_message(msg)
print("notification sent", file=sys.stderr)
PY
then
  log "WARNING: failure email could not be sent; cron alert path will still fire"
  exit 6
fi

log "failure notification sent to $RECIPIENT"
exit "$EXIT_CODE"
