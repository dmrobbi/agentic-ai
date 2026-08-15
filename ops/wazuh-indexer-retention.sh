#!/bin/bash
# wazuh-indexer-retention.sh
#
# Defense-in-depth for the wazuh indexer's ISM policy. The policy says
# "delete after 365 days", but if the indexer stops running, ISM doesn't
# run. So we also:
# 1. Check the indexer disk usage; alert if > 80%
# 2. Delete wazuh-alerts-* indices older than 365 days as a safety net
#
# Run daily via cron (03:30 UTC, after the 03:00 backup).
# Emits a one-line status to stdout; non-zero on disk alert.

set -euo pipefail

INDEXER_CONTAINER="${INDEXER_CONTAINER:-wazuh-stack_wazuh.indexer_1}"
INDEXER_PASSWORD="${INDEXER_PASSWORD:-SecretPassword}"
MAX_DAYS="${MAX_DAYS:-365}"
DISK_WARN_PCT="${DISK_WARN_PCT:-80}"
LOG="${LOG:-/home/wez/logs/wazuh-indexer-retention.log}"

mkdir -p "$(dirname "$LOG")"
log() { echo "[$(date -u +%FT%TZ)] $*" | tee -a "$LOG"; }

command -v docker >/dev/null 2>&1 || { log "ERROR: docker not on PATH"; exit 2; }
docker ps --format '{{.Names}}' | grep -q "^${INDEXER_CONTAINER}$" \
  || { log "ERROR: indexer $INDEXER_CONTAINER not running"; exit 2; }

# 1. Disk usage check
DISK_PCT=$(docker exec "$INDEXER_CONTAINER" bash -c \
  'df -P /var/lib/wazuh-indexer 2>/dev/null | tail -1 | awk "{print \$5}" | tr -d "%"' 2>/dev/null || echo "?")
if [ "$DISK_PCT" != "?" ] && [ "$DISK_PCT" -ge "$DISK_WARN_PCT" ] 2>/dev/null; then
  log "WARN: indexer disk at ${DISK_PCT}% (threshold ${DISK_WARN_PCT}%)"
fi

# 2. Get list of wazuh-alerts-* indices with their age
INDICES=$(docker exec "$INDEXER_CONTAINER" bash -c \
  'curl -sS -k -u "'"$INDEXER_PASSWORD"':'"$INDEXER_PASSWORD"'" \
   "https://localhost:9200/_cat/indices/wazuh-alerts-*?h=index,creation.date&format=json" 2>/dev/null' \
  | python3 -c "
import json, sys, time
data = json.load(sys.stdin)
now = int(time.time())
for entry in data:
    idx = entry.get('index', '')
    ct = entry.get('creation.date', 0) / 1000
    age_days = (now - ct) / 86400
    if age_days > $MAX_DAYS:
        print(idx, int(age_days))
" 2>/dev/null)

if [ -z "$INDICES" ]; then
  log "OK: no wazuh-alerts-* indices older than ${MAX_DAYS} days (disk ${DISK_PCT}%)"
  exit 0
fi

DELETED=0
while read -r idx age; do
  log "DELETING: $idx (${age} days old, max=${MAX_DAYS})"
  docker exec "$INDEXER_CONTAINER" bash -c \
    "curl -sS -k -u 'admin:${INDEXER_PASSWORD}' -X DELETE 'https://localhost:9200/${idx}' 2>&1" \
    | head -1
  DELETED=$((DELETED+1))
done <<< "$INDICES"

log "DONE: deleted $DELETED old wazuh-alerts-* indices (disk ${DISK_PCT}%)"
exit 0
