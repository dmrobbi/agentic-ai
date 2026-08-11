#!/bin/bash
# prune-runner-caches.sh
#
# Removes orphaned GitLab Runner cache volumes from /var/lib/docker/volumes.
# A "cache" volume is one whose name starts with `runner-` and contains
# `_data/` (vs the runner's own config volume). Orphaned = not mounted by
# any running container AND older than MAX_AGE_DAYS.
#
# Why this exists:
#   The GitLab Runner on thing1 has disable_cache=false and volume_keep=false,
#   but cache volumes created during builds are NEVER garbage-collected by
#   the runner. They pile up indefinitely. As of 2026-08-11 there are 777
#   of them totaling ~92 GB on thing1's root volume (disk at 80%).
#
#   Caches are build artifacts (Go module cache, apt cache, etc.) —
#   regenerable. Safe to delete as long as no build is currently using them.
#
# Safety:
#   1. Skip any volume currently mounted by a running container.
#   2. Skip any volume younger than MAX_AGE_DAYS (default 14).
#   3. Default to dry-run; pass --apply to actually remove.
#   4. Always log what it would / did remove.
#
# Usage:
#   sudo /home/wez/.openclaw/workspace/agentic-ai/ops/prune-runner-caches.sh [--apply]
#   (must run as root or via sudo — /var/lib/docker/volumes is not
#   world-readable on Ubuntu.)
#
# Cron: daily 04:30 UTC after the Wazuh backup at 03:00 UTC.
#   30 4 * * * root /home/wez/.openclaw/workspace/agentic-ai/ops/prune-runner-caches.sh --apply
#
# Exit codes:
#   0 = success (including dry-run with no errors)
#   1 = required tool missing (docker)
#   2 = safety check failed (e.g. can't read docker volume dir)

set -euo pipefail

MAX_AGE_DAYS="${MAX_AGE_DAYS:-14}"
DRY_RUN=1
[ "${1:-}" = "--apply" ] && DRY_RUN=0

LOG="${LOG:-/home/wez/logs/prune-runner-caches.log}"
VOLUMES_ROOT="${VOLUMES_ROOT:-/var/lib/docker/volumes}"

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not on PATH" >&2; exit 1; }
mkdir -p "$(dirname "$LOG")"

log() { echo "[$(date -u +%FT%TZ)] $*" | tee -a "$LOG" >&2; }

[ -d "$VOLUMES_ROOT" ] || { log "ERROR: $VOLUMES_ROOT not readable (try sudo)"; exit 2; }

# Collect volumes currently in use by any running container.
# docker ps + docker inspect each container for its mounts.
USED_VOLUMES=$(
  docker ps --format '{{.Names}}' | while read -r c; do
    docker inspect "$c" --format '{{json .Mounts}}' 2>/dev/null \
      | python3 -c "
import json, sys, re
for m in json.load(sys.stdin):
    src = m.get('Source','')
    name = re.sub(r'^.*/volumes/', '', src)
    if name and (name.startswith('runner-') or '-cache-' in name):
        print(name)
" 2>/dev/null
  done
)

# Strip the absolute prefix docker inspect returns.
USED_BASENAMES=$(
  echo "$USED_VOLUMES" | awk -F/ '{print $NF}' | sort -u
)

USED_COUNT=$(echo -n "$USED_BASENAMES" | grep -c . || true)
log "=== prune-runner-caches.sh ==="
log "Mode: $([ $DRY_RUN -eq 1 ] && echo 'DRY RUN' || echo 'APPLY')"
log "Max age: $MAX_AGE_DAYS days"
log "Volumes currently in use (will be skipped): $USED_COUNT"

# Walk volumes.
PRUNE_LIST=$(mktemp)
TOTAL_BYTES=0
COUNT=0
NOW=$(date +%s)

for v in "$VOLUMES_ROOT"/runner-*/; do
  [ -d "$v/_data" ] || continue
  name=$(basename "$v")
  # Skip if in use
  if echo "$USED_BASENAMES" | grep -qx "$name"; then
    log "  skip (in use): $name"
    continue
  fi
  # Age check on _data mtime
  mtime=$(stat -c %Y "$v/_data" 2>/dev/null || echo 0)
  age_days=$(( (NOW - mtime) / 86400 ))
  if [ "$age_days" -lt "$MAX_AGE_DAYS" ]; then
    log "  skip (recent, ${age_days}d): $name"
    continue
  fi
  size=$(du -sb "$v/_data" 2>/dev/null | awk '{print $1}')
  printf "%d\t%s\n" "${size:-0}" "$name" >> "$PRUNE_LIST"
  TOTAL_BYTES=$((TOTAL_BYTES + ${size:-0}))
  COUNT=$((COUNT + 1))
done

# Sort biggest first so a long-running prune makes the most space fast.
sort -rn "$PRUNE_LIST" > "$PRUNE_LIST.sorted"
mv "$PRUNE_LIST.sorted" "$PRUNE_LIST"

log "Candidates: $COUNT volumes, $((TOTAL_BYTES / 1024 / 1024)) MB ($((TOTAL_BYTES / 1024 / 1024 / 1024)) GB)"

if [ $DRY_RUN -eq 1 ]; then
  log "Dry-run mode; top 10 candidates:"
  head -10 "$PRUNE_LIST" | while IFS=$'\t' read -r size name; do
    log "  $((size / 1024 / 1024)) MB  $name"
  done
  log "Re-run with --apply to actually remove."
else
  log "Removing..."
  while IFS=$'\t' read -r size name; do
    [ -z "$name" ] && continue
    if docker volume rm "$name" 2>/dev/null; then
      log "  removed: $name ($((size / 1024 / 1024)) MB)"
    else
      log "  FAILED: $name (may be in use by a job that just started)"
    fi
  done < "$PRUNE_LIST"
  # Report new disk usage
  NEW_USED=$(df --output=used -h / | tail -1 | tr -d ' ')
  NEW_PCT=$(df --output=pcent / | tail -1 | tr -d ' ')
  log "Disk after: $NEW_USED used ($NEW_PCT of /)"
fi

rm -f "$PRUNE_LIST"
exit 0
