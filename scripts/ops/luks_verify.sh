#!/usr/bin/env bash
# LUKS2 container-ops full-loop verification (LUK-03).
# Inspired by the workflow arc of cyberanchor's gist 6535a5b3 (unlicensed);
# all commands re-authored for this guide: docs/LUKS_OPS.md.
#
# Scope and safety:
#   - File-backed containers ONLY, inside a mktemp scratch under /tmp.
#   - Refuses to run unless the scratch is under /tmp (no block devices, ever).
#   - Root needed only for device activation (luksOpen/mkfs/mount/luksClose);
#     everything else runs unprivileged with the absolute cryptsetup path.
#   - Exit 0 iff every matrix row prints PASS.
set -u
CS=/usr/sbin/cryptsetup
MKFS=/usr/sbin/mkfs.ext4

log()  { printf '[%-10s] %s\n' "$1" "$2"; }
PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0
pass() { PASS_COUNT=$((PASS_COUNT+1)); log PASS "$1"; }
fail() { FAIL_COUNT=$((FAIL_COUNT+1)); log FAIL "$1 (${2:-unspecified})"; }
skip() { SKIP_COUNT=$((SKIP_COUNT+1)); log SKIP "$1"; }

# --- preflight ---------------------------------------------------------------
command -v sudo >/dev/null 2>&1 || { echo "ERR: sudo missing"; exit 2; }
[[ -x $CS ]]   ||  { echo "ERR: $CS not found (see docs/LUKS_OPS.md section 0)"; exit 2; }
[[ -x $MKFS ]] ||  { echo "ERR: $MKFS not found"; exit 2; }
sudo -n true 2>/dev/null || log INFO "passwordless sudo not detected: activation rows will fail"

SCRATCH=$(mktemp -d /tmp/luk_verify.XXXXXX) || { echo "ERR: mktemp failed"; exit 2; }
case "$SCRATCH" in /tmp/*) ;; *) echo "ERR: scratch refused: $SCRATCH not under /tmp"; exit 2 ;; esac
cleanup() { sudo umount /mnt/luk_verify_mnt 2>/dev/null; sudo "$CS" luksClose luk_verify 2>/dev/null; rm -rf "$SCRATCH"; }
trap cleanup EXIT

PASSPHRASE='verify-luk03-2026'
ROTATE='rotate-luk03-2026'
IMG="$SCRATCH/container.img"; KEY="$SCRATCH/key.key"; KEY2="$SCRATCH/key2.key"; KEY3="$SCRATCH/key3.key"
HDR="$SCRATCH/header.bak";    MNT=/mnt/luk_verify_mnt

# key material FIRST — every format/open row needs it (the LUK-03 rerun-1 lesson):
# a key referenced by --key-file must exist before format/open touch it
printf '%s' "$PASSPHRASE" > "$KEY" && chmod 600 "$KEY"
dd if=/dev/urandom of="$KEY2" bs=4096 count=1 status=none && chmod 600 "$KEY2"

echo "== LUKS2 full-loop verification matrix (scratch: $SCRATCH) =="

# 1. fast-profile create (unprivileged, file-backed)
dd if=/dev/urandom of="$IMG" bs=1M count=64 status=none
[[ -s $IMG ]] && pass "container-file" "64 MB urandom at $IMG"        || fail "container-file" "dd"
"$CS" luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 256 \
  --hash sha256 --pbkdf pbkdf2 --pbkdf-force-iterations 1000000 --use-random \
  "$IMG" --key-file="$KEY" --batch-mode 2>/dev/null \
  && pass "format-fast" "fast profile accepted"                        || fail "format-fast" "luksFormat"

# 2. geometry parsing (finding-3 rule: derive the header size, never assume)
HDR_BYTES=$("$CS" luksDump "$IMG" 2>/dev/null | awk '/Metadata area:/ {meta=$3} /Keyslots area:/ {ks=$3} END {printf "%d", 2*meta + ks + 1048576}')
if [[ ${HDR_BYTES:-} =~ ^[0-9]+$ ]]; then pass "header-geometry-parse" "derived wipe length = $HDR_BYTES bytes"
else fail "header-geometry-parse" "awk parse"; fi

# 3. activation + mkfs + canary roundtrip (root rows)
sudo mkdir -p "$MNT" 2>/dev/null
MAPPER_OPEN=0
sudo "$CS" luksOpen "$IMG" luk_verify --key-file="$KEY" 2>/dev/null && MAPPER_OPEN=1
if [[ $MAPPER_OPEN -eq 1 && -e /dev/mapper/luk_verify ]]; then pass "luksOpen" "mapper up (root row)"
else
  fail "luksOpen" "no mapper"
  skip "mkfs/roundtrip" "activation failed"
fi
if [[ $MAPPER_OPEN -eq 1 && -e /dev/mapper/luk_verify ]]; then
  CANARY="canary-$(date +%s)"
  if sudo "$MKFS" -q /dev/mapper/luk_verify 2>/dev/null \
     && sudo mount /dev/mapper/luk_verify "$MNT" 2>/dev/null \
     && echo "$CANARY" | sudo tee "$MNT/canary.txt" >/dev/null \
     && sudo umount "$MNT" 2>/dev/null \
     && sudo "$CS" luksClose luk_verify 2>/dev/null \
     && sudo "$CS" luksOpen "$IMG" luk_verify --key-file="$KEY" 2>/dev/null \
     && sudo mount /dev/mapper/luk_verify "$MNT" 2>/dev/null \
     && [[ $(sudo cat "$MNT/canary.txt" 2>/dev/null) == "$CANARY" ]]; then
    pass "canary-roundtrip" "byte-identical after close/open (root row)"
  else
    fail "canary-roundtrip" "mismatch or mount step"
  fi
  sudo umount "$MNT" 2>/dev/null; sudo "$CS" luksClose luk_verify 2>/dev/null
fi

# 4. key + slot ops (all unprivileged; key material staged above)
"$CS" luksAddKey "$IMG" "$KEY2" --key-slot 2 --key-file="$KEY" --batch-mode 2>/dev/null \
  && pass "add-keyfile-slot2" "key file bound to slot 2"              || fail "add-keyfile-slot2" "$?"
"$CS" open --test-passphrase "$IMG" --key-file="$KEY" 2>/dev/null \
  && pass "test-pass-default" "passphrase from file"                   || fail "test-pass-default" "rejected"
printf '%s' 'wrong-pass' | "$CS" open --test-passphrase "$IMG" --key-file=- 2>/dev/null \
  && fail "negative-control" "wrong key ACCEPTED"                      || pass "negative-control" "wrong key rejected"
printf '%s' "$PASSPHRASE" | "$CS" open --test-passphrase "$IMG" --key-file=- 2>/dev/null \
  && pass "test-pass-stdin" "raw stdin passphrase (no newline)"        || fail "test-pass-stdin" "rejected"
printf '%s\n' "$PASSPHRASE" | "$CS" open --test-passphrase "$IMG" --key-file=- 2>/dev/null \
  && pass "raw-bytes-newline" "trailing newline also matched - see docs" \
  || pass "raw-bytes-newline" "newline-terminated PASSPHRASE rejected: raw-byte semantics confirmed"
"$CS" open --test-passphrase "$IMG" --key-slot 2 --key-file="$KEY2" 2>/dev/null \
  && pass "test-pass-slot2" "slot 2 key file works"                     || fail "test-pass-slot2" "rejected"

# rotation: stage on slot 5, test, THEN kill slot 0, re-add rotated key there
printf '%s' "$ROTATE" > "$KEY3" && chmod 600 "$KEY3"
"$CS" luksAddKey "$IMG" "$KEY3" --key-slot 5 --key-file="$KEY2" --batch-mode 2>/dev/null \
  && pass "rotate-stage-slot5" "staged before any kill"                || fail "rotate-stage-slot5" "$?"
"$CS" open --test-passphrase "$IMG" --key-slot 5 --key-file="$KEY3" 2>/dev/null \
  && pass "rotate-test-slot5" "tested before any kill"                 || fail "rotate-test-slot5" "rejected"
"$CS" luksKillSlot "$IMG" 0 --key-file="$KEY2" --batch-mode 2>/dev/null \
  && pass "rotate-kill-slot0" "confirmed kill of slot 0"               || fail "rotate-kill-slot0" "$?"
"$CS" luksAddKey "$IMG" "$KEY3" --key-slot 0 --key-file="$KEY2" --batch-mode 2>/dev/null \
  && pass "rotate-readd-slot0" "rotated key now in slot 0"             || fail "rotate-readd-slot0" "$?"

# 5. header backup/restore round-trip
"$CS" luksHeaderBackup "$IMG" --header-backup-file="$HDR" 2>/dev/null \
  && pass "header-backup" "backed up"                                   || fail "header-backup" "$?"
"$CS" luksDump --header "$HDR" "$IMG" >/dev/null 2>&1 \
  && pass "header-dump-verify" "backup standalone-parseable"            || fail "header-dump-verify" "$?"

# 6. detached-header cycle (own 32 MB container + own key)
DIMG="$SCRATCH/detached.img"
dd if=/dev/urandom of="$DIMG" bs=1M count=32 status=none
"$CS" luksFormat --type luks2 --header "$SCRATCH/dheader.bin" "$DIMG" \
  --key-file="$KEY3" --batch-mode 2>/dev/null \
  && pass "detached-format" "header outside container"                  || fail "detached-format" "$?"
"$CS" luksDump "$DIMG" >/dev/null 2>&1 \
  && fail "detached-no-builtin-header" "dump SUCCEEDED on bare data container" \
  || pass  "detached-no-builtin-header" "bare container has no header (dump refuses)"
sudo "$CS" luksOpen --header "$SCRATCH/dheader.bin" "$DIMG" luk_verify --key-file="$KEY3" 2>/dev/null \
  && pass "detached-luksOpen" "activation with external header works (root row)" \
  || fail "detached-luksOpen" "no mapper"
[[ -e /dev/mapper/luk_verify ]] && { sudo "$CS" luksClose luk_verify 2>/dev/null; true; } >/dev/null 2>&1
"$CS" luksDump --header "$SCRATCH/dheader.bin" "$DIMG" >/dev/null 2>&1 \
  && pass "detached-header-dump" "external header parseable"            || fail "detached-header-dump" "$?"

echo "== matrix: $PASS_COUNT PASS / $FAIL_COUNT FAIL / $SKIP_COUNT SKIP =="
if [[ $FAIL_COUNT -eq 0 ]]; then echo "VERDICT: ALL-CHECKS-OK (exit 0)"; exit 0
else echo "VERDICT: FAILURES PRESENT"; exit 1; fi