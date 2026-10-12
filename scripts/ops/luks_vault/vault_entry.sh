#!/usr/bin/env bash
# vault_entry.sh - LUKS2 vault entry/worker (container side).
#
# Runs as the compose service's pid1 with mode "wait": an interruptible
# idle loop carrying the SIGTERM/SIGINT trap that locks the vault (unmount
# + luksClose) when the container is stopped - after that the LUKS image
# inside the volume sits LOCKED (ciphertext at rest, no mapper, no
# plaintext device). Every other mode is a short stateless operation
# invoked via `docker compose exec`; all credentials travel by STDIN and
# are shredded immediately after use; nothing is echoed but markers.
#
# Scratch rail (the LUKS campaign's standing rule): the selftest runs on
# a /tmp scratch image only; the real vault image in /vault is untouched
# by it. Block-device ops stay consent-gated on the host.
set -euo pipefail

VAULT_DIR="${VAULT_DIR:-/vault}"
IMG="$VAULT_DIR/vault.img"
MAPPER="${MAPPER_NAME:-vaultvol}"
MNT="/mnt/$MAPPER"
CS=/usr/sbin/cryptsetup
MKFS=/usr/sbin/mkfs.ext4
TUNE=/usr/sbin/tune2fs

_mode_tpm_enroll() {
    [ -e "$IMG" ] || { echo "no vault image" >&2; exit 1; }
    # SYSTEMD enrollment: the seal binds THIS chip's measured PCRs (default
    # incl. PCR7/SecureBoot state) - after this the payload's key can only
    # be unsealed on the machine carrying the TPM the seal landed on. The
    # passphrase slot stays as the recovery backup. The EXISTING credential
    # travels by STDIN (the same discipline as create/unlock): staged 0600,
    # handed via --unlock-key-file, then shredded - never argv/env/disk-rest.
    local stage=/run/stage-enroll.key rc=0
    cat > "$stage"
    chmod 600 "$stage"
    if systemd-cryptenroll --tpm2-device=auto --unlock-key-file="$stage" "$IMG"; then
        echo "VAULT-TPM-ENROLL-OK (key sealed to this machine's TPM)"
    else
        rc=1
        echo "VAULT-TPM-ENROLL-FAILED (the TPM seal did not land)" >&2
    fi
    shred -u "$stage"
    return "$rc"
}

_mode_tpm_unlock() {
    [ -e "$IMG" ] || { echo "no vault image" >&2; exit 1; }
    # SYSTEMD TPM2-backed unseal through the cryptsetup CLI's token path:
    # --token-only = the enrolled binding or NOTHING (no ask-password agent,
    # no hang; stdin closed = the token's absence fails fast). The plain
    # systemd-cryptsetup attach wedges on its ask-password FIFO when the
    # unseal fails - measured tonight; the CLI path is the robust one.
    "$CS" open --token-only "$IMG" "$MAPPER" < /dev/null || { echo "VAULT-TPM-UNSEAL-FAILED" >&2; exit 1; }
    # one-time filesystem: mkfs.ext4 only when the payload has no ext4 yet
    if ! "$TUNE" -l "/dev/mapper/$MAPPER" >/dev/null 2>&1; then
        "$MKFS" -q "/dev/mapper/$MAPPER"
    fi
    mkdir -p "$MNT"
    mount "/dev/mapper/$MAPPER" "$MNT" || { echo "VAULT-TPM-MOUNT-FAILED" >&2; exit 1; }
    chown "$(id -u):$(id -g)" "$MNT"
    echo "VAULT-TPM-UNLOCK-OK mapper=$MAPPER mnt=$MNT"
}

_lock_now() {
    if command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$MNT" 2>/dev/null; then
        umount "$MNT"
    fi
    if "$CS" status "$MAPPER" >/dev/null 2>&1; then
        "$CS" luksClose "$MAPPER"
    fi
    return 0
}

trap '_lock_now; exit 0' TERM INT

_usage() {
    cat >&2 <<'USAGE'
usage: vault_entry.sh <mode>
  wait     pid1: idle loop; locks the vault on SIGTERM/SIGINT (the stop mechanic)
  create <mb> [stdin: passphrase]  urandom-fill + luksFormat; the keyslot binds YOUR credential -> VAULT-CREATE-OK
  unlock   stdin: passphrase  open mapper (+one-time mkfs/mount when the payload has no ext4 fs yet), shred the staged key -> VAULT-UNLOCK-OK
  lock     unmount + luksClose -> VAULT-LOCK-OK
  tpm-enroll [stdin: passphrase]  seal the payload key to THIS machine's TPM (systemd-cryptenroll) -> VAULT-TPM-ENROLL-OK
  tpm-unlock   open via the enrolled TPM binding (no stdin passphrase) -> VAULT-TPM-UNLOCK-OK
  status   isLuks + mapper state + img stat -> VAULT-LOCKED | VAULT-OPENED
  selftest the full loop on a /tmp scratch image (the real vault untouched) -> VAULT-SELFTEST-OK
USAGE
    exit 2
}

_mode_create() {
    local size_mb
    size_mb="${1:-}"
    case "$size_mb" in ''|*[!0-9]*) echo "bad size; usage: printf '%s' '<passphrase>' | vault_entry create <size_mb>" >&2; exit 2;; esac
    [ "$size_mb" -ge 1 ] && [ "$size_mb" -le 4096 ] || { echo "size out of range" >&2; exit 2; }
    [ -e "$IMG" ] && { echo "vault image already exists" >&2; exit 1; }
    cat > /run/stage-create.key
    chmod 600 /run/stage-create.key
    [ -s /run/stage-create.key ] || { shred -u /run/stage-create.key; echo "empty credential" >&2; exit 1; }
    dd if=/dev/urandom "of=$IMG" "bs=1M" "count=$size_mb" status=none
    chmod 600 "$IMG"
    # the OPERATOR's credential via stdin, staged as a real 0600 file
    # (whole-file semantics; no process substitution; a hardcoded key
    # would be a repo-readable secret - never again)
    "$CS" luksFormat --type luks2 \
        --cipher aes-xts-plain64 --key-size 256 --hash sha256 \
        --pbkdf pbkdf2 --pbkdf-force-iterations 1000000 --use-random \
        "$IMG" --key-file=/run/stage-create.key --batch-mode
    shred -u /run/stage-create.key
    echo "VAULT-CREATE-OK size_mb=$size_mb"
}

_mode_unlock() {
    [ -e "$IMG" ] || { echo "no vault image" >&2; exit 1; }
    cat > /run/unlock.key
    chmod 600 /run/unlock.key
    if [ ! -s /run/unlock.key ]; then shred -u /run/unlock.key; echo "empty credential" >&2; exit 1; fi
    # negative pre-check: the credential must work BEFORE the mapper opens
    if ! "$CS" open --test-passphrase "$IMG" --key-file=/run/unlock.key >/dev/null 2>&1; then
        shred -u /run/unlock.key
        echo "VAULT-CREDENTIAL-REJECTED"
        exit 1
    fi
    "$CS" luksOpen "$IMG" "$MAPPER" --key-file=/run/unlock.key
    shred -u /run/unlock.key
    # one-time filesystem: mkfs.ext4 only when the payload has no ext4 yet
    if ! "$TUNE" -l "/dev/mapper/$MAPPER" >/dev/null 2>&1; then
        "$MKFS" -q "/dev/mapper/$MAPPER"
    fi
    mkdir -p "$MNT"
    mount "/dev/mapper/$MAPPER" "$MNT"
    chown "$(id -u):$(id -g)" "$MNT"
    echo "VAULT-UNLOCK-OK mapper=$MAPPER mnt=$MNT"
}

_mode_status() {
    if [ ! -e "$IMG" ]; then echo "VAULT-NONE"; exit 1; fi
    "$CS" isLuks "$IMG" && echo "VAULT-IMG-LUKS2-OK size=$(stat -c%s "$IMG")" || { echo "VAULT-IMG-NOT-LUKS" >&2; exit 1; }
    if "$CS" status "$MAPPER" >/dev/null 2>&1; then
        echo "VAULT-OPENED mapper=$MAPPER"
    else
        echo "VAULT-LOCKED no-mapper"
    fi
}

_mode_selftest() {
    # throwaway scratch image inside the container; the real vault untouched
    local img=/tmp/luks-selftest.img
    rm -f "$img"
    dd if=/dev/urandom "of=$img" bs=1M count=40 status=none
    printf '%s' 'selftest-cred-2026' > /tmp/st.key
    chmod 600 /tmp/st.key
    "$CS" luksFormat --type luks2 \
        --cipher aes-xts-plain64 --key-size 256 --hash sha256 \
        --pbkdf pbkdf2 --pbkdf-force-iterations 1000000 --use-random \
        "$img" --key-file=/tmp/st.key --batch-mode
    "$CS" isLuks "$img"
    "$CS" luksOpen "$img" selftestvol --key-file=/tmp/st.key
    "$MKFS" -q /dev/mapper/selftestvol
    mkdir -p /mnt/selftest
    mount /dev/mapper/selftestvol /mnt/selftest
    printf 'canary-%s\n' "$(date -u +%s)" | tee /mnt/selftest/canary.txt >/dev/null
    C=$(cat /mnt/selftest/canary.txt)
    [ -n "$C" ] || { echo "canary write failed" >&2; exit 1; }
    if "$CS" open --test-passphrase "$img" --key-file=/tmp/wrong-cred 2>/dev/null; then
        echo "negative control FAILED" >&2; exit 1;
    fi
    printf '%s' 'not-the-credential' > /tmp/wrong-cred
    chmod 600 /tmp/wrong-cred
    if "$CS" open --test-passphrase "$img" --key-file=/tmp/wrong-cred 2>/dev/null; then
        echo "negative control FAILED (wrong cred accepted)" >&2; exit 1;
    fi
    umount /mnt/selftest && "$CS" luksClose selftestvol
    if "$CS" status selftestvol >/dev/null 2>&1; then
        echo "mapper did not close" >&2; exit 1;
    fi
    # locked-at-rest proof: the canary's plaintext must NOT be in the img
    if grep -a -q "$C" "$img" 2>/dev/null; then
        echo "plaintext leaked into the locked image" >&2; exit 1;
    fi
    rm -f "$img" /tmp/st.key /tmp/wrong-cred
    rmdir /mnt/selftest 2>/dev/null
    echo "VAULT-SELFTEST-OK (format/unlock/mount/canary/negatives/lock/leak-check)"
}

[ $# -ge 1 ] || _usage
case "$1" in
    wait)
        touch /run/vault-entry-ready
        while :; do sleep 60 & wait $!; done
        ;;
    create) _mode_create "${2:-}" ;;
    tpm-enroll) _mode_tpm_enroll ;;
    tpm-unlock) _mode_tpm_unlock ;;
    unlock) _mode_unlock ;;
    lock) _lock_now; echo "VAULT-LOCK-OK mapper=$MAPPER" ;;
    status) _mode_status ;;
    selftest) _mode_selftest ;;
    *) _usage ;;
esac