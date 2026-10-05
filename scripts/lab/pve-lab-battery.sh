#!/bin/bash
# KA-095 pve-lab battery playbook - MANUAL EXECUTOR ONLY; CI never runs this.
# Owner gate: --reset/--run refuse without KA_BATTERY_CONSENT=1 in env.
set -u

LAB_DIR="$HOME/verify-aai/pve-vm"
DISK="$LAB_DIR/rocky-scan-disk.qcow2"
KEYFILE="$LAB_DIR/pve-pilot-key"
PORT=2226
SNAP_NAME=pristine
CONSENT_VAR=KA_BATTERY_CONSENT

say() { echo "[battery] $*"; }
die() { say "FATAL: $*"; exit "${2:-1}"; }

SSH_OPTS=(-i "$KEYFILE" -p "$PORT"
          -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null
          -o BatchMode=yes -o ConnectTimeout=10)
TARGET=root@localhost

qemu_pids() { pgrep -f 'qemu-system.*rocky-scan-disk[.]qcow2' 2>/dev/null; }

consent_refused() {
  [ "${!CONSENT_VAR:-}" = "1" ] && return 0
  say "REFUSED: executing modes need $CONSENT_VAR=1 (owner gate; see docs/KA-LAB-TARGET.md)"
  exit 2
}

host_tier() {
  [ -f "$KEYFILE" ] || { say "FAIL: key missing: $KEYFILE"; return 1; }
  [ -f "$DISK" ]    || { say "FAIL: target disk missing: $DISK"; return 1; }
  if [ -n "$(qemu_pids)" ]; then
    say "INFO: target VM RUNNING (qemu pid $(qemu_pids | head -1); expected between runs)"
  else
    say "WARN: target VM not running (launcher: $LAB_DIR/boot-all.sh rocky block)"
  fi
  say "OK host tier"
}

target_tier() {
  out=$(timeout 15 ssh "${SSH_OPTS[@]}" "$TARGET" "hostname" 2>/dev/null)
  case "$out" in
    *rocky-scan*) say "OK target tier ($out reachable on port $PORT)" ;;
    "")           say "FAIL: target unreachable on gus2:$PORT"; return 1 ;;
    *)            say "OK target tier (hostname reported: $out)" ;;
  esac
}

snapshot_tier() {
  listing=$(qemu-img snapshot -l -U "$DISK" 2>/dev/null)
  if [ -z "$listing" ]; then
    say "WARN: snapshot inventory unreadable (locked or empty); inspect while the VM is stopped"
  elif echo "$listing" | grep -q "$SNAP_NAME"; then
    say "OK reset capability ($SNAP_NAME snapshot present)"
  else
    say "WARN: no $SNAP_NAME snapshot - ARM procedure in docs/KA-LAB-TARGET.md (owner-gated, VM stopped)"
  fi
}

do_check() {
  host_tier    || exit 1
  target_tier  || exit 1
  snapshot_tier
  say "CHECK-OK (read-only preflight green)"
}

do_verify() {
  target_tier || exit 1
  timeout 15 ssh "${SSH_OPTS[@]}" "$TARGET" "uptime" 2>/dev/null || exit 1
  say "VERIFY-OK"
}

do_reset() {
  consent_refused
  pids=$(qemu_pids)
  if [ -z "$pids" ]; then
    say "WARN: no running qemu to stop (continuing to rollback + relaunch)"
  else
    # orderly: SIGTERM qemu, wait briefly, then SIGKILL stragglers
    kill $pids 2>/dev/null
    sleep 5
    pids=$(qemu_pids)
    [ -n "$pids" ] && kill -9 $pids 2>/dev/null
    sleep 2
  fi
  qemu-img snapshot -a "$SNAP_NAME" "$DISK" \
    || die "rollback to $SNAP_NAME failed" 1
  cd "$LAB_DIR" || die "cd lab dir failed" 1
  nohup qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 2 \
    -drive file=rocky-scan-disk.qcow2,if=virtio,format=qcow2 \
    -drive file=seed-rocky.iso,if=virtio,format=raw,media=cdrom \
    -netdev user,id=n0,hostfwd=tcp::2226-:22 -device virtio-net-pci,netdev=n0 \
    -display none -serial file:serial-rocky.log -monitor none \
    >/tmp/rocky-relaunch.log 2>&1 &
  echo "launched rocky-scan pid $!"
  say "RESET-DONE (rollback + relaunch; verify with --verify)"
}

usage() {
  cat <<EOF
usage: pve-lab-battery.sh --check|--verify|--reset|--run CMD...
  --check      read-only preflight (exit 0 = green)
  --verify     read-only post-run target sanity
  --reset      OWNER-GATED: stop vm -> qcow2 rollback -> relaunch
  --run CMD... OWNER-GATED: execute one battery command on the target
Owner gate: $CONSENT_VAR=1 must be set in the environment for --reset/--run.
EOF
}

case "${1:-}" in
  --check)  do_check ;;
  --verify) do_verify ;;
  --reset)  do_reset ;;
  --run)    shift; [ $# -gt 0 ] || die "--run needs a command" 3; consent_refused; timeout 300 ssh "${SSH_OPTS[@]}" "$TARGET" "$*" ;;
  *)        usage; exit 3 ;;
esac
