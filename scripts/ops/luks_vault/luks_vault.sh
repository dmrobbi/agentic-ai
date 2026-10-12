#!/usr/bin/env bash
# luks_vault.sh - host orchestrator for the LUKS2 vault container.
#
# The container runs privileged (LUKS2 + dm-crypt = kernel layer; no
# unprivileged path keeps real LUKS) with a named volume, so the vault
# image persists LOCKED inside the volume whenever the container is
# stopped or removed. Credentials travel by STDIN only - never in
# argv, env, logs, or the image. `destroy` refuses without --yes.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
COMPOSE=(docker compose -f "$DIR/docker-compose.yml")
EXIT=0

usage() {
    cat >&2 <<'USAGE'
usage: luks_vault.sh <cmd>
  build            build the luks-vault image
  up               start the pid1 entry (idle; locks on stop)
  create [stdin: pass] <mb>  create vault.img (urandom + LUKS2 fast profile; the keyslot binds the stdin credential)
  unlock           passphrase via stdin (pipe your 0600 file in; never echoed)
  tpm-enroll [stdin: pass]  seal the payload key to THIS machine's TPM (recovery = the passphrase slot)
  tpm-unlock       open via the enrolled TPM binding (no stdin passphrase)
  lock             unmount + luksClose (the image LOCKED again)
  status           image integrity + mapper state
  selftest         the full loop on a container-side /tmp scratch (the vault untouched)
  verify           run selftest, then the volume flow: create/status/unlock/lock/stop
  stop             stop the container (the pid1 trap locks the vault)
  down             stop + remove the container (the LOCKED image persists in the volume)
  destroy [--yes]  remove the container AND its named volume (data gone; refuses without --yes)
USAGE
    exit 2
}

cmd=${1:-}
case "$cmd" in
    build)    "${COMPOSE[@]}" build ;;
    up)       "${COMPOSE[@]}" up -d --build ;;
    create)
        mb=${2:-}
        case "$mb" in ''|*[!0-9]*) echo "usage: printf '%s' '<passphrase>' | luks_vault.sh create <size_mb>" >&2; exit 2;; esac
        docker compose exec -T luks-vault vault_entry create "$mb"
        ;;
    unlock)
        docker compose exec -T luks-vault vault_entry unlock
        ;;
    tpm-enroll) docker compose exec -T luks-vault vault_entry tpm-enroll ;;
    tpm-unlock) docker compose exec -T luks-vault vault_entry tpm-unlock ;;
    lock)     docker compose exec -T luks-vault vault_entry lock ;;
    status)   docker compose exec -T luks-vault vault_entry status ;;
    selftest) docker compose exec -T luks-vault vault_entry selftest ;;
    stop)     "${COMPOSE[@]}" stop ;;
    down)     "${COMPOSE[@]}" down ;;
    destroy)
        [ "${2:-}" = "--yes" ] || { echo "destroy refuses without --yes (this removes the LOCKED image's volume)" >&2; exit 2; }
        "${COMPOSE[@]}" down -v
        ;;
    verify)
        selftest_out=$(docker compose exec -T luks-vault vault_entry selftest)
        echo "$selftest_out"
        case "$selftest_out" in *VAULT-SELFTEST-OK*) : ;; *) exit 1;; esac
        st=$(docker compose exec -T luks-vault vault_entry status)
        echo "$st"
        case "$st" in *VAULT-LOCKED*|*VAULT-OPENED*) : ;; *) exit 1;; esac
        ;;
    *) usage ;;
esac
exit $EXIT