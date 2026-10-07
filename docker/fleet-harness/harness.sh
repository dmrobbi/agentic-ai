#!/usr/bin/env bash
# KA-076 - the fleet test harness driver (OPT-76). OWNER-RUN ONLY.
#
# LAB BOUNDARY: everything this script touches is intentionally vulnerable
# and lab-only. Never point it at an exposed or production network. Nothing
# here executes from the test suite (committed DATA; the tests only parse
# it - bash -n + marker pins). State-changing subcommands refuse to run
# without the owner gate KA_FLEET_HARNESS=1 (the same discipline as the
# suite's KA_LAB_BATTERY / BRUTEFORCE_E2E gates). `status` and `evidence`
# are read-only and ungated.
#
# Subcommands:
#   help                 print this text (no gate)
#   status               read-only compose ps across every profile (no gate)
#   up [farm|soc|all]    bring profiles up (gate; default farm)
#   down                 stop + remove the harness project, -v volumes (gate)
#   reset                down -v + fresh farm up (gate; the repeated-battery move)
#   run [offline|lab]    run the lab battery (gate for lab; evidence saved)
#   evidence             verify + list saved battery evidence (no gate)
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HARNESS_DIR/../.." && pwd)"
COMPOSE_FILE="$HARNESS_DIR/docker-compose.fleet-lab.yml"
SHARED_LAB_NET="lab-targets_default"
EVIDENCE_DIR="$HARNESS_DIR/evidence"

die() { echo "harness: $*" >&2; exit 1; }

compose() { docker compose -f "$COMPOSE_FILE" "$@"; }

require_gate() {
    # deliberate lab consent; the README gate table documents the family
    [[ "${KA_FLEET_HARNESS:-}" == "1" ]] || \
        die "owner gate not raised: set KA_FLEET_HARNESS=1 first (see README.md)"
}

ensure_shared_net() {
    # the external lab network comes from docker/lab-targets (KA-009);
    # a placeholder keeps the harness runnable before that stack is up
    if ! docker network inspect "$SHARED_LAB_NET" >/dev/null 2>&1; then
        echo "harness: shared net $SHARED_LAB_NET missing (docker/lab-targets up?); creating placeholder"
        docker network create "$SHARED_LAB_NET" >/dev/null
    fi
}

usage() {
    cat <<'EOF'
Usage: harness.sh <subcommand>
  help                 print this text (no gate)
  status               read-only compose ps across every profile (no gate)
  up [farm|soc|all]    bring profiles up (gate; default farm)
  down                 stop + remove the harness project, -v volumes (gate)
  reset                down -v + fresh farm up (gate; the repeated-battery move)
  run [offline|lab]    run the lab battery (gate for lab; evidence saved)
  evidence             verify + list saved battery evidence (no gate)
EOF
}

cmd_help() { usage; }

cmd_status() {
    compose --profile fleet-farm --profile fleet-soc ps --format json
}

cmd_up() {
    local which="${1:-farm}"
    case "$which" in
        farm|soc|all) ;;
        *) die "unknown profile choice: $which (farm|soc|all)" ;;
    esac
    require_gate
    ensure_shared_net
    case "$which" in
        farm|all) compose --profile fleet-farm up -d ;;
    esac
    case "$which" in
        soc|all) compose --profile fleet-soc up -d ;;
    esac
    cmd_status
}

cmd_down() {
    require_gate
    # scoped by `name: fleet-harness` in the compose file: this never
    # touches the docker/lab-targets project (or its network) - the lab
    # farm is disposable by design, KA-009's stack stays put.
    compose down -v
    echo "harness: down (-v); shared lab network left untouched"
}

cmd_reset() {
    # the repeated-battery move: fresh database state per run (the docker
    # analog of the pve-lab snapshot reset, KA-095)
    require_gate
    compose down -v
    ensure_shared_net
    compose --profile fleet-farm up -d
    cmd_status
}

cmd_run() {
    local mode="${1:-offline}"
    case "$mode" in
        offline)
            # the suite-default shape: the offline battery halves only;
            # every gated test skips (no gates exported, nothing starts)
            (cd "$REPO_ROOT" && python3 -m pytest tests/lab -v --tb=short -p no:cacheprovider)
            ;;
        lab)
            require_gate
            # farm guaranteed up before the gated tests run (idempotent)
            cmd_up farm
            local stamp evidence_dir
            stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
            evidence_dir="$EVIDENCE_DIR/$stamp"
            mkdir -p "$evidence_dir"
            echo "harness: gates raised (KA_LAB_BATTERY=1 KA_FLEET_HARNESS=1); pytest tests/lab"
            (cd "$REPO_ROOT" && \
                KA_LAB_BATTERY=1 KA_FLEET_HARNESS=1 \
                python3 -m pytest tests/lab -v --tb=short -p no:cacheprovider \
                2>&1) | tee "$evidence_dir/battery.log"
            (cd "$evidence_dir" && sha256sum battery.log > manifest.sha256)
            echo "harness: evidence: $evidence_dir/battery.log (+manifest.sha256)"
            ;;
        *) die "unknown run mode: $mode (offline|lab)" ;;
    esac
}

cmd_evidence() {
    [[ -d "$EVIDENCE_DIR" ]] || die "no evidence yet: run 'harness.sh run lab'"
    local d
    for d in "$EVIDENCE_DIR"/*/; do
        [[ -d "$d" ]] || continue
        if (cd "$d" && sha256sum -c manifest.sha256 >/dev/null 2>&1); then
            printf '%s  verified\n' "$(basename "$d")"
        else
            printf '%s  UNVERIFIED\n' "$(basename "$d")"
        fi
    done
}

case "${1:-help}" in
    help|-h|--help) cmd_help ;;
    status) cmd_status ;;
    up) shift; cmd_up "${1:-farm}" ;;
    down) cmd_down ;;
    reset) cmd_reset ;;
    run) shift; cmd_run "${1:-offline}" ;;
    evidence) cmd_evidence ;;
    *) usage; die "unknown subcommand: ${1}" ;;
esac
