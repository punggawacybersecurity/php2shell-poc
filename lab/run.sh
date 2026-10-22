#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

compose() {
  docker compose -f "$ROOT/compose.yaml" --project-directory "$ROOT" "$@"
}

prepare_artifacts() {
  mkdir -p "$ROOT/artifacts/vulnerable" "$ROOT/artifacts/patched"
  # The PHP worker writes its proof file as www-data. Sticky directories keep
  # each local user's files from being removed by other local users.
  chmod 1777 "$ROOT/artifacts/vulnerable" "$ROOT/artifacts/patched"
}

usage() {
  cat <<'EOF'
Usage: ./lab/run.sh up|down|status|smoke|compare|probe-618|all|vulnerable|patched

up       Start vulnerable PHP 8.4.26 and patched PHP 8.4.27 on localhost.
down     Stop and remove the lab containers; keep test artifacts.
status   Show the containers.
smoke    Confirm versions and lab settings on both local endpoints.
compare  Run this project's exploit against both local endpoints.
probe-618  Run the independent, local-only CVE-2026-109618 shutdown-corruption probe.
all      Run both CVE reproductions and their controls.
vulnerable / patched  Run the exploit against one local control.
EOF
}

command="${1:-}"
case "$command" in
  up)
    prepare_artifacts
    compose up -d
    python3 "$ROOT/lab/smoke.py"
    ;;
  down)
    compose down --remove-orphans
    ;;
  status)
    compose ps
    ;;
  smoke)
    python3 "$ROOT/lab/smoke.py"
    ;;
  compare|vulnerable|patched)
    prepare_artifacts
    python3 "$ROOT/lab/smoke.py"
    python3 "$ROOT/exploit.py" "$command"
    ;;
  probe-618)
    python3 "$ROOT/lab/probe_618.py"
    ;;
  all)
    prepare_artifacts
    python3 "$ROOT/lab/smoke.py"
    result=0
    python3 "$ROOT/exploit.py" compare || result=1
    python3 "$ROOT/lab/probe_618.py" || result=1
    exit "$result"
    ;;
  *)
    usage
    exit 2
    ;;
esac
