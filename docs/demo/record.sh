#!/usr/bin/env bash
# Records docs/demo/heimdall-demo.cast — the cassette embedded in the README.
# Requires: asciinema, and heimdall-vulnapp running on :8000 (VULNAPP_SAFE=0).
#   PORT=8000 VULNAPP_SAFE=0 python -m vulnapp &
#   ./docs/demo/record.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

export COLUMNS=100
export TERM=xterm-256color

demo() {
    echo -e "\033[1;36m\$ $*\033[0m"
    "$@"
    echo
    sleep 1
}

clear
echo -e "\033[1;33m# Heimdall: find -> prove -> patch, against the project's own vulnerable target\033[0m"
echo
sleep 1

demo heimdall list-checks

demo heimdall eval vulnapp

demo heimdall scan --suite vulnapp --format md --out /tmp/heimdall-demo.md
head -n 40 /tmp/heimdall-demo.md
echo
sleep 2
