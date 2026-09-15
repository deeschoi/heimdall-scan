#!/usr/bin/env bash
# Records docs/demo/oedipus-demo.cast — the cassette embedded in the README.
# Requires: asciinema, and oedipus-vulnapp running on :8000 (VULNAPP_SAFE=0).
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
echo -e "\033[1;33m# Oedipus: find -> prove -> patch, against the project's own vulnerable target\033[0m"
echo
sleep 1

demo oedipus list-checks

demo oedipus eval vulnapp

demo oedipus scan --suite vulnapp --format md --out /tmp/oedipus-demo.md
head -n 40 /tmp/oedipus-demo.md
echo
sleep 2
