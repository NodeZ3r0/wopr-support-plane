#!/bin/bash
# Pause / resume the Prod-1 support plane's restarts (WOPR-260). Run as root on Prod-1.
#   sp-pause.sh pause [why]   observe-only: no unit or container restarts (nebula's plain restart-if-down stays on)
#   sp-pause.sh resume
#   sp-pause.sh status        prints PAUSED or RUNNING; exit 0 either way
# Switch night: pause before the final syncs (they stop containers on Prod-1 to copy their data);
# enable/90-support-plane.sh resumes after the enable phase.
set -euo pipefail
F=/etc/wopr/support-plane.PAUSED
case "${1:-status}" in
  pause)  mkdir -p /etc/wopr; printf 'paused %s: %s\n' "$(date -Is)" "${2:-switch night}" > "$F"; chmod 644 "$F"; echo PAUSED ;;
  resume) rm -f "$F"; echo RUNNING ;;
  status) if [ -e "$F" ]; then echo "PAUSED ($(cat "$F"))"; else echo RUNNING; fi ;;
  *) echo "usage: $0 pause|resume|status"; exit 64 ;;
esac
