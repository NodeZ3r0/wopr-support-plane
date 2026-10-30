#!/bin/bash
# Install the strict-manifest support plane on Prod-1 (WOPR-260). Run as root on Prod-1, from the checkout:
#   sudo bash /opt/wopr/support-plane/prod-1/install.sh
# Idempotent. Exits non-zero on any failure. Installs and STARTS:
#   wopr-support-plane.service  (5-min scan loop; heals only what services-manifest.json lists)
#   wopr-sp-metrics.service     (127.0.0.1:9101, SITREP ops reads it through Caddy /api/sp/)
#   wopr-sp-watchdog.timer      (heartbeat + critical manifest units, guarded)
#   /etc/cron.d/wopr-failsafe   (every 2 min; restarts the plane / watchdog timer)
# Does NOT install: the autodiscovery timer (never on Prod-1), the probe cron (switch night,
# enable/90-support-plane.sh), anything listed in hold-until-switch.json.
set -euo pipefail
SP=/opt/wopr/support-plane
cd "$SP"
say() { printf '== %s\n' "$*"; }

say "cron daemon (Prod-1 had none: every /etc/cron.d job, including the switch-night ones, would never run)"
if [ ! -x /usr/sbin/cron ]; then
  # Beacon-era run-parts scripts from the 10-27 beacon install; their /opt/wopr/scripts is gone with the
  # retired beacon (/root/retired-beacon-20261030). Archive them before cron could run them.
  arch=/root/retired-beacon-20261030/cron
  for f in /etc/cron.hourly/free /etc/cron.hourly/wopr-mesh-health /etc/cron.daily/wopr-backup /etc/cron.weekly/wopr-update-check; do
    if [ -e "$f" ]; then
      d="$arch/$(basename "$(dirname "$f")")"; mkdir -p "$d"; mv "$f" "$d/"; echo "archived $f -> $d/"
    fi
  done
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q cron >/dev/null
fi
systemctl enable --now cron >/dev/null 2>&1
[ "$(systemctl is-active cron)" = active ] || { echo "cron not active"; exit 1; }
echo "cron.d now: $(ls /etc/cron.d | tr '\n' ' ')"

say "units"
install -m 0644 prod-1/systemd/wopr-support-plane.service prod-1/systemd/wopr-sp-metrics.service \
  prod-1/systemd/wopr-sp-watchdog.service prod-1/systemd/wopr-sp-watchdog.timer /etc/systemd/system/
install -m 0644 prod-1/logrotate/wopr-support-plane /etc/logrotate.d/wopr-support-plane
systemctl daemon-reload

say "manifest from what runs now"
python3 -I "$SP/prod1_manifest.py" --write
say "guard self-test"
python3 -I "$SP/prod1_selftest.py"

say "start"
systemctl enable --now wopr-sp-metrics.service wopr-support-plane.service wopr-sp-watchdog.timer
install -m 0644 prod-1/cron.d/wopr-failsafe /etc/cron.d/wopr-failsafe
sleep 3
for u in wopr-sp-metrics wopr-support-plane wopr-sp-watchdog.timer cron; do
  [ "$(systemctl is-active $u)" = active ] || { echo "$u not active"; exit 1; }
done
curl -sf -o /dev/null http://127.0.0.1:9101/health || { echo "exporter not answering on 127.0.0.1:9101"; exit 1; }
ss -ltnH | grep -q '0.0.0.0:9101' && { echo "exporter bound to 0.0.0.0"; exit 1; }
say "INSTALL OK"
