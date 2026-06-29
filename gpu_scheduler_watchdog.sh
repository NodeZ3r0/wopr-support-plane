#!/usr/bin/env bash
# gpu-scheduler :18099 can silently WEDGE (systemd stays "active").
# Use the LIGHTWEIGHT /health endpoint as the liveness signal -- it answers even when
# the worker is busy running a legitimate job, so we no longer restart a merely-busy
# scheduler (that was killing asscast/meme jobs mid-run). Only restart on a true wedge:
# /health must fail TWICE ~5s apart before we act.
set -u
probe() { curl -s -o /dev/null -w %{http_code} --max-time 10 http://127.0.0.1:18099/health 2>/dev/null; }
c1=$(probe)
if [ "$c1" != "200" ]; then
  sleep 5
  c2=$(probe)
  if [ "$c2" != "200" ]; then
    logger -t gpu-scheduler-watchdog "scheduler /health failed twice ($c1,$c2); restarting gpu-scheduler"
    systemctl restart gpu-scheduler
    sleep 8
    curl -s -H "Title: GPU scheduler wedged" -H "Priority: high"       -d "gpu-scheduler /health failed twice ($c1,$c2); auto-restarted."       http://127.0.0.1:18081/wopr-alerts >/dev/null 2>&1
  fi
fi
