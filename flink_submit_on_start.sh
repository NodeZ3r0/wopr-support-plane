#!/bin/bash
# ExecStartPost for flink.service (WOPR-125).
# A standalone session cluster forgets its jobs on every restart (needrestart after a
# library upgrade, reboot, manual restart), so put the jobs.sql job back as soon as a
# TaskManager has slots. Skips if a live copy already exists. Never fails the unit.
REST=http://127.0.0.1:8092
SQL_CLIENT=/opt/flink-2.2.0/bin/sql-client.sh
JOBS_SQL=/opt/falken-flink/jobs.sql
LOG=/opt/wopr/support-plane/flink_submit_on_start.log

exec 9>/run/flink-submit.lock
flock -w 240 9 || { echo "$(date '+%F %T') lock busy, skipping" >>"$LOG"; exit 0; }

slots=0
for _ in $(seq 60); do
    slots=$(curl -s -m 5 "$REST/overview" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("slots-total",0))' 2>/dev/null)
    [ "${slots:-0}" -ge 1 ] && break
    sleep 2
done
if [ "${slots:-0}" -lt 1 ]; then
    echo "$(date '+%F %T') no slots after 120s, leaving it to flink_watchdog" >>"$LOG"
    exit 0
fi

live=$(curl -s -m 5 "$REST/jobs/overview" | python3 -c 'import sys,json; print(sum(1 for j in json.load(sys.stdin)["jobs"] if j["state"] not in ("CANCELED","FINISHED","FAILED")))' 2>/dev/null)
if [ "${live:-0}" -ge 1 ]; then
    echo "$(date '+%F %T') $live live job(s) already, not submitting" >>"$LOG"
    exit 0
fi

timeout 200 "$SQL_CLIENT" -f "$JOBS_SQL" >/dev/null 2>&1
sleep 4
running=$(curl -s -m 5 "$REST/jobs/overview" | python3 -c 'import sys,json; print(sum(1 for j in json.load(sys.stdin)["jobs"] if j["state"]=="RUNNING"))' 2>/dev/null)
echo "$(date '+%F %T') submitted jobs.sql on start, running=${running:-?}" >>"$LOG"
exit 0
