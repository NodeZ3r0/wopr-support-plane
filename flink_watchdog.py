#!/usr/bin/env python3
"""
FALKEN Flink cluster watchdog + AUTO-REMEDIATION (support-plane, root cron */15).

Keeps the Flink 2.2.0 SQL job (jobs.sql -> triage/alerts/operations) running.
Auto-fixes, in order:
  1. Jobmanager REST down (port collision / crash-loop)   -> port-safe restart of flink.service
  2. Jobmanager UP but 0 TaskManagers / 0 slots           -> port-safe restart (dead-worker recovery)
  3. Cluster up WITH slots but 0 running jobs             -> resubmit jobs.sql
Alerts ntfy (wopr-alerts) on the problem AND on the fix taken. Cooldown prevents loops.

Root cause #1 (2026-07-03): the host 2.2.0 cluster couldn't bind rpc:6123 / rest:8081 because a
vestigial docker 1.19.1 cluster published them; 2.2.0 moved to rpc:6126 / rest:8092.
(That 1.19.1 container was removed 2026-07-07.)
Root cause #2 (2026-07-07): a TaskManager died on a stuck task-cancel; the JobManager stayed up so
systemd (Type=forking) never restarted the worker -> the cluster ran with 0 slots and every resubmit
just stacked an un-schedulable zombie job. The old watchdog only restarted on a DOWN JobManager, so
it could not self-heal this; it now detects 0-workers/0-slots and restarts the cluster.
"""
import os, json, time, subprocess, urllib.request
from datetime import datetime, timezone

NTFY_URL   = os.environ.get("NTFY_URL", "http://127.0.0.1:18081")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "wopr-alerts")
STATE      = "/opt/wopr/support-plane/flink_watchdog.state.json"
REST       = "http://127.0.0.1:8092"          # 2.2.0 cluster REST (moved off :8081 collision)
JOBS_SQL   = "/opt/falken-flink/jobs.sql"
SQL_CLIENT = "/opt/flink-2.2.0/bin/sql-client.sh"
MIN_JOBS   = 1                                  # jobs.sql is one STATEMENT SET job
COOLDOWN_S = 1800                               # don't re-remediate the same fault within 30 min


def ntfy(title, msg, priority="high", tags="rotating_light,ocean"):
    try:
        req = urllib.request.Request(NTFY_URL + "/" + NTFY_TOPIC, data=msg.encode(),
            headers={"Title": title, "Priority": priority, "Tags": tags}, method="POST")
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def sh(cmd, timeout=240):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return 1, str(e)


def jobs_running():
    """Return running-job count, or None if the jobmanager REST is unreachable."""
    try:
        with urllib.request.urlopen(REST + "/jobs/overview", timeout=8) as r:
            js = json.loads(r.read().decode()).get("jobs", [])
        return sum(1 for j in js if j.get("state") == "RUNNING")
    except Exception:
        return None


def cluster_slots():
    """Return (taskmanagers, slots_total, slots_available), or None if the JM REST is unreachable."""
    try:
        with urllib.request.urlopen(REST + "/overview", timeout=8) as r:
            d = json.loads(r.read().decode())
        return (d.get("taskmanagers", 0), d.get("slots-total", 0), d.get("slots-available", 0))
    except Exception:
        return None


def load_state():
    try:
        return json.load(open(STATE))
    except Exception:
        return {}


def save_state(st):
    try:
        json.dump(st, open(STATE, "w"))
    except Exception:
        pass


def cooled_down(st, key):
    last = st.get(key, 0)
    return (time.time() - last) > COOLDOWN_S


def restart_cluster():
    """Port-safe restart: stop, kill orphans, clear corrupt pidfiles, start, then wait
    (up to ~40s) for a TaskManager to register at least one slot."""
    sh("systemctl stop flink.service", 120)
    sh("pkill -f flink-2.2.0", 30)
    time.sleep(2)
    sh("rm -f /tmp/flink-root-standalonesession.pid /tmp/flink-root-taskexecutor.pid", 15)
    sh("systemctl start flink.service", 120)
    for _ in range(20):
        time.sleep(2)
        ov = cluster_slots()
        if ov and ov[1] >= 1:          # slots_total >= 1 -> a TaskManager registered
            break
    return jobs_running()


def resubmit():
    rc, out = sh(f"timeout 200 {SQL_CLIENT} -f {JOBS_SQL}", 220)
    time.sleep(4)
    return jobs_running(), ("submitted to the cluster" in out or "Job ID" in out)


def main():
    st = load_state()
    now = time.time()
    action = None
    running = jobs_running()          # None if JM REST down, else count of RUNNING jobs
    slots = cluster_slots()           # None if JM REST down, else (tms, slots_total, slots_avail)

    if running is None or slots is None:
        # (1) Jobmanager REST down -> cluster/JM problem
        if cooled_down(st, "restart_ts"):
            st["restart_ts"] = now
            after = restart_cluster()
            if after is None:
                action = ("FLINK JM DOWN — restart FAILED",
                          "Flink 2.2.0 jobmanager REST :8092 unreachable; auto-restart did NOT bring it back. Manual check needed (port collision? see flink_watchdog).")
            elif after < MIN_JOBS:
                after2, ok = resubmit()
                action = ("FLINK auto-recovered (restart+resubmit)",
                          f"Jobmanager was down; restarted flink.service and resubmitted jobs.sql. Running jobs now: {after2}.")
                running = after2
            else:
                action = ("FLINK auto-recovered (restart)",
                          f"Jobmanager REST was down; restarted flink.service. Running jobs now: {after}.")
                running = after
        else:
            action = ("FLINK JM still down (cooldown)",
                      "Flink jobmanager REST :8092 still unreachable; within 30-min remediation cooldown, not restarting again. Manual check needed.")
    elif slots[0] == 0 or slots[1] == 0:
        # (2) JM up but NO TaskManagers / 0 slots -> dead worker. A resubmit CANNOT help (nowhere to
        #     deploy); the only cure is a full cluster restart to bring a TaskManager back.
        if cooled_down(st, "restart_ts"):
            st["restart_ts"] = now
            restart_cluster()
            slots2 = cluster_slots()
            if slots2 is None or slots2[1] == 0:
                action = ("FLINK no workers — restart FAILED",
                          "Flink 2.2.0 JobManager up but 0 TaskManagers/slots; auto-restart did NOT bring a worker back (still 0 slots). Manual check needed.")
            else:
                after2, ok = resubmit()
                if after2 >= MIN_JOBS:
                    action = ("FLINK auto-recovered (dead worker)",
                              f"TaskManager had died (0 slots) — JobManager was up so systemd never noticed. Restarted flink.service ({slots2[1]} slots back) and resubmitted jobs.sql -> {after2} job(s) running.")
                    running = after2
                else:
                    action = ("FLINK resubmit FAILED after worker restart",
                              f"Restored {slots2[1]} slots but jobs.sql resubmit did not start a job (still {after2}). Manual check needed.")
        else:
            action = ("FLINK no workers (cooldown)",
                      "Flink JobManager up but 0 TaskManagers/slots; within 30-min restart cooldown, not restarting again. Manual check needed.")
    elif running < MIN_JOBS:
        # (3) Cluster healthy WITH slots but the SQL job isn't running -> resubmit
        if cooled_down(st, "resubmit_ts"):
            st["resubmit_ts"] = now
            after, ok = resubmit()
            if after >= MIN_JOBS:
                action = ("FLINK job auto-resubmitted",
                          f"Flink cluster was up ({slots[1]} slots) but had {running} running job(s); resubmitted jobs.sql -> {after} now running.")
                running = after
            else:
                action = ("FLINK resubmit FAILED",
                          f"Flink cluster up ({slots[1]} slots) but jobs.sql resubmit did not start a job (still {after}). Manual check needed.")
        else:
            action = ("FLINK 0 jobs (cooldown)",
                      "Flink cluster up but no running job; within resubmit cooldown. Manual check needed.")

    # Alert only on state change (problem appears) or when a fix was taken
    prev_ok = st.get("last_ok", True)
    now_ok = (running is not None and running >= MIN_JOBS and action is None)
    if action:
        ntfy(f"[FLINK] {action[0]}", action[1])
    elif now_ok and not prev_ok:
        ntfy("[FLINK] recovered", f"Flink SQL job running again ({running} job(s)).",
             "default", "white_check_mark")
    st["last_ok"] = now_ok
    save_state(st)
    print(datetime.now().strftime("%F %T"), "running=", running,
          "slots=", (slots[1] if slots else None), "action=", action[0] if action else "none")


if __name__ == "__main__":
    main()
