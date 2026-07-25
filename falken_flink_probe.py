#!/usr/bin/env python3
"""
Falken / Flink health probe for the WOPR support-plane.

Alerts (ntfy -> wopr-alerts) when the Falken data pipeline that FEEDS ASScast +
the meme engine stops grinding. This is the gap that let the Flink trending/alerts
job sit dead for 10 days with no notification.

Signals (DB is ground-truth, no false positives):
  - Kafka broker :9092 reachable
  - Falken DB reachable
  - flink_trending  -> EMPTY or stale  == Flink SQL trending job dead (0 trending narratives)
  - flink_alerts    -> EMPTY or stale  == Flink SQL alerts job dead
  - content         -> stale           == ingestion stalled (overnight scrape failed)
  - analyses        -> stale           == analysis stalled

Alerts ONLY on failure-set CHANGE (no spam). Recovery clears it. Cron */30.
"""
import os
import re
import json
import socket
import subprocess
import urllib.request
from datetime import datetime, timezone

NTFY_URL   = os.environ.get("NTFY_URL", "http://127.0.0.1:18081")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "wopr-alerts")
STATE      = "/opt/wopr/support-plane/falken_flink_probe.state.json"
DSN        = os.environ.get("FALKEN_DSN", "postgresql://falken:F4lk3nW0PR2026@127.0.0.1:5432/falken")
KAFKA      = ("127.0.0.1", 9092)
STALE_HRS  = 26          # daily overnight cadence (02:00-05:00) -> alert if no fresh data >26h


def ntfy(title, msg, priority, tags):
    try:
        req = urllib.request.Request(
            NTFY_URL + "/" + NTFY_TOPIC, data=msg.encode(),
            headers={"Title": title, "Priority": priority, "Tags": tags}, method="POST")
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def q1(sql):
    """One scalar via psql. Returns stripped text, or None on any failure."""
    try:
        r = subprocess.run(["psql", DSN, "-tAc", sql],
                           capture_output=True, text=True, timeout=20)
        if r.returncode == 0:
            return r.stdout.strip()
    except Exception:
        pass
    return None


def hours_since(ts_text):
    """Age in hours for a postgres timestamp string, or None if unparseable."""
    if not ts_text:
        return None
    t = ts_text.strip().replace(" ", "T", 1)
    m = re.search(r'([+-]\d{2})$', t)      # normalize -05 -> -0500
    if m:
        t = t + "00"
    try:
        dt = datetime.fromisoformat(t)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).total_seconds() / 3600.0
    except Exception:
        return None


def check():
    fails = {}

    # Kafka broker reachable
    try:
        s = socket.create_connection(KAFKA, timeout=5)
        s.close()
    except Exception:
        fails["kafka"] = "Kafka broker %s:%d unreachable" % KAFKA

    # DB reachable?
    if q1("SELECT 1;") != "1":
        fails["falken_db"] = "Falken DB unreachable (%s)" % DSN.split("@")[-1]
        return fails   # nothing else queryable

    # Flink SQL output tables -> feed ASScast + meme-gen trending narratives
    for tbl, label in (("flink_trending", "trending narratives"),
                       ("flink_alerts", "alerts")):
        cnt = q1("SELECT count(*) FROM %s;" % tbl)
        last = q1("SELECT max(created_at) FROM %s;" % tbl)
        if cnt == "0":
            fails[tbl] = "Flink %s pipeline DEAD: %s is EMPTY -> ASScast+meme-gen get 0 %s" % (label, tbl, label)
        else:
            age = hours_since(last)
            if age is None or age > STALE_HRS:
                fails[tbl] = "Flink %s STALE: %s last row %s (>%dh old)" % (label, tbl, last, STALE_HRS)

    # Core ingestion + analysis freshness (daily overnight cadence)
    for tbl, col, label in (("content", "collected_at", "content ingestion"),
                            ("analyses", "analyzed_at", "analysis")):
        last = q1("SELECT max(%s) FROM %s;" % (col, tbl))
        age = hours_since(last)
        if age is None or age > STALE_HRS:
            fails[tbl] = "Falken %s STALLED: last %s (>%dh)" % (label, last or "NULL", STALE_HRS)

    return fails


def main():
    fails = check()
    cur = set(fails)
    try:
        prev = set(json.load(open(STATE)).get("failing", []))
    except Exception:
        prev = set()

    new_break = cur - prev
    recovered = prev - cur

    if new_break:
        ntfy("FALKEN/FLINK broken (%d)" % len(new_break),
             "\n".join(fails[k] for k in sorted(new_break)),
             "high", "rotating_light,brain")
    if recovered and not new_break:
        ntfy("FALKEN/FLINK recovered",
             "Back to grinding: " + ", ".join(sorted(recovered)),
             "default", "white_check_mark")

    try:
        json.dump({"failing": sorted(cur),
                   "ts": datetime.now(timezone.utc).isoformat()}, open(STATE, "w"))
    except Exception:
        pass

    print(datetime.now().strftime("%F %T"), "fails=" + (",".join(sorted(cur)) or "none"))


if __name__ == "__main__":
    main()
