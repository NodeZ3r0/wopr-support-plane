#!/usr/bin/env python3
"""
FALKEN DATA FRESHNESS probe (support-plane, root cron */30).

Services can all be "active" and the site can return 200 while Falken's data is dead.
Checks the data itself:
  - latest analyses.analyzed_at            (pipeline runs 02:00-05:00, so allow 26h)
  - latest operation_content.added_at      (correlation output, allow 30h)
  - /api/psyops/geo is non-empty           (empty map = splash shows a false DEFCON 5)
Alerts ntfy (wopr-alerts) when the set of stale checks changes, and once on recovery.

Root cause (2026-09-23): analysis silently stopped 2026-09-06; no alert for 16 days.

Test: python3 falken_freshness_probe.py --test --analyzed-hours 0.01 --state /tmp/x.json
"""
import argparse, json, os, subprocess, urllib.request
from datetime import datetime

NTFY_URL   = os.environ.get("NTFY_URL", "http://127.0.0.1:18081")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "wopr-alerts")
STATE      = "/opt/wopr/support-plane/falken_freshness_probe.state.json"
ENV_LOCAL  = "/opt/wopr-falken/.env.local"
GEO_URL    = "http://127.0.0.1:13000/api/psyops/geo"


def ntfy(title, msg, priority="high", tags="rotating_light,hourglass"):
    try:
        req = urllib.request.Request(NTFY_URL + "/" + NTFY_TOPIC, data=msg.encode(),
            headers={"Title": title, "Priority": priority, "Tags": tags}, method="POST")
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def load_state(path):
    try:
        return json.load(open(path))
    except Exception:
        return {}


def save_state(path, st):
    try:
        json.dump(st, open(path, "w"))
    except Exception:
        pass


def db_url():
    for line in open(ENV_LOCAL):
        if line.startswith("DATABASE_URL="):
            return line.split("=", 1)[1].strip().strip('"')
    return None


def age_hours(sql):
    """Hours since the timestamp the query returns; None if the query fails or returns NULL."""
    r = subprocess.run(["psql", db_url(), "-Atc",
                        f"SELECT EXTRACT(EPOCH FROM (now() - ({sql})))/3600"],
                       capture_output=True, text=True, timeout=60)
    out = r.stdout.strip()
    return float(out) if r.returncode == 0 and out else None


def geo_count():
    try:
        with urllib.request.urlopen(GEO_URL, timeout=30) as r:
            d = json.loads(r.read().decode())
        return len(d) if isinstance(d, list) else None
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--analyzed-hours", type=float, default=26)
    ap.add_argument("--linked-hours", type=float, default=30)
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--test", action="store_true", help="prefix alert titles with TEST")
    a = ap.parse_args()
    prefix = "[FALKEN] TEST - ignore: " if a.test else "[FALKEN] "

    analyzed = age_hours("SELECT max(analyzed_at) FROM analyses")
    linked = age_hours("SELECT max(added_at) FROM operation_content")
    geo = geo_count()

    stale = {}
    if analyzed is None or analyzed > a.analyzed_hours:
        stale["analysis"] = (f"no content analyzed for {analyzed:.1f}h (limit {a.analyzed_hours:g}h)"
                             if analyzed is not None else "analysis age unreadable")
    if linked is None or linked > a.linked_hours:
        stale["links"] = (f"no operation links for {linked:.1f}h (limit {a.linked_hours:g}h)"
                          if linked is not None else "operation link age unreadable")
    if not geo:
        stale["geo"] = ("geo map is empty (splash shows a false DEFCON 5)" if geo == 0
                        else "geo API unreachable")
    problem = "; ".join(stale.values())
    keys = sorted(stale)

    st = load_state(a.state)
    if keys and keys != st.get("keys", []):
        ntfy(prefix + "data stale", f"Falken data is stale: {problem}. Services may still look healthy.")
    elif not keys and st.get("keys"):
        ntfy(prefix + "data fresh again", "Falken analysis, operation links and geo map are current.",
             "default", "white_check_mark")
    st["keys"] = keys
    save_state(a.state, st)
    fmt = lambda h: "n/a" if h is None else f"{h:.1f}h"
    print(datetime.now().strftime("%F %T"), f"analyzed={fmt(analyzed)} linked={fmt(linked)} geo={geo}",
          "problem=", problem or "none")


if __name__ == "__main__":
    main()
