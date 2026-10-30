#!/usr/bin/env python3
"""Support-plane mesh-health probe: ping 24/7 Nebula server nodes, ntfy on state change.
Runs on the Rig (10.0.0.3) via root cron */5. Alerts after 2 consecutive fails (~10min) to avoid flapping."""
import subprocess, json, os, urllib.request
NTFY = "http://127.0.0.1:18081/wopr-alerts"
STATE = "/opt/wopr/support-plane/mesh_probe.state.json"
# 24/7 server nodes only (NOT the laptop 10.0.0.10 — "asleep" is not a fault).
# 10.0.0.2 / 10.0.0.4 / 10.0.0.5 were the old DO/Hetzner VPSes: gone, never probe them.
# woprtest02 (10.0.0.100, /etc/nebula/allocations.json) did not answer on 2026-10-25;
# add it back here once it is on the mesh again.
NODES = {
    "10.0.0.1": "ystest lighthouse",  # Contabo 212.28.177.202, the only lighthouse
    "10.0.0.20": "Bear's beacon",   # Contabo 144.126.143.227
    "10.0.0.101": "BINK beacon",
}
FAIL_THRESHOLD = 2  # consecutive */5 misses before alerting (~10 min)

def ping(ip):
    return subprocess.run(["ping", "-c", "2", "-W", "2", ip],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

def notify(title, msg, prio, tags):
    try:
        req = urllib.request.Request(NTFY, data=msg.encode(),
                                     headers={"Title": title, "Priority": prio, "Tags": tags})
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass

state = {}
if os.path.exists(STATE):
    try: state = json.load(open(STATE))
    except Exception: state = {}
# keep state only for nodes still probed, so a removed node's counters do not linger
state = {ip: s for ip, s in state.items() if ip in NODES}

for ip, name in NODES.items():
    s = state.get(ip, {"fails": 0, "alerted": False, "ever_up": False})
    ever_up = s.get("ever_up", False)
    if ping(ip):
        if s.get("alerted"):
            notify(f"Mesh RECOVERED: {name}", f"{name} ({ip}) is back on the Nebula mesh.", "default", "white_check_mark")
        state[ip] = {"fails": 0, "alerted": False, "ever_up": True}
    else:
        fails = s.get("fails", 0) + 1
        alerted = s.get("alerted", False)
        # only alert a node that has actually been up before (skips decommissioned/never-seen nodes)
        if ever_up and fails >= FAIL_THRESHOLD and not alerted:
            notify(f"Mesh node DOWN: {name}",
                   f"{name} ({ip}) dropped off the Nebula mesh (~{fails*5}min). Check Nebula on that host.",
                   "high", "rotating_light")
            alerted = True
        state[ip] = {"fails": fails, "alerted": alerted, "ever_up": ever_up}

json.dump(state, open(STATE, "w"))
