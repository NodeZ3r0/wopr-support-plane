#!/usr/bin/env python3
"""Support-plane mesh-health probe: ping 24/7 Nebula server nodes, ntfy on state change.
Runs on the Rig (10.0.0.3) via root cron */5. Alerts after 2 consecutive fails (~10min) to avoid flapping."""
import subprocess, json, os, urllib.request
NTFY = "http://127.0.0.1:18081/wopr-alerts"
STATE = "/opt/wopr/support-plane/mesh_probe.state.json"
# 24/7 server nodes only (NOT the laptop 10.0.0.10 — "asleep" is not a fault)
NODES = {
    "10.0.0.2": "nodez3r0 VPS",
    "10.0.0.4": "micro-reactor",
    "10.0.0.5": "hetzner",
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
