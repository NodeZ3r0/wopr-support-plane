#!/usr/bin/env python3
"""Build the support-plane manifest on Prod-1 from what runs NOW (WOPR-260).

Prod-1 is a strict-manifest host: the support plane, its watchdog and the failsafe restart only what
this manifest lists (see sp_guard.py). autodiscovery.py is not used here: it adds every container
that exists (the never-started Saleor worker, Barterra scanner, SerpBear, GSC puller...) and every
loaded unit, and it would drop the strict flag.

What goes in:
  services   units that are active now AND `systemctl is-enabled` == enabled, minus OS internals,
             minus anything in hold-until-switch.json, minus timer-driven jobs
  containers containers that are running now AND have a restart policy, minus the hold file
  backend    each 127.0.0.1 port of those that answers HTTP below 500 now (+ Caddy on :18080)
  public     none: public hosts are the synthetic probe's job

Usage (root):
  prod1_manifest.py              dry run: print what the manifest would hold and the diff
  prod1_manifest.py --write      write services-manifest.json (backup: services-manifest.json.prev)
  prod1_manifest.py --switched   switch night: release the until_switch hold, then write
Exit 1 if the result would hold anything on hold, is empty, or the write fails.
"""
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime

HERE = "/opt/wopr/support-plane"
MANIFEST = os.path.join(HERE, "services-manifest.json")
HOLD = os.path.join(HERE, "hold-until-switch.json")

SKIP_UNIT_PREFIXES = (
    "systemd-", "dbus", "getty@", "serial-getty@", "user@", "user-runtime-dir@", "polkit",
    "unattended-upgrades", "cloud-", "e2scrub", "apparmor", "keyboard-setup", "kmod", "console-setup",
    "networking", "ifup", "lvm2", "blk-availability", "plymouth", "rc-local", "finalrd",
    "ssh", "sshd",                      # never restarted by the support plane anyway
    "wopr-support-plane",               # itself: the watchdog timer and the failsafe cron look after it
)
CRITICAL_UNITS = {
    "docker", "containerd", "nebula", "crowdsec", "crowdsec-firewall-bouncer", "cron", "postfix",
    "opendkim", "sso-bridge", "wopr-user-registry", "mosquitto",
    # once they run after the switch
    "cloudflared", "wopr-control-plane", "protonmail-bridge",
}
CRITICAL_CONTAINERS = {
    "wopr-caddy-rig", "prod-postgres", "authentik-server-1", "authentik-postgresql-1", "authentik_redis",
    "infisical", "infisical-redis", "wopr-ntfy", "wopr-sso-redis",
    # once they run after the switch
    "authentik-worker-1", "saleor-worker-dude",
}
NOT_HTTP = {25, 465, 587, 1883, 2021, 3306, 5432, 5433, 6379, 6380, 6390, 9101, 9445, 55440, 8883}
PROBE_PATHS = ("/health", "/healthz", "/api/health", "/")
EXTRA_BACKENDS = [  # host-network containers (no published port in docker ps)
    {"name": "caddy-18080", "url": "http://127.0.0.1:18080/", "container": "wopr-caddy-rig", "critical": True},
]


def sh(cmd, timeout=30):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.stdout


def load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def held(hold):
    out = set()
    for sec in ("until_switch", "off_for_good"):
        s = hold.get(sec) or {}
        for n in (s.get("services") or []) + (s.get("containers") or []) + (s.get("timers") or []):
            out.add(n[:-8] if n.endswith(".service") else n)
    return out


def enabled_state(unit):
    return sh(["systemctl", "is-enabled", unit], 15).strip()


def services(hold_names):
    out = []
    for line in sh(["systemctl", "list-units", "--type=service", "--state=active", "--no-legend", "--plain",
                    "--no-pager"]).splitlines():
        parts = line.split()
        if not parts or not parts[0].endswith(".service"):
            continue
        name = parts[0][:-8]
        if name.startswith(SKIP_UNIT_PREFIXES) or name in hold_names:
            continue
        if enabled_state(name) != "enabled":
            continue
        if enabled_state(name + ".timer") == "enabled":
            continue
        entry = {"name": name, "type": "systemd", "critical": name in CRITICAL_UNITS}
        if name == "nebula":
            entry["mesh"] = True
            entry["note"] = "lighthouse: only a plain systemctl restart when it is down; /etc/nebula never touched"
        out.append(entry)
    return sorted(out, key=lambda e: e["name"])


def containers(hold_names):
    ids = sh(["docker", "ps", "-q"]).split()
    if not ids:
        return [], {}
    fmt = ("{{.Name}}\t{{.HostConfig.RestartPolicy.Name}}\t{{.Config.Image}}\t"
           "{{index .Config.Labels \"com.docker.compose.project\"}}\t"
           "{{index .Config.Labels \"com.docker.compose.service\"}}\t"
           "{{index .Config.Labels \"com.docker.compose.depends_on\"}}")
    rows = []
    for line in sh(["docker", "inspect", "-f", fmt] + ids).splitlines():
        p = line.split("\t")
        if len(p) < 6:
            continue
        rows.append({"name": p[0].lstrip("/"), "policy": p[1], "image": p[2], "project": p[3],
                     "service": p[4], "deps": p[5]})
    by_proj_svc = {(r["project"], r["service"]): r["name"] for r in rows}
    out, skipped = [], {}
    for r in rows:
        if r["name"] in hold_names:
            skipped[r["name"]] = "on hold"
            continue
        if r["policy"] in ("", "no"):
            skipped[r["name"]] = "no restart policy (run by a unit or by hand)"
            continue
        deps = []
        for d in filter(None, r["deps"].split(",")):
            dep = by_proj_svc.get((r["project"], d.split(":")[0]))
            if dep and dep not in hold_names:
                deps.append(dep)
        e = {"name": r["name"], "image": r["image"], "critical": r["name"] in CRITICAL_CONTAINERS,
             "expected_state": "running"}
        if deps:
            e["depends_on"] = sorted(deps)
        out.append(e)
    return sorted(out, key=lambda e: e["name"]), skipped


def probe(port):
    for path in PROBE_PATHS:
        url = "http://127.0.0.1:%d%s" % (port, path)
        try:
            req = urllib.request.Request(url, method="GET", headers={"User-Agent": "WOPR-SP-manifest/prod-1"})
            code = urllib.request.urlopen(req, timeout=4).getcode()
        except urllib.error.HTTPError as e:
            code = e.code
        except Exception:
            return None
        if code < 500 and (code != 404 or path == "/"):
            return url, code
    return None


def unit_of_pid(pid):
    try:
        with open("/proc/%s/cgroup" % pid) as f:
            m = re.search(r"/system\.slice/([^/\s]+)\.service", f.read())
        return m.group(1) if m else None
    except Exception:
        return None


def backends(svc_list, ctr_list):
    ctr_names = {c["name"] for c in ctr_list}
    svc_names = {s["name"] for s in svc_list}
    ports = {}  # port -> owner (container or unit)
    for line in sh(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"]).splitlines():
        name, _, pstr = line.partition("\t")
        if name not in ctr_names:
            continue
        for m in re.finditer(r"127\.0\.0\.1:(\d+)->", pstr):
            ports.setdefault(int(m.group(1)), ("container", name))
    for line in sh(["ss", "-ltnpH"]).splitlines():
        cols = line.split()
        if len(cols) < 6 or not cols[3].startswith("127.0.0.1:"):
            continue
        port = int(cols[3].rsplit(":", 1)[1])
        m = re.search(r"pid=(\d+)", line)
        unit = unit_of_pid(m.group(1)) if m else None
        if unit in svc_names and port not in ports:
            ports[port] = ("unit", unit)
    out, broken = [], []
    for port in sorted(ports):
        if port in NOT_HTTP:
            continue
        kind, owner = ports[port]
        res = probe(port)
        if not res:
            continue
        url, code = res
        e = {"name": "%s-%d" % (owner, port), "url": url, "expected_status": sorted({200, code}),
             "critical": owner in CRITICAL_CONTAINERS or owner in CRITICAL_UNITS, "discovered_via": "prod1_manifest"}
        if kind == "container":
            e["container"] = owner
        else:
            e["unit"] = owner
        out.append(e)
    for extra in EXTRA_BACKENDS:
        if extra.get("container") and extra["container"] not in ctr_names:
            continue
        port = int(re.search(r":(\d+)/", extra["url"]).group(1))
        res = probe(port)
        if not res:
            broken.append(extra["url"])
            continue
        e = dict(extra, expected_status=sorted({200, res[1]}), discovered_via="prod1_manifest")
        e["url"] = res[0]
        out.append(e)
    return out, broken


def main():
    write = "--write" in sys.argv or "--switched" in sys.argv
    if os.geteuid() != 0:
        print("run as root"); return 1
    hold = load(HOLD, None)
    if not isinstance(hold, dict):
        print("FAIL: %s missing or unreadable" % HOLD); return 1
    if "--switched" in sys.argv:
        us = hold.get("until_switch") or {}
        if any(us.get(k) for k in ("services", "containers", "timers")):
            hold.setdefault("released_at_switch", {})[datetime.now().isoformat(timespec="seconds")] = us
            hold["until_switch"] = {"services": [], "containers": [], "timers": []}
            tmp = HOLD + ".tmp"
            with open(tmp, "w") as f:
                json.dump(hold, f, indent=2)
            os.chmod(tmp, 0o644)
            os.rename(tmp, HOLD)
            print("hold: until_switch released (kept under released_at_switch)")
        else:
            print("hold: until_switch already empty")
    hn = held(hold)
    svc = services(hn)
    ctr, skipped = containers(hn)
    be, broken = backends(svc, ctr)
    manifest = {
        "version": "prod1-strict-1",
        "host": os.uname().nodename,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "generator": "prod1_manifest.py (WOPR-260)",
        "strict_manifest": True,
        "autodiscovery": False,
        "llm_remediation": False,
        "container_runtime": "docker",
        "alerts": {"ntfy_url": "http://127.0.0.1:18081", "topic": "wopr-alerts", "urgent_topic": "wopr-texts",
                   "defcon2_email": False,
                   "_note": "DEFCON-1: mail + wopr-texts priority 5. DEFCON-2: wopr-alerts only (the alert "
                            "forwarder decides what becomes a text); its mail stays muted as on the Rig (WOPR-175)."},
        "mail_units": ["postfix", "opendkim", "protonmail-bridge"],
        "services": svc,
        "containers": ctr,
        "http_endpoints": {"public": [], "backend": be},
        "log_noise_filters": [],
    }
    bad = sorted(hn & ({s["name"] for s in svc} | {c["name"] for c in ctr}))
    old = load(MANIFEST, {})
    names = lambda m, k: {e.get("name") for e in m.get(k, [])}
    print("services   %d: %s" % (len(svc), " ".join(s["name"] for s in svc)))
    print("containers %d: %s" % (len(ctr), " ".join(c["name"] for c in ctr)))
    print("backends   %d: %s" % (len(be), " ".join(e["url"].split("//")[1] for e in be)))
    if skipped:
        print("not watched: " + "; ".join("%s (%s)" % kv for kv in sorted(skipped.items())))
    if broken:
        print("WARN: not answering now, left out: " + " ".join(broken))
    for k in ("services", "containers"):
        add, rem = names(manifest, k) - names(old, k), names(old, k) - names(manifest, k)
        if add or rem:
            print("diff %s: +%s -%s" % (k, sorted(add), sorted(rem)))
    if bad:
        print("FAIL: on hold but would be watched: %s" % bad); return 1
    if not svc or not ctr:
        print("FAIL: empty services or containers; refusing to write"); return 1
    if not write:
        print("dry run (nothing written); --write to write it")
        return 0
    if os.path.exists(MANIFEST):
        subprocess.run(["cp", "-p", MANIFEST, MANIFEST + ".prev"], check=False)
    tmp = MANIFEST + ".tmp"
    with open(tmp, "w") as f:
        json.dump(manifest, f, indent=2)
    os.chmod(tmp, 0o644)
    os.rename(tmp, MANIFEST)
    print("WROTE %s: %d services, %d containers, %d backends" % (MANIFEST, len(svc), len(ctr), len(be)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
