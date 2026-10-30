#!/usr/bin/env python3
"""Restart guard for a support plane that may only heal what its manifest lists (WOPR-260, Prod-1).

A manifest with "strict_manifest": true turns the guard on. Then the support plane, its watchdog and
the failsafe may restart a systemd unit or a container ONLY when all of these hold:
  - the manifest lists it (services[].name / containers[].name);
  - hold-until-switch.json does not name it (sections until_switch and off_for_good);
    an unreadable hold file blocks every restart (fail closed);
  - a unit: `systemctl is-enabled` says exactly "enabled" (never static, disabled, masked) and it
    has no enabled .timer (a timer-driven job is the timer's business);
  - a container: it has a restart policy. To stop one on purpose: take it out of the manifest, or
    `docker update --restart=no NAME && docker stop NAME`.
  - it was not stopped on purpose: a container Docker marks HasBeenManuallyStopped (`docker stop`,
    `docker kill`, `docker compose stop`), or a unit that ran this boot and went inactive with
    Result=success (`systemctl stop`), is left alone. Crashed / failed ones are healed (Docker's own
    restart policy already restarts crashed containers).
  - the plane is not paused: /etc/wopr/support-plane.PAUSED (switch night: the final syncs stop
    containers on Prod-1 to copy their data; a restart in the middle would corrupt the copy).
nebula is never restarted through these checks: restart_mesh_if_down() is the only thing that may
touch it, a plain `systemctl restart nebula` when it is down (also while paused). Nothing here reads
or writes /etc/nebula.

Without the flag (the Rig) every check answers True, so the Rig behaves exactly as before.
"""
import json
import os
import subprocess
import urllib.request
from datetime import datetime, timezone

MANIFEST_FILE = "/opt/wopr/support-plane/services-manifest.json"
HOLD_FILE = "/opt/wopr/support-plane/hold-until-switch.json"
PAUSE_FILE = "/etc/wopr/support-plane.PAUSED"
MESH_UNIT = "nebula"


def paused():
    return os.path.exists(PAUSE_FILE)


def _load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def manifest():
    return _load(MANIFEST_FILE) or {}


def strict(m=None):
    m = manifest() if m is None else m
    return bool(m.get("strict_manifest"))


def unit_name(n):
    n = (n or "").strip()
    return n[:-8] if n.endswith(".service") else n


def held_names():
    """Names in the hold file, or None if it cannot be read."""
    d = _load(HOLD_FILE)
    if not isinstance(d, dict):
        return None
    out = set()
    for sec in ("until_switch", "off_for_good"):
        s = d.get(sec) or {}
        for n in (s.get("services") or []) + (s.get("containers") or []) + (s.get("timers") or []):
            out.add(unit_name(n))
    return out


def _out(cmd, timeout=15):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout.strip()
    except Exception:
        return ""


def may_restart_unit(name, m=None):
    """-> (ok, reason)."""
    m = manifest() if m is None else m
    if not strict(m):
        return True, "not strict"
    u = unit_name(name)
    if u == MESH_UNIT:
        return False, "nebula: only a plain restart when it is down (restart_mesh_if_down)"
    listed = {unit_name(s.get("name")) for s in m.get("services", []) if s.get("type", "systemd") == "systemd"}
    if u not in listed:
        return False, "not in the manifest"
    held = held_names()
    if held is None:
        return False, "hold file unreadable (fail closed)"
    if u in held:
        return False, "on hold until the switch"
    if paused():
        return False, "paused (%s)" % PAUSE_FILE
    state = _out(["systemctl", "is-enabled", u])
    if state != "enabled":
        return False, "is-enabled=%s" % (state or "?")
    if _out(["systemctl", "is-enabled", u + ".timer"]) == "enabled":
        return False, "timer-driven"
    if unit_stopped_on_purpose(u):
        return False, "stopped on purpose (ran this boot, inactive, Result=success)"
    return True, "ok"


def unit_stopped_on_purpose(u):
    props = {}
    for line in _out(["systemctl", "show", u, "-p", "ActiveState", "-p", "Result",
                      "-p", "ActiveEnterTimestampMonotonic"]).splitlines():
        k, _, v = line.partition("=")
        props[k] = v
    return (props.get("ActiveState") == "inactive" and props.get("Result") == "success"
            and props.get("ActiveEnterTimestampMonotonic", "0") not in ("", "0"))


def container_stopped_on_purpose(name, runtime="docker"):
    st = _out([runtime, "inspect", "-f", "{{.State.Status}} {{.State.FinishedAt}} {{.Id}}", name]).split()
    if len(st) < 3 or st[0] in ("running", "restarting", "paused"):
        return False
    if st[0] == "created":
        return True  # never started: created to be started later (switch-night containers)
    # Docker persists this flag (it is what makes unless-stopped stay down): true after
    # `docker stop`/`docker kill`/`compose stop`, false after a crash and again after `docker start`.
    root = _out([runtime, "info", "-f", "{{.DockerRootDir}}"]) or "/var/lib/docker"
    cfg = _load(os.path.join(root, "containers", st[2], "config.v2.json"))
    if isinstance(cfg, dict) and "HasBeenManuallyStopped" in cfg:
        return bool(cfg["HasBeenManuallyStopped"])
    # Fallback: a "stop" event around the exit (Docker keeps only the last few hundred events).
    try:
        t = datetime.strptime(st[1][:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return False
    acts = _out([runtime, "events", "--since", str(int(t) - 30), "--until", str(int(t) + 30),
                 "--filter", "container=" + name, "--format", "{{.Action}}"], timeout=20).split()
    return "stop" in acts


def may_restart_container(name, runtime="docker", m=None):
    """-> (ok, reason)."""
    m = manifest() if m is None else m
    if not strict(m):
        return True, "not strict"
    if name not in {c.get("name") for c in m.get("containers", [])}:
        return False, "not in the manifest"
    held = held_names()
    if held is None:
        return False, "hold file unreadable (fail closed)"
    if name in held:
        return False, "on hold until the switch"
    if paused():
        return False, "paused (%s)" % PAUSE_FILE
    pol = _out([runtime, "inspect", "-f", "{{.HostConfig.RestartPolicy.Name}}", name]).lower()
    if pol in ("", "no"):
        return False, "no restart policy (stopped on purpose)"
    if container_stopped_on_purpose(name, runtime):
        return False, "stopped on purpose (docker stop)"
    return True, "ok"


def mesh_down():
    return _out(["systemctl", "is-active", MESH_UNIT]) not in ("active", "activating", "reloading")


def restart_mesh_if_down():
    """The only thing a strict support plane ever does to nebula (Prod-1 is the mesh lighthouse):
    a plain `systemctl restart nebula` when it is down. Returns None if it was up, else True/False."""
    if not mesh_down():
        return None
    try:
        r = subprocess.run(["systemctl", "restart", MESH_UNIT], capture_output=True, text=True, timeout=60)
    except Exception:
        return False
    return r.returncode == 0 and not mesh_down()


def alerts_conf(m=None):
    m = manifest() if m is None else m
    a = m.get("alerts") or {}
    return {
        "ntfy_url": a.get("ntfy_url", "http://127.0.0.1:18081").rstrip("/"),
        "topic": a.get("topic", "wopr-alerts"),
        "urgent_topic": a.get("urgent_topic", "wopr-texts"),
        "defcon2_email": bool(a.get("defcon2_email", True)),
    }


def ntfy(topic, title, body, priority="default", tags="", m=None):
    """Push to the local ntfy (anonymous write-only topics). Returns True on success, never raises."""
    c = alerts_conf(m)
    try:
        headers = {"Title": title[:200].encode("ascii", "replace").decode(), "Priority": str(priority)}
        if tags:
            headers["Tags"] = tags
        req = urllib.request.Request("%s/%s" % (c["ntfy_url"], topic), data=body[:3500].encode(),
                                     headers=headers, method="POST")
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception:
        return False
