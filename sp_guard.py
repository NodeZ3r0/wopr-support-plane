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
nebula is never restarted through these checks: restart_mesh_if_down() is the only thing that may
touch it, a plain `systemctl restart nebula` when it is down. Nothing here reads or writes /etc/nebula.

Without the flag (the Rig) every check answers True, so the Rig behaves exactly as before.
"""
import json
import subprocess
import urllib.request

MANIFEST_FILE = "/opt/wopr/support-plane/services-manifest.json"
HOLD_FILE = "/opt/wopr/support-plane/hold-until-switch.json"
MESH_UNIT = "nebula"


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
    state = _out(["systemctl", "is-enabled", u])
    if state != "enabled":
        return False, "is-enabled=%s" % (state or "?")
    if _out(["systemctl", "is-enabled", u + ".timer"]) == "enabled":
        return False, "timer-driven"
    return True, "ok"


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
    pol = _out([runtime, "inspect", "-f", "{{.HostConfig.RestartPolicy.Name}}", name]).lower()
    if pol in ("", "no"):
        return False, "no restart policy (stopped on purpose)"
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
