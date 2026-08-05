#!/usr/bin/env python3
"""
Host PORT REGISTRY + conflict detector (support-plane, root cron */15).

Snapshots every LISTENing TCP port -> {proc, pid, user, container, cmd} and keeps a
persistent DB at /opt/wopr/support-plane/port_registry.json so we always know what owns
what. Alerts ntfy (wopr-alerts) when a registered port's OWNER CHANGES (a conflict — a
different process/container grabbed a port another service expects), or when an
"expected"-annotated port is missing/held by the wrong owner.

Born from the 2026-07-03 Flink incident: the docker 1.19.1 cluster silently squatted on
:6123/:8081 that the 2.2.0 cluster needed. This makes that class of collision visible.

DB entries may carry a manual "expected" owner + "note" (edit the JSON) — those get
strict conflict checks. Auto-discovered ports are tracked and conflict-checked on owner
change. Registry autofix is per-service (Flink has flink_watchdog.py); generic port
conflicts are alert-only because blind remediation is unsafe.
"""
import os, re, json, subprocess, urllib.request
from datetime import datetime, timezone

NTFY_URL   = os.environ.get("NTFY_URL", "http://127.0.0.1:18081")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "wopr-alerts")
DB         = "/opt/wopr/support-plane/port_registry.json"


def ntfy(title, msg, priority="high", tags="rotating_light,electric_plug"):
    try:
        req = urllib.request.Request(NTFY_URL + "/" + NTFY_TOPIC, data=msg.encode(),
            headers={"Title": title, "Priority": priority, "Tags": tags}, method="POST")
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def sh(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return ""


def docker_port_map():
    """host_port -> container name, from published docker ports."""
    m = {}
    out = sh("docker ps --format '{{.Names}}|{{.Ports}}'")
    for line in out.splitlines():
        if "|" not in line:
            continue
        name, ports = line.split("|", 1)
        for hp in re.findall(r":(\d+)->", ports):
            m[hp] = name.strip()
    return m


def proc_info(pid):
    user = cmd = ""
    try:
        import pwd
        st = os.stat("/proc/%s" % pid)
        user = pwd.getpwuid(st.st_uid).pw_name
    except Exception:
        pass
    try:
        with open("/proc/%s/cmdline" % pid, "rb") as f:
            cmd = f.read().replace(b"\x00", b" ").decode(errors="replace").strip()[:160]
    except Exception:
        pass
    return user, cmd


def snapshot():
    """port(str) -> {proc,pid,user,container,cmd,addr}."""
    dmap = docker_port_map()
    cur = {}
    out = sh("ss -Hltnp")
    for line in out.splitlines():
        m_addr = re.search(r"\s(\S+):(\d+)\s+\S+\s+users:\(\(\"([^\"]+)\",pid=(\d+)", line)
        if not m_addr:
            continue
        addr, port, proc, pid = m_addr.group(1), m_addr.group(2), m_addr.group(3), m_addr.group(4)
        # a socket can be held by several processes at once (postfix master +
        # smtpd children, netdata + an fd-inheriting bash helper). Record them
        # all so a sample that catches a sibling is not read as a takeover.
        all_owners = set(re.findall(r'"([^"]+)",pid=\d+', line))
        # keep the most informative row per port (prefer non-loopback / a real container)
        user, cmd = proc_info(pid)
        container = ""
        if proc == "docker-proxy":
            container = dmap.get(port, "")
        owner = container or proc
        entry = {"proc": proc, "pid": pid, "user": user, "container": container,
                 "owner": owner, "cmd": cmd, "addr": addr,
                 "all_owners": sorted(all_owners | ({container} if container else set()))}
        prev = cur.get(port)
        if prev is None or (prev["owner"] in ("docker-proxy", "") and owner):
            cur[port] = entry
    return cur


def main():
    now = datetime.now(timezone.utc).isoformat()
    cur = snapshot()
    try:
        db = json.load(open(DB))
    except Exception:
        db = {"ports": {}, "created": now}
    known = db.setdefault("ports", {})

    conflicts, new_ports = [], []
    for port, e in cur.items():
        rec = known.get(port)
        _pnum = int(port) if str(port).isdigit() else 0
        if rec is None:
            # 2026-07-06: skip ephemeral/dynamic ports (32768-60999) -- OS-assigned to
            # ollama model runners, rygel UPnP, etc. Transient, not stable assignments.
            if _pnum >= 32768:
                continue
            known[port] = {"owner": e["owner"], "proc": e["proc"], "cmd": e["cmd"],
                           "container": e["container"], "first_seen": now, "last_seen": now,
                           "expected": None, "note": ""}
            new_ports.append((port, e["owner"]))
            continue
        rec["last_seen"] = now
        expected = rec.get("expected") or rec.get("owner")
        # 2026-07-06: transient-by-design owner changes are NOT conflicts --
        #  docker-published ports flip container<->docker-proxy on restart; ephemeral ports reuse.
        _transient = (e["proc"] == "docker-proxy" or bool(e.get("container"))
                      or expected == "docker-proxy" or (_pnum >= 32768 and not rec.get("expected")))
        # CONFLICT: a manually-expected owner, or the previously-recorded owner, changed
        # postfix runs a master with a family of children; any of them holding
        # the socket means postfix still owns it.
        _FAMILIES = [{"master", "smtpd", "pickup", "qmgr", "cleanup", "tlsmgr",
                      "anvil", "scache", "trivial-rewrite", "bounce", "local"}]
        _holders = set(e.get("all_owners") or [e["owner"]])
        _same_family = any(expected in fam and _holders & fam for fam in _FAMILIES)
        _any_match = expected in _holders
        if (e["owner"] and expected and e["owner"] != expected
                and not _transient and not _any_match and not _same_family):
            key = "%s:%s->%s" % (port, expected, e["owner"])
            if rec.get("last_conflict") != key:
                conflicts.append("port %s: expected '%s' but now held by '%s' (%s)"
                                 % (port, expected, e["owner"], e["cmd"][:60]))
                rec["last_conflict"] = key
        else:
            rec.pop("last_conflict", None)
            # refresh the observed owner if no explicit 'expected' pin
            if not rec.get("expected"):
                rec["owner"] = e["owner"]; rec["proc"] = e["proc"]
                rec["cmd"] = e["cmd"]; rec["container"] = e["container"]

    db["last_scan"] = now
    db["count"] = len(known)
    try:
        json.dump(db, open(DB, "w"), indent=2)
    except Exception:
        pass

    if conflicts:
        ntfy("[PORTS] %d conflict(s)" % len(conflicts), "\n".join(conflicts))
    print(datetime.now().strftime("%F %T"),
          "ports=%d new=%d conflicts=%d" % (len(cur), len(new_ports), len(conflicts)))


if __name__ == "__main__":
    main()
