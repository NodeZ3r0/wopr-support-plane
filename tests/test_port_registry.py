"""WOPR-075: a port held by two sockets on different addresses (Proton Bridge
on 127.0.0.1:1026 + its socat forwarder on 192.168.160.1:1026) is not a
takeover, whichever order ss lists them in. A real takeover still alerts.

    python3 tests/test_port_registry.py
"""
import json, os, sys, tempfile, types

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "port_registry.py")
fails = 0


def check(name, cond):
    global fails
    print(("PASS " if cond else "FAIL ") + name)
    fails += 0 if cond else 1


BRIDGE = 'LISTEN 0 4096 127.0.0.1:1026 0.0.0.0:* users:(("bridge",pid=10779,fd=16))'
SOCAT = 'LISTEN 0 5 192.168.160.1:1026 0.0.0.0:* users:(("socat",pid=575573,fd=5))'
EVIL = 'LISTEN 0 5 0.0.0.0:1026 0.0.0.0:* users:(("nc",pid=4242,fd=3))'


def scan(lines, db):
    m = types.ModuleType("pr")
    m.__file__ = SRC
    exec(compile(open(SRC).read(), SRC, "exec"), m.__dict__)
    sent = []
    m.DB = db
    m.sh = lambda cmd: "\n".join(lines) if cmd.startswith("ss ") else ""
    m.docker_port_map = lambda: {}
    m.proc_info = lambda pid: ("root", "/usr/bin/x --pid " + pid)
    m.ntfy = lambda title, msg, *a, **k: sent.append(msg)
    m.main()
    return sent


db = os.path.join(tempfile.mkdtemp(prefix="prtest-"), "reg.json")
scan([BRIDGE, SOCAT], db)                      # first sight: bridge recorded
check("registry records bridge as the owner", json.load(open(db))["ports"]["1026"]["owner"] == "bridge")
check("same order again -> no alert", scan([BRIDGE, SOCAT], db) == [])
check("bridge restarted, ss lists socat first -> no alert (the 02:15 text)", scan([SOCAT, BRIDGE], db) == [])
check("owner does not flip-flop to socat", json.load(open(db))["ports"]["1026"]["owner"] == "bridge")
check("bridge gone, only a stranger on the port -> alerts", len(scan([EVIL], db)) == 1)

sys.exit(1 if fails else 0)
