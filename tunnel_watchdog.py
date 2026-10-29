#!/usr/bin/env python3
"""WOPR cloudflared tunnel watchdog.

Why this exists: 2026-09-07..09 the tunnel stayed *running* but its edge
connections degraded, and every site behind it (11 hosts) served intermittent
failures for ~64h. systemd's Restart=on-failure never fired because the process
never exited. A manual restart at 2026-09-09 19:36 cleared it instantly.

Watches cloudflared_tunnel_ha_connections on the local metrics endpoint. Requires
sustained degradation before acting, and rate-limits restarts so it can never flap.

Home internet drops (most nights 03:30-05:00, e.g. 2026-10-29 04:17) take every edge
connection down at once. A restart can't fix that, so a bad check with no public
address answering doesn't count toward a restart; the state file says so
(internet_ok) for Joshua and anything else that reads it.
"""
import json, os, socket, subprocess, sys, time, urllib.request

METRICS   = os.environ.get("CF_METRICS", "http://127.0.0.1:20241/metrics")
NTFY_URL  = os.environ.get("NTFY_URL", "http://127.0.0.1:18081")
NTFY_TOPIC= os.environ.get("NTFY_TOPIC", "wopr-alerts")
STATE     = "/opt/wopr/support-plane/tunnel_watchdog.state.json"
UNIT      = "cloudflared"
WANT_CONNS   = 4     # a healthy tunnel holds 4 edge connections
BAD_STREAK   = 3     # consecutive bad checks before restarting (3 x 5min = 15min)
RESTART_COOLDOWN = 3600
# public resolvers on four different networks; any one answering = the Rig's internet is up
INTERNET_PROBES = [("9.9.9.9", 443), ("8.8.8.8", 443), ("1.1.1.1", 443), ("208.67.222.222", 443)]
DRY = "--dry-run" in sys.argv

def notify(title, msg, prio="high"):
    if DRY:
        print(f"  [dry-run] would alert: {title}: {msg}"); return
    try:
        urllib.request.urlopen(urllib.request.Request(
            f"{NTFY_URL}/{NTFY_TOPIC}", data=msg.encode(),
            headers={"Title": title, "Priority": prio, "Tags": "satellite"}), timeout=10)
    except Exception:
        pass

def ha_connections():
    """-> int, or None if the metrics endpoint is unreachable."""
    try:
        with urllib.request.urlopen(METRICS, timeout=8) as r:
            for line in r.read().decode("utf-8", "replace").splitlines():
                if line.startswith("cloudflared_tunnel_ha_connections"):
                    return int(float(line.split()[-1]))
    except Exception:
        return None
    return None

def unit_active():
    return subprocess.run(["systemctl", "is-active", "--quiet", UNIT]).returncode == 0

def internet_up():
    """-> True if any public resolver takes a TCP connection."""
    for host, port in INTERNET_PROBES:
        try:
            socket.create_connection((host, port), timeout=4).close()
            return True
        except OSError:
            continue
    return False

def main():
    now = int(time.time())
    try: st = json.load(open(STATE))
    except Exception: st = {}
    streak = st.get("bad_streak", 0)
    last_restart = st.get("last_restart", 0)

    conns, active = ha_connections(), unit_active()
    if not active:
        healthy, why = False, f"{UNIT} is not active"
    elif conns is None:
        healthy, why = False, "metrics endpoint unreachable"
    else:
        healthy, why = conns >= WANT_CONNS, f"ha_connections={conns} (want {WANT_CONNS})"

    internet = True if healthy else internet_up()
    if healthy:
        streak = 0
    elif internet:
        streak += 1
    else:
        why += "; internet down (no public resolver answers), not counted toward a restart"
    action = "none"
    if not healthy and internet and streak >= BAD_STREAK:
        if now - last_restart < RESTART_COOLDOWN:
            action = f"suppressed (restarted {(now-last_restart)//60}m ago)"
        else:
            action = "restart"
            if DRY:
                print(f"  [dry-run] would: systemctl restart {UNIT}")
            else:
                subprocess.run(["systemctl", "restart", UNIT], timeout=60)
                last_restart = now; streak = 0
            notify("WOPR tunnel restarted",
                   f"cloudflared degraded for {BAD_STREAK} consecutive checks ({why}). "
                   f"Restarted. Every site behind the tunnel was likely serving intermittent errors.")

    bad_since = None if healthy else (st.get("bad_since") or now)
    st.update(bad_streak=streak, last_restart=last_restart, last_check=now,
              last_conns=conns, last_healthy=healthy, internet_ok=internet, bad_since=bad_since)
    if not DRY:
        json.dump(st, open(STATE, "w"))
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} tunnel-watchdog: "
          f"{'OK' if healthy else 'DEGRADED'} {why} streak={streak} action={action}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
