#!/usr/bin/env python3
"""WOPR shop-payments probe (support-plane check) - WOPR-023.

Hits the control-plane's shop endpoints DIRECTLY on 127.0.0.1:8001 (not through
Caddy) every 5 min and asserts they behave safely:

  - the API is alive (/api/health 200)
  - every shop route stays MOUNTED and auth-gated (401 without an Authentik
    header) - a stripped route or a 500 shows up as a status change
  - the Connect WEBHOOK REFUSES an unsigned payload (never 200). This is the
    security-regression alarm: if a code change ever let an unsigned webhook
    through, sales/unlocks could be forged. That one fires at high priority.

Alerts ONLY on failure-set CHANGE (no spam), like the other support-plane
probes. Cron */5.
"""
import json, os, urllib.request, urllib.error

APP        = os.environ.get("WOPR_CP_URL", "http://127.0.0.1:8001")
NTFY_URL   = os.environ.get("NTFY_URL", "http://127.0.0.1:18081")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "wopr-alerts")
STATE      = "/opt/wopr/support-plane/.shop_probe_state.json"
LOG        = "/opt/wopr/support-plane/shop_probe.log"


def _req(method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    h = dict(headers or {})
    if data is not None:
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(APP + path, data=data, headers=h, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=12)
        return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return None, ("UNREACHABLE(%s)" % type(e).__name__).encode()


def check_alive():
    st, _ = _req("GET", "/api/health")
    return None if st == 200 else "health status %s want 200" % st


def check_route_gated(name, method, path, body=None):
    # No Authentik header -> the app must answer 401, proving the route is
    # mounted and refuses anonymous callers. 404/500/000 means it broke.
    st, _ = _req(method, path, body)
    return None if st == 401 else "%s status %s want 401 (route mounted+gated)" % (name, st)


def check_webhook_refuses_unsigned():
    # A bogus signature (and, pre-go-live, no configured secret) must be refused.
    # Accept 400 (bad signature) or 503 (not configured yet) - anything else,
    # especially 200, is a security regression.
    st, _ = _req("POST", "/api/webhook/stripe/connect",
                 body={"id": "evt_probe", "type": "account.updated"},
                 headers={"stripe-signature": "t=1,v1=deadbeef"})
    if st in (400, 503):
        return None
    return "connect webhook accepted an UNSIGNED payload (status %s) - refuses expected" % st


def run_checks():
    fails = {}
    for name, fn in [
        ("control-plane alive", check_alive),
        ("shop/status gated", lambda: check_route_gated("shop/status", "GET", "/api/v1/shop/status")),
        ("connect/callback gated", lambda: check_route_gated("connect/callback", "GET", "/api/v1/shop/connect/callback")),
        ("unlock/confirm gated", lambda: check_route_gated("unlock/confirm", "GET", "/api/v1/shop/unlock/confirm?session_id=x")),
        ("connect webhook refuses unsigned", check_webhook_refuses_unsigned),
    ]:
        try:
            r = fn()
        except Exception as e:  # noqa: BLE001
            r = "probe error: %s" % type(e).__name__
        if r:
            fails[name] = r
    return fails


def ntfy(title, msg, priority, tags):
    try:
        req = urllib.request.Request(
            NTFY_URL + "/" + NTFY_TOPIC, data=msg.encode(),
            headers={"Title": title, "Priority": priority, "Tags": tags}, method="POST")
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def main():
    fails = run_checks()

    # The unsigned-webhook failure is a security regression -> always high prio.
    security_break = "connect webhook refuses unsigned" in fails

    prev = {}
    try:
        with open(STATE) as f:
            prev = json.load(f)
    except Exception:
        prev = {}

    prev_fails = set(prev.get("fails", []))
    now_fails = set(fails.keys())

    new_break = now_fails - prev_fails
    recovered = prev_fails - now_fails

    if new_break:
        detail = "; ".join("%s: %s" % (k, fails[k]) for k in sorted(new_break))
        if security_break:
            ntfy("SHOP PROBE: SECURITY REGRESSION", detail, "urgent", "rotating_light,lock")
        else:
            ntfy("Shop probe: %d DOWN" % len(new_break), detail, "high", "warning")
    if recovered and not new_break:
        ntfy("Shop probe: recovered", "Back OK: " + ", ".join(sorted(recovered)), "default", "white_check_mark")

    try:
        with open(STATE, "w") as f:
            json.dump({"fails": sorted(now_fails)}, f)
    except Exception:
        pass

    # A line in the log every run, so "is it even running" is answerable.
    try:
        from datetime import datetime
        with open(LOG, "a") as f:
            f.write("[%s] fails=%s\n" % (datetime.now().isoformat(timespec="seconds"), sorted(now_fails)))
    except Exception:
        pass

    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
