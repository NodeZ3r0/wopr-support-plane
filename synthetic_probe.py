#!/usr/bin/env python3
"""WOPR synthetic endpoint prober (support-plane check).
Tests real user-journey endpoints THROUGH Caddy (Host: -> 127.0.0.1:18080), asserts
status + JSON validity. Catches migration class-bugs (dead ports, stripped routes ->
empty/405/000 bodies) that container/log health checks miss. Does NOT follow redirects
(so a 301/302 alias is seen as healthy, not chased out to the external URL).
ntfy alerts ONLY on failure-set CHANGE (no spam). Cron */5."""
import json, os, urllib.request, urllib.error

CADDY      = "http://127.0.0.1:18080"
NTFY_URL   = os.environ.get("NTFY_URL", "http://127.0.0.1:18081")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "wopr-alerts")
STATE      = "/opt/wopr/support-plane/.synthetic_probe_state.json"
LOG        = "/opt/wopr/support-plane/synthetic_probe.log"

OK   = [200]
REDIR= [301, 302, 308]
# name, host, method, path, body, expect_status, expect_json, json_key
PROBES = [
  # ---- deep auth/api checks (the migration class-bug targets) ----
  ("brainjoos api/health",   "brainjoos.com",          "GET", "/api/health", None, OK, True,  "status"),
  ("brainjoos flow executor","brainjoos.com",          "GET", "/api/v3/flows/executor/brainjoos-authentication/?query=", None, OK, True, "component"),
  ("brainjoos api/me noauth","brainjoos.com",          "GET", "/api/me", None, [401], True, "error"),
  ("store auth-api/login",   "thedudeabides.shop",     "POST","/auth-api/login", {"username":"probe@invalid.test","password":"x"}, [401], True, "error"),
  ("store auth-api/register","thedudeabides.shop",     "POST","/auth-api/register", {}, [400], True, "error"),
  ("authentik health",       "auth.wopr.systems",      "GET", "/-/health/ready/", None, [200,204], False, None),
  ("lovejoos api health",    "api.lovejoos.com",       "GET", "/health", None, OK, True, "status"),
  # ---- public brand / revenue / storefront / foundation reachability ----
  ("brainjoos.com",          "brainjoos.com",          "GET","/",None,OK,False,None),
  ("brainjoos.wopr.systems", "brainjoos.wopr.systems", "GET","/",None,OK,False,None),
  ("lovejoos.com",           "lovejoos.com",           "GET","/",None,OK,False,None),
  ("lovejoos.lgbt redir",    "lovejoos.lgbt",          "GET","/",None,REDIR,False,None),
  ("artjoos.art",            "artjoos.art",            "GET","/",None,OK,False,None),
  ("thedudeabides.shop",     "thedudeabides.shop",     "GET","/",None,OK,False,None),
  ("dudeabides.wopr.systems","dudeabides.wopr.systems","GET","/",None,OK,False,None),
  ("commiesocialists.org",   "commiesocialists.org",   "GET","/",None,OK,False,None),
  ("shop.commiesocialists",  "shop.commiesocialists.org","GET","/",None,REDIR,False,None),
  ("barterra.store",         "barterra.store",         "GET","/",None,OK,False,None),
  ("buylocal.barterra",      "buylocal.barterra.store","GET","/",None,OK,False,None),
  ("blackoutlabs.store",     "blackoutlabs.store",     "GET","/",None,OK,False,None),
  ("folkmoot.app",           "folkmoot.app",           "GET","/",None,OK,False,None),
  ("asscast.org",            "asscast.org",            "GET","/",None,OK,False,None),
  ("wopr.systems",           "wopr.systems",           "GET","/",None,OK,False,None),
  ("wopr.foundation",        "wopr.foundation",        "GET","/",None,OK,False,None),
  ("project2028",            "project2028.wopr.systems","GET","/",None,OK,False,None),
  ("powerforthepeople",      "powerforthepeople.party","GET","/",None,OK,False,None),
  ("reactorai.app",          "reactorai.app",          "GET","/",None,OK,False,None),
  ("defconone.app",          "defconone.app",          "GET","/",None,OK,False,None),
  ("tismtrail.com",          "tismtrail.com",          "GET","/",None,OK,False,None),
  ("statestreettheater",     "statestreettheater.wopr.systems","GET","/",None,OK,False,None),
  ("social.wopr.systems",    "social.wopr.systems",    "GET","/",None,OK,False,None),
  ("mstdn.wopr.systems",     "mstdn.wopr.systems",     "GET","/health",None,OK,False,None),
  ("nostr-api relay",        "nostr-api.wopr.systems",  "GET","/",None,OK,False,None),
  ("falken.wopr.systems",    "falken.wopr.systems",    "GET","/",None,OK,False,None),
  ("multiverse",             "multiverse.wopr.systems","GET","/",None,OK,False,None),
]

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None
_OPENER = urllib.request.build_opener(_NoRedirect)

def probe(name, host, method, path, body, exp, ej, jk):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Host": host}
    if data is not None: h["Content-Type"] = "application/json"
    req = urllib.request.Request(CADDY + path, data=data, headers=h, method=method)
    st, raw, er = None, b"", None
    try:
        r = _OPENER.open(req, timeout=12); st = r.status; raw = r.read()
    except urllib.error.HTTPError as e:
        st = e.code; raw = e.read()
    except Exception as e:
        er = type(e).__name__
    if er: return "UNREACHABLE(%s)" % er
    if st not in exp: return "status %s want %s" % (st, exp)
    if ej:
        try:
            j = json.loads(raw)
            if jk and jk not in j: return "json missing '%s'" % jk
        except Exception:
            return "NOT JSON (empty/html body)"
    return None

def ntfy(title, msg, priority, tags):
    try:
        req = urllib.request.Request(NTFY_URL + "/" + NTFY_TOPIC, data=msg.encode(),
            headers={"Title": title, "Priority": priority, "Tags": tags}, method="POST")
        urllib.request.urlopen(req, timeout=10)
    except Exception: pass

def main():
    fails = {}
    for p in PROBES:
        r = probe(*p)
        if r: fails[p[0]] = r
    cur = set(fails)
    try: prev = set(json.load(open(STATE)).get("failing", []))
    except Exception: prev = set()
    new_break = cur - prev
    recovered = prev - cur
    if new_break:
        ntfy("Synthetic probe: %d DOWN" % len(new_break),
             "\n".join("%s: %s" % (k, fails[k]) for k in sorted(new_break)), "high", "rotating_light")
    if recovered and not new_break:
        ntfy("Synthetic probe: recovered", "Back up: " + ", ".join(sorted(recovered)), "default", "white_check_mark")
    try: json.dump({"failing": sorted(cur)}, open(STATE, "w"))
    except Exception: pass
    line = "probe: %d/%d ok" % (len(PROBES)-len(cur), len(PROBES)) + ("" if not cur else " | FAIL: " + "; ".join("%s(%s)" % (k, fails[k]) for k in sorted(cur)))
    try: open(LOG, "a").write(line + "\n")
    except Exception: pass
    print(line)

if __name__ == "__main__":
    main()