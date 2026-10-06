"""WOPR-082: the sign-in probe pages only for access points that worked before,
calls Authentik's own page a failure, checks OIDC discovery is on the app's own
host, never pages on a network blip, and names itself to Cloudflare.
Fakes HTTP, the DB and ntfy; state lives in a temp dir.

    python3 tests/test_sso_access_probe.py
"""
import json, os, sys, tempfile, types

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sso_access_probe.py")
TMP = tempfile.mkdtemp(prefix="ssoprobetest-")
fails = 0


def check(name, cond):
    global fails
    print(("PASS " if cond else "FAIL ") + name)
    fails += 0 if cond else 1


p = types.ModuleType("ssoprobe")
p.__file__ = SRC
exec(compile(open(SRC).read(), SRC, "exec"), p.__dict__)
real_fetch = p.fetch
p.STATE = os.path.join(TMP, "state.json")
p.RETRY_DELAY = 0
p.EXTRA_TARGETS = []
H = "b.yourspace.you"
db = [[{"host": H, "label": "YourSpace page"}]]
p.db_targets = lambda: db[0]
sent, ntfy_up, answers = [], [True], {}
p.ntfy = lambda title, msg, prio, tags: (sent.append((title, prio)), ntfy_up[0])[1]
real_check = p.check
p.check = lambda item, t: answers[item]


def run(**ans):
    answers.clear()
    answers.update({i: (True, "ok") for i in p.CHECKS})
    answers.update(ans)
    del sent[:]
    sys.argv = ["probe"]
    p.main()
    return json.load(open(p.STATE))["hosts"].get(H, {})


# --- alerting ---
for _ in range(p.FAIL_THRESHOLD + 1):
    s = run(form=(False, "HTTP 404"))
check("never worked (sign-in not rolled out yet) -> logged, no page", not sent and not s["alerted"])

run()
for _ in range(p.FAIL_THRESHOLD):
    s = run(form=(False, "HTTP 502"))
check("worked, then the form breaks for 2 runs -> BROKEN paged high (our zone)",
      s["alerted"] and sent == [("Sign-in BROKEN: " + H, "high")])

s = run(form=(None, "timeout"))
check("a network blip is not a recovery (alert kept, no RECOVERED)", s["alerted"] and not sent)

s = run()
check("fixed -> RECOVERED once, alert cleared", not s["alerted"] and sent and "RECOVERED" in sent[0][0])

ntfy_up[0] = False
for _ in range(p.FAIL_THRESHOLD):
    s = run(no_ak=(False, "HTTP 200 Authentik sign-in page"))
check("BROKEN while ntfy is down is not marked sent", s["alerted"] is False)
ntfy_up[0] = True
s = run(no_ak=(False, "HTTP 200 Authentik sign-in page"))
check("... and goes out once ntfy is back", s["alerted"] and sent)
run()

db[0] = None
for _ in range(p.DB_DOWN_ALERT_RUNS):
    run()
check("control-plane DB unreadable %d runs -> one page, still checks the cached list" % p.DB_DOWN_ALERT_RUNS,
      any("DB unreadable" in t for t, _ in sent) and json.load(open(p.STATE))["hosts"].get(H))
db[0] = [{"host": H, "label": "YourSpace page"}]

# --- the checks themselves, with fake HTTP ---
p.check = real_check
pages = {}
p.fetch = lambda url: pages.get(url.split("://", 1)[1].split("/", 1)[1], (404, {}, "not found"))
T = {"host": H, "label": "x"}
EXEC = "api/v3/flows/executor/default-authentication-flow/?query="
IF = "if/flow/default-authentication-flow/"

pages[EXEC] = (200, {}, json.dumps({"component": "ak-stage-identification"}))
check("form: Authentik answers with a sign-in step -> OK", p.check("form", T)[0] is True)
pages[EXEC] = (404, {}, "<html>Not found</html>")
check("form: the app's own 404 -> FAIL", p.check("form", T)[0] is False)
p.fetch = lambda url: (None, {}, "URLError")
check("form: network error -> could not check (None), not a fail", p.check("form", T)[0] is None)
p.fetch = lambda url: pages.get(url.split("://", 1)[1].split("/", 1)[1], (404, {}, "not found"))

pages[IF] = (200, {"Content-Type": "text/html"}, "<html><title>authentik</title><ak-flow-executor>")
check("no_ak: Authentik's own page served -> FAIL", p.check("no_ak", T)[0] is False)
pages[IF] = (302, {"Location": "/?wopr_sso_flow=default-authentication-flow"}, "")
check("no_ak: redirected into the site's own form -> OK", p.check("no_ak", T)[0] is True)

O = {"host": "forum.example.org", "label": "forum", "oidc_slug": "f"}
DISC = "application/o/f/.well-known/openid-configuration"
pages[DISC] = (200, {}, json.dumps({"issuer": "https://auth.example.org/application/o/f/"}))
check("issuer: discovery on the Authentik host, not the app's -> FAIL", p.check("issuer", O)[0] is False)
pages[DISC] = (200, {}, json.dumps({"issuer": "https://forum.example.org/application/o/f/"}))
check("issuer: on the app's own host -> OK", p.check("issuer", O)[0] is True)
check("issuer: apps without OIDC are not asked", p.check("issuer", T)[0] is True)

# --- names itself (Cloudflare 403s Python-urllib) ---
seen = []


class _Opener:
    def open(self, req, timeout=None):
        seen.append(req.get_header("User-agent"))
        raise OSError("offline")


p._OPENER = _Opener()
check("a request that cannot connect -> None (could not check)", real_fetch("https://x.example/")[0] is None)
check("every request sends a WOPR User-Agent: %s" % seen, seen and seen[0].startswith("WOPR-"))

print("\n%d failure(s)" % fails)
sys.exit(1 if fails else 0)
