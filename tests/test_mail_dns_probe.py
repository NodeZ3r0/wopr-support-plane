"""WOPR-074 review: mail_dns_probe never reports a false OK on a half-failed
lookup, never loses an alert ntfy didn't take, and never hands dig an option.
Fakes DNS, the DB and ntfy; state lives in a temp dir.

    python3 tests/test_mail_dns_probe.py
"""
import json, os, sys, tempfile, types

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "mail_dns_probe.py")
TMP = tempfile.mkdtemp(prefix="probetest-")
fails = 0


def check(name, cond):
    global fails
    print(("PASS " if cond else "FAIL ") + name)
    fails += 0 if cond else 1


T = {"domain": "b.yourspace.you", "ip": "203.0.113.9", "selector": "wopr", "label": "control plane"}
p = types.ModuleType("probe")
p.__file__ = SRC
exec(compile(open(SRC).read(), SRC, "exec"), p.__dict__)
p.STATE = os.path.join(TMP, "state.json")
p.RETRY_DELAY = 0
p.db_targets = lambda: [dict(T)]
sent, ntfy_up, answers = [], [True], {}
p.ntfy = lambda title, msg, prio, tags: (sent.append(title), ntfy_up[0])[1]
p.check = lambda item, t: answers[item]


def run(**ans):
    answers.clear()
    answers.update({i: (True, "ok") for i in p.CHECKS})
    answers.update(ans)
    del sent[:]
    sys.argv = ["probe"]
    p.main()
    return json.load(open(p.STATE))["domains"].get(T["domain"], {})


run()                                                    # healthy: ever_ok
for _ in range(p.FAIL_THRESHOLD):
    s = run(dkim=(False, "nothing"))
check("DKIM gone -> BROKEN sent and recorded", s["alerted"] and any("BROKEN" in x for x in sent))

s = run(dkim=(None, "lookup error"))
check("DKIM lookup times out, rest OK -> NOT a recovery (alert kept, no RECOVERED)",
      s["alerted"] and not any("RECOVERED" in x for x in sent))

ntfy_up[0] = False
s = run()
check("all OK but ntfy down -> RECOVERED retried next run", s["alerted"] is True)
ntfy_up[0] = True
s = run()
check("ntfy back -> RECOVERED sent, alert cleared", not s["alerted"] and any("RECOVERED" in x for x in sent))

ntfy_up[0] = False
for _ in range(p.FAIL_THRESHOLD):
    s = run(ptr=(False, "nothing"))
check("BROKEN while ntfy is down is not marked sent", s["alerted"] is False)
ntfy_up[0] = True
s = run(ptr=(False, "nothing"))
check("... and goes out once ntfy is back", s["alerted"] and any("BROKEN" in x for x in sent))

check("dig refuses a name that would be an option", p.dig("-f/etc/shadow", "TXT") is None
      and p.dig("@1.2.3.4", "TXT") is None and p.dig("not-an-ip", "PTR") is None)

sys.exit(1 if fails else 0)
