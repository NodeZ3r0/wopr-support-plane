#!/usr/bin/env python3
"""WOPR sign-in probe (support-plane check, WOPR-082; contract wopr-sso-embedded-login).

Every beacon access point signs people in with a form built into the app itself, which
talks to the beacon's own Authentik on the app's own address. From the Rig, for each
access point, this checks what a visitor's browser relies on:
  form    GET https://<host>/api/v3/flows/executor/default-authentication-flow/?query=
          -> 200 JSON with an ak-stage-* step: the app's own form can sign people in
  no_ak   GET https://<host>/if/flow/default-authentication-flow/   (redirects not followed)
          -> must NOT be Authentik's own sign-in page (it has to land in the app's form)
  issuer  OIDC apps only: https://<host>/application/o/<slug>/.well-known/openid-configuration
          -> issuer on the same host, so the app's OIDC sign-in returns without a page

Access points: Bear's forum + main site (hand-built) and every active beacon's YourSpace
page (control-plane Postgres `wopr_cp`). A failing check is re-checked before it counts.
An access point that has passed before and then fails FAIL_THRESHOLD runs in a row pages
ntfy (priority high for zones we host, default for customer domains); RECOVERED when it
clears. One that has NEVER passed (sign-in not rolled out there yet) is only logged.

The beacon-side wopr-sso-probe (installer, WOPR-063) checks app logins from inside the box;
this one checks the public, embedded sign-in from outside.

Usage:
  sso_access_probe.py                     normal run (cron): check, alert on change, save state
  sso_access_probe.py --once --verbose    one manual check, print the table, no alerts, no state
  sso_access_probe.py --dry-run           full alert logic, but print alerts instead of sending

Cron (root, on the Rig):
  */15 * * * * /usr/bin/python3 /opt/wopr/support-plane/sso_access_probe.py >> /opt/wopr/support-plane/sso_access_probe.log 2>&1
"""
import argparse, fcntl, json, os, re, subprocess, time, urllib.error, urllib.parse, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
NTFY = "http://127.0.0.1:18081/wopr-alerts"
STATE = os.path.join(HERE, "sso_access_probe.state.json")
FAIL_THRESHOLD = 2        # consecutive failing runs before paging (*/15 -> ~30 min)
CONFIRM_ATTEMPTS = 3      # total tries per failing check within one run
RETRY_DELAY = 5
TIMEOUT = 15
# Cloudflare answers 403 to Python-urllib's default User-Agent.
UA = "WOPR-SSO-Probe/1.0"
LOGIN_FLOW = "default-authentication-flow"
OUR_ZONES = ("wopr.systems", "yourspace.you", "wethepeoplerisenetwork.org")
IGNORE_DOMAINS = {"wopr-lighthouse.wopr.systems"}
EXTRA_TARGETS = [
    {"host": "forum.wethepeoplerisenetwork.org", "label": "Bear forum", "oidc_slug": "wtp-forum"},
    {"host": "wethepeoplerisenetwork.org", "label": "Bear main site"},
]
DB_SQL = "select coalesce(nullif(b.custom_domain,''), b.domain) from beacons b where b.status='active'"
HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")
DB_DOWN_ALERT_RUNS = 8
CHECKS = ("form", "no_ak", "issuer")
HEAD = {"form": "FORM", "no_ak": "NO-AK-PAGE", "issuer": "ISSUER"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def fetch(url):
    """(status, headers, body[:64k]) without following redirects; status None on network error."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json, text/html"})
    try:
        with _OPENER.open(req, timeout=TIMEOUT) as r:
            return r.status, r.headers, r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(65536).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, e.headers, body
    except Exception as e:
        return None, {}, type(e).__name__


def ntfy(title, msg, prio, tags):
    try:
        req = urllib.request.Request(NTFY, data=msg.encode(), method="POST",
                                     headers={"Title": title, "Priority": prio, "Tags": tags})
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception:
        return False


def load_state():
    try:
        return json.load(open(STATE))
    except Exception:
        return {}


def db_targets():
    psql = ["psql", "-d", "wopr_cp", "-At", "-c", DB_SQL]
    cmd = (["runuser", "-u", "postgres", "--"] if os.geteuid() == 0 else ["sudo", "-n", "-u", "postgres"]) + psql
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, cwd="/")
    except Exception:
        return None
    if r.returncode != 0:
        return None
    out = []
    for line in r.stdout.splitlines():
        host = line.strip().lower().rstrip(".")
        if host and host not in IGNORE_DOMAINS and HOST_RE.match(host):
            out.append({"host": host, "label": "YourSpace page"})
    return out


def targets(state):
    rows, src = db_targets(), "db"
    if rows is None or (not rows and state.get("db_targets")):
        rows, src = state.get("db_targets", []), "cached"
        state["db_down_runs"] = state.get("db_down_runs", 0) + 1
    else:
        state["db_targets"], state["db_down_runs"] = rows, 0
    seen = {t["host"] for t in rows}
    return rows + [t for t in EXTRA_TARGETS if t["host"] not in seen], src


def is_authentik_page(status, headers, body):
    ctype = (headers.get("Content-Type", "") if headers else "") or ""
    return status == 200 and "html" in ctype and ("ak-flow-executor" in body or "<title>authentik" in body.lower())


def check(item, t):
    """(ok, seen): ok True/False, or None when the check could not run (network error)."""
    host = t["host"]
    if item == "form":
        st, _, body = fetch("https://%s/api/v3/flows/executor/%s/?query=" % (host, LOGIN_FLOW))
        if st is None:
            return None, body
        try:
            comp = json.loads(body).get("component", "")
        except Exception:
            comp = ""
        return (st == 200 and comp.startswith("ak-stage-")), "HTTP %s %s" % (st, comp or "(not Authentik JSON)")
    if item == "no_ak":
        st, hdr, body = fetch("https://%s/if/flow/%s/" % (host, LOGIN_FLOW))
        if st is None:
            return None, body
        if is_authentik_page(st, hdr, body):
            return False, "HTTP 200 Authentik sign-in page"
        loc = (hdr.get("Location", "") if hdr else "") or ""
        return True, "HTTP %s%s" % (st, (" -> " + loc[:80]) if loc else "")
    if item == "issuer":
        slug = t.get("oidc_slug")
        if not slug:
            return True, "n/a"
        st, _, body = fetch("https://%s/application/o/%s/.well-known/openid-configuration" % (host, slug))
        if st is None:
            return None, body
        try:
            iss = json.loads(body).get("issuer", "")
        except Exception:
            iss = ""
        want = "https://%s/" % host
        return (st == 200 and iss.startswith(want)), "HTTP %s issuer=%s" % (st, iss or "-")
    raise ValueError(item)


def explain(item, t, seen):
    h = t["host"]
    return {
        "form": "%s: the built-in sign-in form cannot reach Authentik (%s). Expected an ak-stage step from "
                "https://%s/api/v3/flows/executor/%s/ - check the site's 'import wopr_sso' Caddy routes and "
                "that the beacon's Authentik is up." % (h, seen, h, LOGIN_FLOW),
        "no_ak": "%s: serves Authentik's own sign-in page at /if/flow/ (%s). It must redirect into the "
                 "site's own form (Caddy wopr_sso snippet)." % (h, seen),
        "issuer": "%s: OIDC discovery is not on the site's own address (%s), so sign-in would show an "
                  "Authentik page. Point the app at https://%s/application/o/%s/." % (h, seen, h, t.get("oidc_slug")),
    }[item]


def ours(host):
    return any(host == z or host.endswith("." + z) for z in OUR_ZONES)


def run_checks(tlist):
    res = {t["host"]: {i: check(i, t) for i in CHECKS} for t in tlist}
    by = {t["host"]: t for t in tlist}
    for _ in range(CONFIRM_ATTEMPTS - 1):
        pending = [(h, i) for h, r in res.items() for i, (ok, _) in r.items() if ok is not True]
        if not pending:
            break
        time.sleep(RETRY_DELAY)
        for h, i in pending:
            ok, seen = check(i, by[h])
            if ok is True or res[h][i][0] is None:
                res[h][i] = (ok, seen)
    return res


def table(tlist, res):
    rows = [("HOST", "WHAT") + tuple(HEAD[i] for i in CHECKS) + ("RESULT",)]
    for t in tlist:
        r = res[t["host"]]
        cells = tuple("OK" if r[i][0] else ("?" if r[i][0] is None else "FAIL") for i in CHECKS)
        rows.append((t["host"], t.get("label", "")) + cells + ("ok" if "FAIL" not in cells else "FAIL",))
    w = [max(len(r[c]) for r in rows) for c in range(len(rows[0]))]
    out = ["  ".join(r[c].ljust(w[c]) for c in range(len(r))) for r in rows]
    for t in tlist:
        for i in CHECKS:
            ok, seen = res[t["host"]][i]
            if ok is False:
                out.append("  - " + explain(i, t, seen))
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Sign-in probe for WOPR beacon access points")
    ap.add_argument("--once", action="store_true", help="single manual check: no alerts, no state write")
    ap.add_argument("--verbose", action="store_true", help="print the per-host table")
    ap.add_argument("--dry-run", action="store_true", help="print alerts instead of sending; no state write")
    a = ap.parse_args()
    quiet = a.once or a.dry_run
    send = (lambda ti, m, p, tg: print("[would ntfy] %s (%s)\n%s" % (ti, p, m)) or True) if a.dry_run else ntfy

    lock = open(STATE + ".lock", "a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("sso_access_probe: previous run still going, skipping")
        return
    state = load_state()
    tlist, src = targets(state)
    if src == "cached" and state.get("db_down_runs") == DB_DOWN_ALERT_RUNS and not a.once:
        send("Sign-in probe: control-plane DB unreadable",
             "sso_access_probe could not list beacons from wopr_cp for %d runs; it is checking the last "
             "known list, so new beacons are not being checked." % DB_DOWN_ALERT_RUNS, "default", "warning")
    res = run_checks(tlist)
    if a.verbose:
        print(table(tlist, res))

    hosts = state.setdefault("hosts", {})
    summary = []
    for t in tlist:
        h, r = t["host"], res[t["host"]]
        failing = [i for i in CHECKS if r[i][0] is False]
        if not failing and any(ok is None for ok, _ in r.values()):
            summary.append("%s=?" % h)  # could not check: neither a pass nor a fail
            continue
        s = hosts.get(h, {"fails": 0, "alerted": False, "ever_ok": False, "alerted_items": []})
        if not failing:
            still = False
            if s.get("alerted") and not a.once:
                still = not send("Sign-in RECOVERED: " + h,
                                 "%s (%s): the built-in sign-in works again." % (h, t.get("label", "")),
                                 "default", "white_check_mark,key")
            hosts[h] = {"fails": 0, "alerted": still, "ever_ok": True, "alerted_items": []}
            summary.append("%s=ok" % h)
            continue
        fails = s.get("fails", 0) + 1
        alerted, items = s.get("alerted", False), s.get("alerted_items", [])
        if s.get("ever_ok") and fails >= FAIL_THRESHOLD and not a.once and (not alerted or items != failing):
            lines = ["- " + explain(i, t, r[i][1]) for i in failing]
            if send("Sign-in BROKEN: " + h,
                    "%s (%s): people cannot sign in the normal way. Wrong for %d runs:\n%s"
                    % (h, t.get("label", ""), fails, "\n".join(lines)),
                    "high" if ours(h) else "default", "key,warning"):
                alerted, items = True, failing  # unsent -> retried next run
        hosts[h] = {"fails": fails, "alerted": alerted, "ever_ok": s.get("ever_ok", False), "alerted_items": items}
        summary.append("%s=FAIL(%s)" % (h, ",".join(HEAD[i] for i in failing)))

    if src == "db":
        for h in [h for h in hosts if h not in {t["host"] for t in tlist}]:
            hosts.pop(h)  # beacon gone: forget it
    if not quiet:
        try:
            tmp = STATE + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(state, fh, indent=1)
            os.replace(tmp, STATE)
        except Exception:
            pass
    print("%s sso_access_probe targets=%d(%s) %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
          len(tlist), src, " ".join(summary)))


if __name__ == "__main__":
    main()
