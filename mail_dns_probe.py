#!/usr/bin/env python3
"""WOPR mail-DNS probe (support-plane check, WOPR-068: every customer beacon sends its own mail).

For every active beacon (control-plane Postgres `wopr_cp`) plus a few hand-built one-offs,
checks the public DNS a receiving mail server looks at, via dig against 1.1.1.1:
  mail A   mail.<domain>                 -> beacon IP
  SPF      TXT <domain>                  contains ip4:<beacon IP>
  DKIM     TXT <selector>._domainkey.<d> has v=DKIM1 and a non-empty p=
  DMARC    TXT _dmarc.<domain>           starts with v=DMARC1
  PTR      reverse of the beacon IP      == mail.<domain>.
(TCP 25 is deliberately NOT checked: beacons only listen on loopback / the docker bridge.)

The mail domain is the beacon's custom_domain when set, else its domain. A failing record is
re-checked (CONFIRM_ATTEMPTS) before it counts. A domain that has passed before and then fails
FAIL_THRESHOLD runs in a row pages ntfy (priority high for zones we host -> SMS via
wopr-alert-sms; priority default for customer-hosted custom domains, which the customer has to
fix). The page lists what is wrong in plain words and the exact record that should exist.
RECOVERED is sent when it clears. A domain that has NEVER passed (mail not built yet) is only
logged, unless ALERT_NEVER_OK is True.

Usage:
  mail_dns_probe.py                     normal run (cron): check, alert on change, save state
  mail_dns_probe.py --once --verbose    one manual check, print the table, no alerts, no state
  mail_dns_probe.py --dry-run           full alert logic, but print alerts instead of sending;
                                        no state write, no remote heal

Cron (root, on the Rig) -- add by hand when ready:
  */30 * * * * /usr/bin/python3 /opt/wopr/support-plane/mail_dns_probe.py >> /opt/wopr/support-plane/mail_dns_probe.log 2>&1
"""
import argparse, json, os, subprocess, sys, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
NTFY = "http://127.0.0.1:18081/wopr-alerts"
STATE = os.path.join(HERE, "mail_dns_probe.state.json")
RESOLVER = "1.1.1.1"
FAIL_THRESHOLD = 2        # consecutive failing runs before paging (*/30 -> ~1h)
CONFIRM_ATTEMPTS = 3      # total tries per failing record within one run
RETRY_DELAY = 5           # seconds between confirm passes
ALERT_NEVER_OK = False    # page for domains that have never passed (mail not set up yet)
DEFAULT_SELECTOR = "wopr" # control-plane beacons sign with s=wopr unless DB says otherwise
# Zones in our Cloudflare account: we own these records, so a break pages high.
OUR_ZONES = ("wopr.systems", "yourspace.you", "wethepeoplerisenetwork.org")
# Active rows in `beacons` that are infrastructure, not mail-sending customer beacons.
IGNORE_DOMAINS = {"wopr-lighthouse.wopr.systems"}
# Hand-built one-offs not (fully) in the control plane.
EXTRA_TARGETS = [
    {"domain": "wethepeoplerisenetwork.org", "ip": "144.126.143.227", "selector": "wtp",
     "label": "Bear / WTP (hand-built)"},
]
# Optional remote heal: when DKIM TXT is missing on a domain in OUR_ZONES, ask the beacon to
# re-post its DKIM key to the control plane. Leave OFF until the beacon unit + CP path exist.
AUTO_REPUBLISH = False
SSH_KEY = "/root/.ssh/id_wopr"
REPUBLISH_CMD = "systemctl start wopr-mail-report.service"

DB_SQL = ("select b.domain, coalesce(b.custom_domain,''), coalesce(host(b.instance_ip),''), "
          "coalesce(b.metadata->>'dkim_selector', (select j.metadata->>'dkim_selector' "
          "from provisioning_jobs j where j.beacon_id=b.id and j.metadata ? 'dkim_selector' "
          "order by j.updated_at desc limit 1), '') "
          "from beacons b where b.status='active'")

CHECKS = ("mail_a", "spf", "dkim", "dmarc", "ptr")
HEAD = {"mail_a": "A", "spf": "SPF", "dkim": "DKIM", "dmarc": "DMARC", "ptr": "PTR"}


def ntfy(title, msg, prio, tags):
    try:
        req = urllib.request.Request(NTFY, data=msg.encode(), method="POST",
                                     headers={"Title": title, "Priority": prio, "Tags": tags})
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def load_state():
    try:
        return json.load(open(STATE))
    except Exception:
        return {}


def db_targets():
    """Active beacons from wopr_cp, or None if the DB can't be read."""
    psql = ["psql", "-d", "wopr_cp", "-At", "-F", "|", "-c", DB_SQL]
    cmd = (["runuser", "-u", "postgres", "--"] if os.geteuid() == 0
           else ["sudo", "-n", "-u", "postgres"]) + psql
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, cwd="/")
    except Exception:
        return None
    if r.returncode != 0:
        return None
    out = []
    for line in r.stdout.splitlines():
        parts = line.split("|")
        if len(parts) != 4:
            continue
        dom, custom, ip, sel = (p.strip() for p in parts)
        if not ip or dom in IGNORE_DOMAINS:
            continue
        out.append({"domain": custom or dom, "ip": ip, "selector": sel or DEFAULT_SELECTOR,
                    "label": dom if custom else "control plane"})
    return out


def targets(state):
    rows = db_targets()
    src = "db"
    if rows is None:  # tolerate DB failure: fall back to the last good list
        rows, src = state.get("db_targets", []), "cached"
    else:
        state["db_targets"] = rows
    seen = {t["domain"] for t in rows}
    return rows + [t for t in EXTRA_TARGETS if t["domain"] not in seen], src


def dig(name, rtype):
    """List of answer lines, or None if the lookup itself failed (resolver unreachable)."""
    args = ["dig", "+short", "+time=3", "+tries=2", "@" + RESOLVER]
    args += ["-x", name] if rtype == "PTR" else [name, rtype]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=20)
    except Exception:
        return None
    if r.returncode != 0:
        return None
    return [l.strip() for l in r.stdout.splitlines() if l.strip() and not l.startswith(";")]


def txt_values(lines):
    # dig prints long TXT as several quoted chunks: "abc" "def" -> abcdef
    return [l.strip('"').replace('" "', "") for l in lines]


def ours(domain):
    return any(domain == z or domain.endswith("." + z) for z in OUR_ZONES)


def check(item, t):
    """(ok, what_we_saw). ok is None when the lookup errored (inconclusive)."""
    d, ip, sel = t["domain"], t["ip"], t["selector"]
    if item == "mail_a":
        a = dig("mail." + d, "A")
        return (None, "lookup error") if a is None else (ip in a, ", ".join(a) or "nothing")
    if item == "spf":
        a = dig(d, "TXT")
        if a is None:
            return None, "lookup error"
        spf = [v for v in txt_values(a) if v.lower().startswith("v=spf1")]
        ok = any(tok in ("ip4:" + ip, "ip4:" + ip + "/32") for v in spf for tok in v.split())
        return ok, (spf[0] if spf else "no SPF record")
    if item == "dkim":
        a = dig("%s._domainkey.%s" % (sel, d), "TXT")
        if a is None:
            return None, "lookup error"
        vals = txt_values(a)
        for v in vals:
            tags = dict(p.strip().split("=", 1) for p in v.split(";") if "=" in p)
            if v.replace(" ", "").startswith("v=DKIM1") and tags.get("p", "").strip():
                return True, "v=DKIM1 key present (s=%s)" % sel
        return False, (vals[0][:60] if vals else "nothing")
    if item == "dmarc":
        a = dig("_dmarc." + d, "TXT")
        if a is None:
            return None, "lookup error"
        vals = txt_values(a)
        return any(v.startswith("v=DMARC1") for v in vals), (vals[0] if vals else "nothing")
    if item == "ptr":
        a = dig(ip, "PTR")
        return (None, "lookup error") if a is None else \
            ("mail.%s." % d in a, ", ".join(a) or "nothing")


def explain(item, t, seen):
    d, ip, sel = t["domain"], t["ip"], t["selector"]
    return {
        "mail_a": "mail.%s does not point at the beacon (got: %s). Need:  mail.%s.  A  %s"
                  % (d, seen, d, ip),
        "spf":    "SPF on %s does not allow the beacon IP (got: %s). Need:  %s.  TXT  \"v=spf1 ip4:%s ~all\""
                  " (or add ip4:%s to the existing SPF)" % (d, seen, d, ip, ip),
        "dkim":   "DKIM key missing for selector %s (got: %s). Need:  %s._domainkey.%s.  TXT  "
                  "\"v=DKIM1; k=rsa; p=<public key from the beacon>\"" % (sel, seen, sel, d),
        "dmarc":  "DMARC missing on %s (got: %s). Need:  _dmarc.%s.  TXT  \"v=DMARC1; p=none; adkim=r; aspf=r\""
                  % (d, seen, d),
        "ptr":    "Reverse DNS of %s is wrong (got: %s). Need PTR %s -> mail.%s. "
                  "(set at the VPS provider, e.g. Contabo rDNS)" % (ip, seen, ip, d),
    }[item]


def run_checks(tlist):
    """results[domain][item] = (ok, seen); failures are confirmed by re-checking."""
    res = {t["domain"]: {i: check(i, t) for i in CHECKS} for t in tlist}
    by = {t["domain"]: t for t in tlist}
    for _ in range(CONFIRM_ATTEMPTS - 1):
        pending = [(d, i) for d, r in res.items() for i, (ok, _) in r.items() if ok is not True]
        if not pending:
            break
        time.sleep(RETRY_DELAY)
        for d, i in pending:
            ok, seen = check(i, by[d])
            if ok is True or res[d][i][0] is None:
                res[d][i] = (ok, seen)
    return res


def table(tlist, res):
    rows = [("DOMAIN", "IP", "SEL") + tuple(HEAD[i] for i in CHECKS) + ("RESULT",)]
    for t in tlist:
        r = res[t["domain"]]
        cells = tuple("OK" if r[i][0] else ("?" if r[i][0] is None else "FAIL") for i in CHECKS)
        bad = [HEAD[i] for i in CHECKS if r[i][0] is False]
        rows.append((t["domain"], t["ip"], t["selector"]) + cells + ("ok" if not bad else "FAIL",))
    w = [max(len(r[c]) for r in rows) for c in range(len(rows[0]))]
    out = ["  ".join(r[c].ljust(w[c]) for c in range(len(r))) for r in rows]
    for t in tlist:
        for i in CHECKS:
            ok, seen = res[t["domain"]][i]
            if ok is False:
                out.append("  - " + explain(i, t, seen))
    return "\n".join(out)


def republish(t):
    try:
        r = subprocess.run(["ssh", "-i", SSH_KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                            "root@" + t["ip"], REPUBLISH_CMD], capture_output=True, text=True, timeout=60)
        return r.returncode == 0
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser(description="Mail DNS probe for WOPR beacons")
    ap.add_argument("--once", action="store_true", help="single manual check: no alerts, no state write")
    ap.add_argument("--verbose", action="store_true", help="print the per-domain table")
    ap.add_argument("--dry-run", action="store_true", help="print alerts instead of sending; no state write")
    a = ap.parse_args()
    quiet = a.once or a.dry_run

    state = load_state()
    tlist, src = targets(state)
    res = run_checks(tlist)
    if a.verbose:
        print(table(tlist, res))

    send = (lambda ti, m, p, tg: print("[would ntfy] %s (%s)\n%s" % (ti, p, m))) if a.dry_run else ntfy
    doms = state.setdefault("domains", {})
    summary = []
    for t in tlist:
        d = t["domain"]
        r = res[d]
        if all(ok is None for ok, _ in r.values()):
            summary.append("%s=?" % d)  # resolver trouble: don't move state
            continue
        failing = [i for i in CHECKS if r[i][0] is False]
        s = doms.get(d, {"fails": 0, "alerted": False, "ever_ok": False, "alerted_items": []})
        hosted = ours(d)
        if not failing:
            if s.get("alerted") and not a.once:
                send("Mail DNS RECOVERED: " + d,
                     "%s (%s) mail records are all correct again (A, SPF, DKIM s=%s, DMARC, PTR)."
                     % (d, t["ip"], t["selector"]), "default", "white_check_mark,email")
            doms[d] = {"fails": 0, "alerted": False, "ever_ok": True, "alerted_items": []}
            summary.append("%s=ok" % d)
            continue
        fails = s.get("fails", 0) + 1
        alerted, items = s.get("alerted", False), s.get("alerted_items", [])
        eligible = (s.get("ever_ok") or ALERT_NEVER_OK) and fails >= FAIL_THRESHOLD
        if eligible and not a.once and (not alerted or items != failing):
            lines = ["- " + explain(i, t, r[i][1]) for i in failing]
            who = "" if hosted else "\nCustom domain we don't host: the customer must add these records."
            send("Mail DNS BROKEN: " + d,
                 "%s (%s, %s) will fail mail delivery checks. Wrong for %d runs:\n%s%s"
                 % (d, t["ip"], t.get("label", ""), fails, "\n".join(lines), who),
                 "high" if hosted else "default", "email,warning")
            alerted, items = True, failing
        if (AUTO_REPUBLISH and not quiet and hosted and "dkim" in failing
                and fails >= FAIL_THRESHOLD and not s.get("republished")):
            s["republished"] = republish(t)
        doms[d] = {"fails": fails, "alerted": alerted, "ever_ok": s.get("ever_ok", False),
                   "alerted_items": items, "republished": s.get("republished", False)}
        summary.append("%s=FAIL(%s)" % (d, ",".join(HEAD[i] for i in failing)))

    for d in [d for d in doms if d not in {t["domain"] for t in tlist}]:
        doms.pop(d)  # beacon gone/decommissioned: forget it
    if not quiet:
        try:
            json.dump(state, open(STATE, "w"), indent=1)
        except Exception:
            pass
    print("%s mail_dns_probe targets=%d(%s) %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
          len(tlist), src, " ".join(summary)))


if __name__ == "__main__":
    main()
