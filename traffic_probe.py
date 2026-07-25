#!/usr/bin/env python3
"""WOPR traffic / SEO probe (support-plane check).

Turns the one-shot "traffic intelligence" brief into a LIVE monitor: every 30 min
it pulls the real numbers from Umami (web analytics) + seo-db (Google Search
Console), regenerates a dashboard at sitrep.wopr.systems/traffic/, and fires an
ntfy/SMS alert the instant a growth "win" signal first trips (first UTM referral,
first real external referrer, first Google click). Cron */30.

Reads via `docker exec psql` (no python DB driver needed) like the other probes.
State: /opt/wopr/support-plane/traffic_probe.state.json  (also the alert memory).
"""
import os, json, subprocess, html, datetime

NTFY_URL   = os.environ.get("NTFY_URL",   "http://127.0.0.1:18081")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "wopr-alerts")
STATE   = "/opt/wopr/support-plane/traffic_probe.state.json"
OUT_DIR = "/var/www/sitrep.wopr.systems/traffic"
OUT     = os.path.join(OUT_DIR, "index.html")

def q(container, db, user, sql):
    try:
        r = subprocess.run(
            ["docker","exec",container,"psql","-U",user,"-d",db,"-t","-A","-F","\t","-c",sql],
            capture_output=True, text=True, timeout=25)
        return [ln.split("\t") for ln in r.stdout.strip().splitlines() if ln.strip()]
    except Exception:
        return []

um  = lambda sql: q("wopr-umami-db", "umami",    "umami", sql)
seo = lambda sql: q("seo-db",        "seo_data", "seo",   sql)
def sc(rows, d=0):
    try: return rows[0][0]
    except Exception: return d
def i(rows, d=0):
    try: return int(float(sc(rows, d)))
    except Exception: return d

# ---------------- pull live data ----------------
pv   = i(um("SELECT count(*) FROM website_event WHERE event_type=1"))
pv7  = i(um("SELECT count(*) FROM website_event WHERE event_type=1 AND created_at > now()-interval '7 days'"))
ext  = i(um("SELECT count(*) FROM website_event WHERE referrer_domain<>'' AND referrer_domain NOT ILIKE '%wopr%' AND referrer_domain NOT ILIKE '%localhost%'"))
utm  = i(um("SELECT count(*) FROM website_event WHERE utm_campaign ILIKE 'meme%' OR utm_source ILIKE 'bsky'"))
refs = um("SELECT referrer_domain, count(*) FROM website_event WHERE referrer_domain<>'' AND referrer_domain NOT ILIKE '%wopr%' AND referrer_domain NOT ILIKE '%localhost%' GROUP BY 1 ORDER BY 2 DESC LIMIT 6")
persite = um("SELECT w.name, count(*) FROM website_event e JOIN website w ON w.website_id=e.website_id WHERE e.event_type=1 GROUP BY 1 ORDER BY 2 DESC LIMIT 10")

clk = i(seo("SELECT COALESCE(SUM(clicks),0) FROM gsc_search_data"))
imp = i(seo("SELECT COALESCE(SUM(impressions),0) FROM gsc_search_data"))
gsc = seo("SELECT replace(site,'sc-domain:',''), COALESCE(SUM(clicks),0), COALESCE(SUM(impressions),0) FROM gsc_search_data GROUP BY site ORDER BY 3 DESC LIMIT 12")
asspos = sc(seo("SELECT ROUND(MIN(position)::numeric,1) FROM gsc_search_data WHERE site ILIKE '%asscast%' AND impressions>0"), "—")

signals = {"utm_referrals": utm, "external_referrers": ext, "gsc_clicks": clk}

# ---------------- alert on first-trip transitions ----------------
prev = {}
if os.path.exists(STATE):
    try: prev = json.load(open(STATE))
    except Exception: prev = {}
prev_sig = prev.get("signals", {})
alerts = []
def trip(key, cur, label):
    if cur > 0 and int(prev_sig.get(key, 0)) == 0:
        alerts.append(f"WIN — {label} just went live ({cur}). Traffic has a path in.")
trip("utm_referrals", utm, "first meme-engine UTM referral")
trip("external_referrers", ext, "a real external referrer")
trip("gsc_clicks", clk, "first Google Search click")
for a in alerts:
    try:
        subprocess.run(["curl","-s","-H","Title: WOPR Traffic","-H","Priority: high","-H","Tags: rocket",
                        "-d", a, f"{NTFY_URL}/{NTFY_TOPIC}"], timeout=8)
    except Exception: pass

now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
snap = {"ts": now, "pv": pv, "pv7": pv7, "ext": ext, "utm": utm, "clk": clk, "imp": imp,
        "asspos": asspos, "signals": signals}
os.makedirs(os.path.dirname(STATE), exist_ok=True)
json.dump(snap, open(STATE, "w"), indent=2)

# ---------------- render live dashboard ----------------
def esc(x): return html.escape(str(x))
def kpi(n, label, tone=""):
    return f'<div class="kpi"><span class="n {tone}">{esc(n)}</span><span class="l">{label}</span></div>'
def pill(v):
    return '<span class="s win">LIVE</span>' if int(v) > 0 else '<span class="s wait">waiting</span>'

SIGNALS_TBL = [
    ("Meme-engine UTM referrals", "Umami", utm, "utm_campaign=meme_* &rarr; the link fix landed"),
    ("Real external referrers",   "Umami", ext, "first genuine outside referrer"),
    ("Google Search clicks",      "GSC",   clk, "first clicks (you have impressions, not clicks)"),
]
sig_rows = "".join(
    f'<tr><td>{esc(name)}</td><td class="src">{esc(src)}</td><td class="num">{esc(cur)}</td>'
    f'<td>{pill(cur)}</td><td class="win-def">{goal}</td></tr>'
    for name, src, cur, goal in SIGNALS_TBL)

ps_rows = "".join(f'<tr><td>{esc(n)}</td><td class="num">{esc(c)}</td></tr>' for n, c in persite) \
          or '<tr><td class="dim" colspan="2">no pageviews recorded yet</td></tr>'
ref_rows = "".join(f'<tr><td>{esc(d)}</td><td class="num">{esc(c)}</td></tr>' for d, c in refs) \
           or '<tr><td class="dim" colspan="2">no external referrers yet</td></tr>'
gsc_rows = "".join(f'<tr><td>{esc(s)}</td><td class="num">{esc(c)}</td><td class="num">{esc(m)}</td></tr>'
                   for s, c, m in gsc) \
           or '<tr><td class="dim" colspan="3">no GSC data yet</td></tr>'

PLAYBOOK = [
    "Inject UTM'd CTA links into meme-engine posts (Bluesky first)",
    "Purge Cloudflare cache on lovejoos.com + artjoos.art",
    "CTR rescue: rewrite titles/meta on the page-1 impressions you already own",
    "Extend the shared WOPR global nav to all 19 properties",
    "Add the Nostr relay vhost + cross-post to damus/nos.lol/primal",
    "Revive Bluesky posting; all 8 accounts follow relevant mesh/FOSS accounts",
    'Publish a "What does WOPR stand for" explainer on wopr.systems',
    "Retitle ASScast around its proven phrases",
    "Route podcast/TV drops into relay-connected Mastodon; submit feed to Apple/Spotify",
    "Interlink page-1 sites &rarr; buried sites (free internal PageRank)",
    "Embed ASScast player + newest WOPR TV + listmonk signup on wopr.systems",
    "Serialize /cyoa_stories and syndicate across fedi + ASScast",
    "Seed the forum with pillar posts + lock down spam signups",
    "Fire the first listmonk campaign to existing contacts",
]
play_rows = "".join(
    f'<li><label><input type="checkbox" data-k="pb{n}"><span>{txt}</span></label></li>'
    for n, txt in enumerate(PLAYBOOK))

CSS = r"""
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0b1210;--surface:#111a16;--s2:#16211c;--line:#26362e;--ink:#dce6df;--dim:#8a9c92;
  --accent:#f2a638;--crit:#ec5a41;--good:#54c88a;--mono:ui-monospace,"Cascadia Code","JetBrains Mono",Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
body{background:var(--bg);color:var(--ink);font-family:var(--sans);line-height:1.55;-webkit-font-smoothing:antialiased}
.wrap{max-width:1000px;margin:0 auto;padding:34px 22px 80px}
a{color:var(--accent)}
.top{display:flex;flex-wrap:wrap;gap:12px 20px;align-items:baseline;justify-content:space-between;
  border-bottom:1px solid var(--line);padding-bottom:18px}
.top .tag{font-family:var(--mono);font-size:.7rem;letter-spacing:.22em;text-transform:uppercase;color:var(--accent)}
.top h1{font-family:var(--mono);font-size:clamp(1.2rem,3vw,1.7rem);letter-spacing:.02em;margin-top:5px}
.top .meta{font-family:var(--mono);font-size:.7rem;color:var(--dim);text-align:right;line-height:1.7}
.live{display:inline-flex;align-items:center;gap:6px}
.live::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--good);box-shadow:0 0 0 0 var(--good);animation:p 2s infinite}
@keyframes p{0%{box-shadow:0 0 0 0 rgba(84,200,138,.5)}70%{box-shadow:0 0 0 7px rgba(84,200,138,0)}100%{box-shadow:0 0 0 0 rgba(84,200,138,0)}}
@media(prefers-reduced-motion:reduce){.live::before{animation:none}}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;background:var(--line);border:1px solid var(--line);margin:24px 0 6px}
.kpi{background:var(--surface);padding:15px 17px;display:flex;flex-direction:column;gap:4px}
.kpi .n{font-family:var(--mono);font-size:1.7rem;font-weight:700;font-variant-numeric:tabular-nums;line-height:1}
.kpi .n.bad{color:var(--crit)}.kpi .n.hot{color:var(--accent)}.kpi .n.good{color:var(--good)}
.kpi .l{font-size:.76rem;color:var(--dim);line-height:1.3}
section{margin-top:38px}
.sh{display:flex;align-items:center;gap:12px;margin-bottom:14px}
.sh .k{font-family:var(--mono);font-size:.68rem;color:var(--accent);letter-spacing:.14em;border:1px solid var(--line);padding:3px 8px}
.sh h2{font-family:var(--mono);font-size:.95rem;letter-spacing:.06em;text-transform:uppercase}
.sh .rule{flex:1;height:1px;background:var(--line)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:640px){.grid2{grid-template-columns:1fr}}
.tw{overflow-x:auto;border:1px solid var(--line);background:var(--surface)}
table{border-collapse:collapse;width:100%;font-size:.86rem}
th,td{padding:8px 11px;text-align:left;border-bottom:1px solid var(--line)}
th{font-family:var(--mono);font-size:.66rem;letter-spacing:.06em;text-transform:uppercase;color:var(--dim)}
td.num{font-family:var(--mono);text-align:right;font-variant-numeric:tabular-nums}
td.src{font-family:var(--mono);font-size:.74rem;color:var(--dim)}
td.win-def{color:var(--dim);font-size:.8rem}
td.dim{color:var(--dim)}
tr:last-child td{border-bottom:none}
.s{font-family:var(--mono);font-size:.62rem;letter-spacing:.06em;text-transform:uppercase;padding:2px 7px;border-radius:3px}
.s.win{color:var(--good);background:rgba(84,200,138,.12);border:1px solid rgba(84,200,138,.35)}
.s.wait{color:var(--dim);background:var(--s2);border:1px solid var(--line)}
ol.play{list-style:none;counter-reset:p;border:1px solid var(--line)}
ol.play li{counter-increment:p;border-top:1px solid var(--line);background:var(--surface)}
ol.play li:first-child{border-top:none}
ol.play li:nth-child(-n+4){background:var(--s2)}
ol.play label{display:grid;grid-template-columns:30px 22px 1fr;gap:10px;align-items:center;padding:11px 14px;cursor:pointer}
ol.play label::before{content:counter(p,decimal-leading-zero);font-family:var(--mono);color:var(--accent);font-size:.9rem;font-variant-numeric:tabular-nums}
ol.play input{width:18px;height:18px;accent-color:var(--good)}
ol.play input:checked + span{color:var(--dim);text-decoration:line-through}
.foot{margin-top:46px;padding-top:16px;border-top:1px solid var(--line);font-family:var(--mono);font-size:.7rem;color:var(--dim);letter-spacing:.03em}
.tools{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.tools a{font-family:var(--mono);font-size:.74rem;text-decoration:none;border:1px solid var(--line);padding:5px 10px;color:var(--ink)}
.tools a:hover{border-color:var(--accent)}
"""

HTML = (
"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
"<title>WOPR Traffic // Live</title><style>" + CSS + "</style></head><body><div class=\"wrap\">"
"<header class=\"top\"><div><div class=\"tag\">◢ Traffic &amp; Search // support-plane</div>"
"<h1>WOPR Traffic &mdash; Live</h1></div>"
f"<div class=\"meta\"><span class=\"live\">checked every 30 min</span><br>last: {esc(now)}<br>"
"source: Umami · GSC</div></header>"
"<div class=\"kpis\">"
+ kpi(pv, "web pageviews recorded (all time, 19 sites)", "bad" if pv < 100 else "")
+ kpi(pv7, "pageviews, last 7 days")
+ kpi(ext, "real external referrers", "good" if ext > 0 else "bad")
+ kpi(utm, "meme-engine UTM referrals", "good" if utm > 0 else "bad")
+ kpi(clk, "Google clicks", "good" if clk > 0 else "bad")
+ kpi(imp, "Google impressions", "hot")
+ kpi(asspos, "ASScast best position", "hot")
+ "</div>"
"<section><div class=\"sh\"><span class=\"k\">01</span><h2>Win signals &mdash; watched live</h2><span class=\"rule\"></span></div>"
"<div class=\"tw\"><table><thead><tr><th>Signal</th><th>Source</th><th>Now</th><th>State</th><th>Win =</th></tr></thead><tbody>"
+ sig_rows +
"</tbody></table></div><p style=\"font-size:.8rem;color:var(--dim);margin-top:8px\">The moment any of these flips to <b style=\"color:var(--good)\">LIVE</b>, this probe SMS/ntfy-alerts you — same channel as your other monitors.</p></section>"
"<section><div class=\"grid2\">"
"<div><div class=\"sh\"><span class=\"k\">02</span><h2>Pageviews by site</h2><span class=\"rule\"></span></div>"
"<div class=\"tw\"><table><thead><tr><th>Site</th><th>Views</th></tr></thead><tbody>" + ps_rows + "</tbody></table></div></div>"
"<div><div class=\"sh\"><span class=\"k\">03</span><h2>External referrers</h2><span class=\"rule\"></span></div>"
"<div class=\"tw\"><table><thead><tr><th>Domain</th><th>Hits</th></tr></thead><tbody>" + ref_rows + "</tbody></table></div></div>"
"</div></section>"
"<section><div class=\"sh\"><span class=\"k\">04</span><h2>Search Console &mdash; clicks &amp; impressions</h2><span class=\"rule\"></span></div>"
"<div class=\"tw\"><table><thead><tr><th>Property</th><th>Clicks</th><th>Impressions</th></tr></thead><tbody>" + gsc_rows + "</tbody></table></div></section>"
"<section><div class=\"sh\"><span class=\"k\">05</span><h2>Guerilla playbook &mdash; ranked by impact ÷ effort</h2><span class=\"rule\"></span></div>"
"<ol class=\"play\">" + play_rows + "</ol>"
"<p style=\"font-size:.78rem;color:var(--dim);margin-top:8px\">Top 4 are highlighted. Your ticks are saved in this browser.</p></section>"
"<section><div class=\"sh\"><span class=\"k\">06</span><h2>Underlying tools</h2><span class=\"rule\"></span></div>"
"<div class=\"tools\"><a href=\"https://analytics.wopr.systems\">Umami analytics</a>"
"<a href=\"https://seo.wopr.systems\">SerpBear ranks</a>"
"<a href=\"https://sitrep.wopr.systems\">SITREP</a></div></section>"
f"<p class=\"foot\">Regenerated every 30 min by <b>traffic_probe.py</b> · WOPR support-plane · no paid ads, owned-audience only · {esc(now)}</p>"
"<script>document.querySelectorAll('ol.play input').forEach(function(c){var k='wopr-traf-'+c.dataset.k;"
"try{c.checked=localStorage.getItem(k)==='1'}catch(e){}"
"c.addEventListener('change',function(){try{localStorage.setItem(k,c.checked?'1':'0')}catch(e){}})});</script>"
"</div></body></html>"
)
os.makedirs(OUT_DIR, exist_ok=True)
open(OUT, "w", encoding="utf-8").write(HTML)
print(f"traffic_probe: pv={pv} ext={ext} utm={utm} clk={clk} imp={imp} asspos={asspos} alerts={len(alerts)} -> {OUT}")
