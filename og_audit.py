import re, subprocess
from urllib.parse import urljoin, urlparse

SITES = [
    "https://lovejoos.com/", "https://thedudeabides.shop/", "https://wopr.foundation/",
    "https://wopr.systems/", "https://brainjoos.com/", "https://artjoos.art/",
    "https://commiesocialists.org/", "https://barterra.store/", "https://blackoutlabs.store/",
    "https://folkmoot.app/", "https://asscast.org/", "https://project2028.wopr.systems/",
    "https://powerforthepeople.party/", "https://statestreettheater.wopr.systems/",
    "https://tismtrail.com/", "https://tismtrail.quest/", "https://reactorai.app/",
    "https://defconone.app/", "https://sonicforge.wopr.systems/", "https://cyoa.wopr.systems/",
]
_dns={}
def pub_ip(h):
    if h in _dns: return _dns[h]
    ip=None
    try:
        for l in subprocess.run(["dig","+short","@1.1.1.1",h],capture_output=True,text=True,timeout=8).stdout.splitlines():
            l=l.strip()
            if l and l[0].isdigit(): ip=l;break
    except Exception: pass
    _dns[h]=ip;return ip
def curl(url,body=False):
    p=urlparse(url);host=p.hostname or "";port=443 if p.scheme=="https" else 80;ip=pub_ip(host)
    a=["curl","-sL","--max-time","15","-A","Mozilla/5.0 (compatible; WOPR-audit)","-w","\n__C__%{http_code}__T__%{content_type}"]
    if ip:a+=["--resolve",f"{host}:{port}:{ip}"]
    if not body:a+=["-o","/dev/null"]
    a.append(url)
    try:
        r=subprocess.run(a,capture_output=True,timeout=20);o=r.stdout
        m=re.search(rb"__C__(\d+)__T__([^\n]*)$",o)
        if not m:return 0,"",b""
        return int(m.group(1)),m.group(2).decode("utf-8","replace"),(o[:m.start()] if body else b"")
    except Exception:return 0,"",b""
def find(html,pat):
    m=re.search(pat,html,re.I);return m.group(1).strip() if m else None
for site in SITES:
    s,_,body=curl(site,body=True)
    if s!=200:
        print(f"{site:42} PAGE {s}");continue
    h=body.decode("utf-8","replace")
    fav=find(h,r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]*href=["\']([^"\']+)')
    fav_url=urljoin(site,fav) if fav else urljoin(site,"/favicon.ico")
    fs,fct,_=curl(fav_url)
    ogt=find(h,r'property=["\']og:title["\'][^>]*content=["\']([^"\']*)')
    ogd=find(h,r'property=["\']og:description["\'][^>]*content=["\']([^"\']*)')
    ogi=find(h,r'property=["\']og:image["\'][^>]*content=["\']([^"\']+)')
    tw=find(h,r'name=["\']twitter:card["\'][^>]*content=["\']([^"\']*)')
    ois="-"
    if ogi:
        ois,_,_=curl(urljoin(site,ogi));ois=str(ois)
    miss=[]
    if not (fs==200):miss.append(f"FAVICON({fs})")
    if not ogt:miss.append("og:title")
    if not ogd:miss.append("og:desc")
    if not ogi:miss.append("og:image")
    elif ois!="200":miss.append(f"og:image({ois})")
    if not tw:miss.append("twitter:card")
    print(f"{site:42} {'OK' if not miss else 'MISSING: '+', '.join(miss)}")

# --- support-plane mode: alert on any MISSING (run with --alert) ---
def _alert_mode():
    import json as _j, time as _t, urllib.request as _u
    NTFY="https://notify.wopr.systems/wopr-alerts"; ST="/opt/wopr/support-plane/og_audit.state.json"
    bad=[]
    for site in SITES:
        s,_,body=curl(site,body=True)
        if s!=200: continue
        h=body.decode("utf-8","replace")
        fav=find(h,r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]*href=["\']([^"\']+)')
        fs,_,_=curl(urljoin(site,fav) if fav else urljoin(site,"/favicon.ico"))
        ogi=find(h,r'property=["\']og:image["\'][^>]*content=["\']([^"\']+)')
        ois=curl(urljoin(site,ogi))[0] if ogi else 0
        m=[]
        if fs!=200: m.append("favicon")
        if not find(h,r'property=["\']og:title["\'][^>]*content=["\']([^"\']*)'): m.append("og:title")
        if not ogi: m.append("og:image")
        elif ois!=200: m.append("og:image-broken")
        if not find(h,r'name=["\']twitter:card["\'][^>]*content=["\']([^"\']*)'): m.append("twitter:card")
        if m: bad.append(f"{site}: {','.join(m)}")
    now=int(_t.time())
    try: st=_j.load(open(ST))
    except Exception: st={}
    fresh=[b for b in bad if now-st.get(b.split(':')[0],0)>86400]
    for b in fresh: st[b.split(':')[0]]=now
    _j.dump({k:v for k,v in st.items() if now-v<7*86400},open(ST,"w"))
    print(f"og-audit: {len(bad)} sites with missing favicon/OG")
    for b in bad: print("  "+b)
    if fresh:
        try: _u.urlopen(_u.Request(NTFY,data=("Sites missing favicon/OG:\n"+"\n".join(fresh)).encode(),
            headers={"Title":"WOPR favicon/OG missing"}),timeout=10)
        except Exception: pass

if __name__=="__main__":
    import sys
    if "--alert" in sys.argv: _alert_mode()
