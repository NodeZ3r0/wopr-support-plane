#!/usr/bin/env python3
"""WOPR content-integrity probe (support-plane check).
Catches the failure class the other probes MISS: an HTML page that returns 200 but whose
<body> has been stripped/truncated to nothing (blank page, no console error). The earlier
probes only assert status (synthetic) or check images (image_probe) -- a 200-with-empty-body
sails through. project2032.us roadmap/constitution/indictment/swiss-model were lost this way.

DISCRIMINATOR (avoids flagging SPAs): a truly-corrupt static page has <div> count == 0
(all content gone). React/Vite SPAs always keep a root <div>, so they never match. Jinja
templates ({% extends %}) and non-served backup/venv dirs are skipped.

AUTO-HEAL: if a verified-good backup exists (real <body>, >=3 divs, >200 visible chars),
the corrupt live file is saved aside as *.corrupt.<ts> and the backup is restored, then
re-verified. Otherwise alert-only. ntfy on every heal/alert. Cron */30."""
import os,re,glob,json,time,subprocess

NTFY_URL=os.environ.get("NTFY_URL","http://127.0.0.1:18081")
NTFY_TOPIC=os.environ.get("NTFY_TOPIC","wopr-alerts")
STATE="/opt/wopr/support-plane/content_probe.state.json"
ROOTS=["/var/www/project2028","/var/www/tismtrail","/var/www/asscast.org","/var/www/barterra",
       "/var/www/brainjoos","/var/www/cyoa","/var/www/commiesocialists.org","/var/www/pftp",
       "/var/www/sonicforge","/var/www/wopr-spa","/var/www/wopr-plan","/var/www/nodez3r0",
       "/var/www/sitrep.wopr.systems","/var/www/snitch","/var/www/orc","/var/www/install.wopr.systems",
       "/etc/caddy/pages","/var/www/chat-pages"]
SKIP=("/node_modules/","/.git/","/venv/","/backup","/backups/","backup_","/__pycache__/")
SKIPNAME=(".bak",".corrupt.",".preBLT","_placeholder","preinject")

def visible(body):
    t=re.sub(r"<script.*?</script>","",body,flags=re.S|re.I)
    t=re.sub(r"<style.*?</style>","",t,flags=re.S|re.I)
    t=re.sub(r"<[^>]+>"," ",t); return re.sub(r"\s+"," ",t).strip()

def is_corrupt(h):
    if "{%" in h: return False                       # Jinja template, body lives in base
    if "<div" in h.lower(): return False             # has content/SPA root -> not stripped
    closed = "</body>" in h.lower() or "</html>" in h.lower()
    bodyopen = h.lower().count("<body")
    m=re.search(r"<body[^>]*>(.*)</body>",h,re.S|re.I)
    vt=visible(m.group(1)) if m else visible(h)
    return closed and bodyopen==0 and len(vt)<120

def is_good(h):
    if h.lower().count("<body")<1: return False
    if h.lower().count("<div")<3: return False
    m=re.search(r"<body[^>]*>(.*)</body>",h,re.S|re.I)
    return m and len(visible(m.group(1)))>200

def ntfy(title,msg,prio="high",tags="rotating_light"):
    try:
        import urllib.request
        urllib.request.urlopen(urllib.request.Request(f"{NTFY_URL}/{NTFY_TOPIC}",data=msg.encode(),
            headers={"Title":title,"Priority":prio,"Tags":tags}),timeout=10)
    except Exception: pass

def main():
    dry = "--dry-run" in os.sys.argv
    healed=[]; alerted=[]; scanned=0
    for root in ROOTS:
        if not os.path.isdir(root): continue
        for dp,dn,fn in os.walk(root):
            if any(s in dp+"/" for s in SKIP): continue
            for f in fn:
                if not f.endswith((".html",".htm")) or any(s in f for s in SKIPNAME): continue
                p=os.path.join(dp,f); scanned+=1
                try: h=open(p,encoding="utf-8",errors="replace").read()
                except Exception: continue
                if not is_corrupt(h): continue
                # pick newest verified-good backup
                cands=sorted(glob.glob(p+".bak*")+glob.glob(p[:-5]+"*.bak*"),
                             key=lambda x:os.path.getmtime(x),reverse=True)
                pick=next((c for c in cands if is_good(open(c,encoding="utf-8",errors="replace").read())),None)
                if pick and not dry:
                    ts=time.strftime("%Y%m%d%H%M%S")
                    subprocess.run(["cp","-p",p,p+".corrupt."+ts]); subprocess.run(["cp","-p",pick,p])
                    ok=is_good(open(p,encoding="utf-8",errors="replace").read())
                    healed.append((p,os.path.basename(pick),ok))
                elif pick and dry:
                    healed.append((p,os.path.basename(pick),"DRY"))
                else:
                    alerted.append(p)
    print("content-probe: scanned %d, healed %d, alert-only %d"%(scanned,len(healed),len(alerted)))
    for p,b,ok in healed: print("  HEAL %s <- %s (ok=%s)"%(p,b,ok))
    for p in alerted: print("  ALERT(no good backup) %s"%p)
    # state + ntfy on change
    cur=sorted(set([p for p,_,_ in healed]+alerted))
    try: prev=set(json.load(open(STATE)).get("seen",[]))
    except Exception: prev=set()
    new=[x for x in cur if x not in prev]
    if not dry:
        json.dump({"seen":cur,"ts":int(time.time())},open(STATE,"w"))
        if healed: ntfy("Content-probe: %d blank page(s) AUTO-HEALED"%len(healed),
                        "\n".join("HEALED %s <- %s"%(p,b) for p,b,_ in healed),"default","wrench")
        if [a for a in alerted if a in new]:
            ntfy("Content-probe: blank page, NO backup","\n".join(alerted),"high","rotating_light")

if __name__=="__main__":
    import sys; main()
