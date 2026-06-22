#!/usr/bin/env python3
"""WOPR alert -> SMS forwarder (anti-avalanche): critical-only, dedup, rate-capped."""
import os, json, time, re, hashlib, urllib.request, collections, smtplib
from email.mime.text import MIMEText
NTFY_BASE = os.environ.get("NTFY_BASE", "https://notify.wopr.systems")
TOPICS    = os.environ.get("ALERT_TOPICS", "wopr-alerts,gpu-scheduler,asscast")
TOKEN     = os.environ.get("NTFY_TOKEN", "")
SMS_GW    = os.environ.get("SMS_GW_URL", "http://127.0.0.1:7890/send")
DEST      = os.environ.get("ALERT_PHONE", "+12172097937")
COOLDOWN  = int(os.environ.get("DEDUP_SECONDS", "1800"))
MAX_HR    = int(os.environ.get("MAX_SMS_PER_HOUR", "8"))
CRIT = re.compile(r"down|fail|critical|error|breach|expired|oom|unreachable|emergency|attack|intrusion|\U0001F6A8|\U0001F534|❌|sacred|offline|crash", re.I)
SKIP = re.compile(r"recovered|resolved|\bok\b|back online|✅|cleared|healthy|test ok", re.I)
MIN_GAP    = int(os.environ.get("SMS_MIN_GAP", "25"))      # sec between modem sends (anti burst-drop)
EMAIL_SMS  = os.environ.get("EMAIL_SMS_DEST", "")  # carrier email-to-SMS (tmomail.net CONFIRMED DEAD 2026-06-22; off)
EMAIL_FROM = os.environ.get("ALERT_FROM_EMAIL", "wopr-alerts@wopr.systems")
seen = {}; sent = collections.deque(); last_suppress = [0.0]; last_sms = [0.0]
def keep(m):
    t=(m.get("title") or ""); b=(m.get("message") or ""); pri=m.get("priority",3); s=t+" "+b
    if SKIP.search(s): return None
    if not (pri>=4 or CRIT.search(s)): return None
    h=hashlib.md5((m.get("topic","")+t+b[:40]).encode()).hexdigest(); now=time.time()
    if h in seen and now-seen[h]<COOLDOWN: return None
    seen[h]=now
    while sent and now-sent[0]>3600: sent.popleft()
    if len(sent)>=MAX_HR:
        if now-last_suppress[0]>3600: last_suppress[0]=now; return "RATE"
        return None
    return (t,b)
def _email_sms(text):
    if not EMAIL_SMS: return
    try:
        msg=MIMEText(text); msg["From"]=EMAIL_FROM; msg["To"]=EMAIL_SMS
        with smtplib.SMTP("localhost",25) as srv: srv.sendmail(EMAIL_FROM,[EMAIL_SMS],msg.as_string())
        print("email-sms sent",flush=True)
    except Exception as e: print("email-sms err:",e,flush=True)
def sms(text):
    gap=MIN_GAP-(time.time()-last_sms[0])      # space bursts (carrier drops back-to-back A2P SMS)
    if gap>0: time.sleep(gap)
    last_sms[0]=time.time()
    text=text[:150]
    data=json.dumps({"number":DEST,"text":text}).encode()
    req=urllib.request.Request(SMS_GW,data=data,headers={"Content-Type":"application/json"},method="POST")
    try: urllib.request.urlopen(req,timeout=20); print("SMS sent:",text[:60],flush=True)
    except Exception as e: print("sms err:",e,flush=True)
    _email_sms(text)                            # independent backup path (email -> carrier SMS)
def run():
    url=f"{NTFY_BASE}/{TOPICS}/json"
    print("alert->sms watching",url,"-> ",DEST,flush=True)
    while True:
        try:
            req=urllib.request.Request(url,headers={"Authorization":"Bearer "+TOKEN} if TOKEN else {})
            with urllib.request.urlopen(req,timeout=900) as r:
                for line in r:
                    try: m=json.loads(line.decode())
                    except: continue
                    if m.get("event")!="message": continue
                    res=keep(m)
                    if res=="RATE": sms("WOPR: alert rate cap hit (8/hr). More suppressed this hour - check dashboard."); sent.append(time.time())
                    elif res: sms(("WOPR ALERT: "+res[0]+" - "+res[1]).strip(" -")); sent.append(time.time())
        except Exception as e:
            print("stream err, retry 10s:",e,flush=True); time.sleep(10)
if __name__=="__main__": run()
