#!/usr/bin/env python3
"""WOPR Support Plane - Metrics + Local Actions API. Port 9101."""
import json, os, time, socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timedelta
from collections import Counter
from urllib.parse import urlparse, parse_qs

HOSTNAME = socket.gethostname()
ACTIONS_LOG = "/var/lib/wopr-support-plane-actions.json"
FIX_MEMORY = "/var/lib/wopr-support-plane-fix-memory.json"
LEARNED_FIXES = "/var/lib/wopr-support-plane-learned-fixes.json"
STATE_FILE = "/var/lib/wopr-support-plane-state.json"
HEARTBEAT = "/var/lib/wopr-support-plane-heartbeat"
PORT = 9101

def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except:
        return {}

def get_actions_entries():
    data = load_json(ACTIONS_LOG)
    return data.get("entries", data.get("actions", []))

def get_metrics():
    lines = []
    actions = load_json(ACTIONS_LOG)
    fixes = load_json(FIX_MEMORY)
    learned = load_json(LEARNED_FIXES)
    state = load_json(STATE_FILE)
    entries = actions.get("entries", actions.get("actions", []))
    now = datetime.now()
    recent_24h = []
    recent_1h = []
    for e in entries:
        try:
            ts = datetime.fromisoformat(e["ts"])
            age = (now - ts).total_seconds()
            if age < 86400: recent_24h.append(e)
            if age < 3600: recent_1h.append(e)
        except: pass
    for e in recent_24h:
        a = e.get("action", "unknown").replace('"', "")
        r = e.get("result", "unknown").replace('"', "")
        lines.append('wopr_sp_actions_24h{host="%s",action="%s",result="%s"} 1' % (HOSTNAME, a, r))
    for e in recent_1h:
        a = e.get("action", "unknown").replace('"', "")
        r = e.get("result", "unknown").replace('"', "")
        lines.append('wopr_sp_actions_1h{host="%s",action="%s",result="%s"} 1' % (HOSTNAME, a, r))
    lines.append('wopr_sp_actions_total{host="%s"} %d' % (HOSTNAME, len(entries)))
    fs = fixes.get("stats", {})
    lines.append('wopr_sp_fixes_attempted{host="%s"} %d' % (HOSTNAME, fs.get("total_attempted", 0)))
    lines.append('wopr_sp_fixes_success{host="%s"} %d' % (HOSTNAME, fs.get("total_success", 0)))
    lines.append('wopr_sp_fixes_failed{host="%s"} %d' % (HOSTNAME, fs.get("total_failed", 0)))
    lines.append('wopr_sp_failed_approaches{host="%s"} %d' % (HOSTNAME, fs.get("total_failed_approaches", 0)))
    lf = learned.get("fixes", [])
    lines.append('wopr_sp_learned_fixes{host="%s"} %d' % (HOSTNAME, len(lf)))
    issues = state.get("issues", [])
    ic = state.get("issue_count", len(issues) if isinstance(issues, list) else 0)
    lines.append('wopr_sp_current_issues{host="%s"} %d' % (HOSTNAME, ic))
    if isinstance(issues, list):
        tc = Counter(i.get("tier", 0) for i in issues)
        for tier, count in tc.items():
            lines.append('wopr_sp_issues_by_tier{host="%s",tier="%s"} %d' % (HOSTNAME, tier, count))
    hb_age = 9999
    try: hb_age = time.time() - os.path.getmtime(HEARTBEAT)
    except: pass
    lines.append('wopr_sp_heartbeat_age_seconds{host="%s"} %.0f' % (HOSTNAME, hb_age))
    up = 1 if hb_age < 600 else 0
    lines.append('wopr_sp_up{host="%s"} %d' % (HOSTNAME, up))
    return "\n".join(lines) + "\n"

def handle_actions(params):
    limit = int(params.get("limit", ["100"])[0])
    since_hours = int(params.get("since", ["72"])[0])
    entries = get_actions_entries()
    cutoff = (datetime.now() - timedelta(hours=since_hours)).isoformat()
    filtered = [a for a in entries if a.get("ts", "") >= cutoff]
    for a in filtered:
        if "host" not in a:
            a["host"] = HOSTNAME
    result = filtered[-limit:]
    result.reverse()
    return json.dumps({"actions": result, "host": HOSTNAME, "count": len(result)})

def handle_actions_stats():
    entries = get_actions_entries()
    now = datetime.now()
    cutoff_24h = (now - timedelta(hours=24)).isoformat()
    cutoff_7d = (now - timedelta(days=7)).isoformat()
    recent = [a for a in entries if a.get("ts", "") >= cutoff_24h]
    week = [a for a in entries if a.get("ts", "") >= cutoff_7d]
    successes = len([a for a in recent if a.get("result") == "success"])
    failures = len([a for a in recent if a.get("result") == "failed"])
    type_counts = {}
    for a in recent:
        t = a.get("action", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
    return json.dumps({"host": HOSTNAME, "total_24h": len(recent), "total_7d": len(week), "total_all": len(entries), "successes_24h": successes, "failures_24h": failures, "by_type": type_counts})

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)
        if path == "/metrics" or path == "" or path == "/":
            body = get_metrics().encode()
            ctype = "text/plain"
        elif path == "/actions/stats":
            body = handle_actions_stats().encode()
            ctype = "application/json"
        elif path == "/actions":
            body = handle_actions(params).encode()
            ctype = "application/json"
        elif path == "/health":
            body = json.dumps({"status": "ok", "host": HOSTNAME, "port": PORT}).encode()
            ctype = "application/json"
        else:
            body = b"not found"
            ctype = "text/plain"
            self.send_response(404)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, format, *args): pass

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print("WOPR SP Metrics+Actions on :%d (host=%s)" % (PORT, HOSTNAME))
    server.serve_forever()
