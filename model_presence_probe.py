#!/usr/bin/env python3
"""
MODEL PRESENCE probe (support-plane, root cron */15).

Every *_MODEL setting in the env files below must name a model that exists in Ollama.
Alerts ntfy (wopr-alerts) when a configured model goes missing, when Ollama is unreachable,
and once when everything is back.

Root cause (2026-09-23): Falken's pipeline still pointed at joshua:latest after Joshua was
retired; once the model was removed (~2026-09-06) triage silently scored 0.00 for 16 days,
the map emptied and DEFCON read a false 5. Nothing checked that the model existed.

Test: python3 model_presence_probe.py --test --source test=/path/to/fake.env --state /tmp/x.json
"""
import argparse, json, os, re, urllib.request
from datetime import datetime

NTFY_URL   = os.environ.get("NTFY_URL", "http://127.0.0.1:18081")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "wopr-alerts")
STATE      = "/opt/wopr/support-plane/model_presence_probe.state.json"
OLLAMA     = "http://127.0.0.1:11435"               # behind gpu-scheduler :18099
SOURCES    = {
    "falken-pipeline": "/opt/wopr-falken/pipeline/.env",
}


def ntfy(title, msg, priority="high", tags="rotating_light,brain"):
    try:
        req = urllib.request.Request(NTFY_URL + "/" + NTFY_TOPIC, data=msg.encode(),
            headers={"Title": title, "Priority": priority, "Tags": tags}, method="POST")
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def load_state(path):
    try:
        return json.load(open(path))
    except Exception:
        return {}


def save_state(path, st):
    try:
        json.dump(st, open(path, "w"))
    except Exception:
        pass


def norm(name):
    return name if ":" in name.split("/")[-1] else name + ":latest"


def installed():
    try:
        with urllib.request.urlopen(OLLAMA + "/api/tags", timeout=10) as r:
            return {norm(m["name"]) for m in json.loads(r.read().decode()).get("models", [])}
    except Exception:
        return None


def configured(sources):
    """[(service, key, model)] for every KEY_MODEL=value line."""
    out = []
    for svc, path in sources.items():
        try:
            for line in open(path):
                m = re.match(r"^\s*([A-Z0-9_]*MODEL)\s*=\s*['\"]?([^'\"\s#]+)", line)
                if m:
                    out.append((svc, m.group(1), m.group(2)))
        except Exception as e:
            out.append((svc, "UNREADABLE", f"{path}: {e}"))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", action="append", help="name=/path/to/env (replaces the built-in list)")
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--test", action="store_true", help="prefix alert titles with TEST")
    a = ap.parse_args()
    sources = dict(s.split("=", 1) for s in a.source) if a.source else SOURCES
    prefix = "[MODEL] TEST - ignore: " if a.test else "[MODEL] "

    st = load_state(a.state)
    have = installed()
    if have is None:
        problem = f"Ollama {OLLAMA} unreachable; cannot verify configured models."
        missing = []
    else:
        missing = [(s, k, m) for s, k, m in configured(sources)
                   if k == "UNREADABLE" or norm(m) not in have]
        problem = "; ".join(f"{s} {k}={m}" for s, k, m in missing) if missing else ""

    if problem and problem != st.get("problem"):
        ntfy(prefix + ("model missing" if missing else "Ollama unreachable"),
             f"Configured model(s) not in Ollama: {problem}. That service's AI calls will fail or "
             f"score 0 until the model is installed or the setting is changed." if missing else problem)
    elif not problem and st.get("problem"):
        ntfy(prefix + "models OK", "All configured models are present in Ollama again.",
             "default", "white_check_mark")
    st["problem"] = problem
    save_state(a.state, st)
    print(datetime.now().strftime("%F %T"), "missing=", len(missing),
          "problem=", problem or "none")


if __name__ == "__main__":
    main()
