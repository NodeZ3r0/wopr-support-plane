#!/usr/bin/env python3
"""
MODEL PRESENCE probe (support-plane, root cron */15).

Every *_MODEL setting in the env files below must name a model that exists in Ollama.
Alerts ntfy (wopr-alerts) when a configured model goes missing, when Ollama is unreachable,
and once when everything is back.

Also (WOPR-113, propose-only - nothing is ever changed or run):
  * GPU queue starvation: reads "Expired stale queued job ... from <source> after Ns" from
    /opt/gpu-scheduler/scheduler.log and sends one digest per run with counts per source,
    who holds the GPU now, and the proposed fix (each source re-alerts at most every 6 h).
    The scheduler keeps job history only in memory, so the log is the durable record.
  * Model registry (/opt/gpu-scheduler/registry/out/models.json): alerts when a pipeline
    references a ComfyUI model file that is not on disk, and when the registry goes stale.

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
SCHED      = os.environ.get("GPU_SCHEDULER_URL", "http://127.0.0.1:18099")
SCHED_LOG  = "/opt/gpu-scheduler/scheduler.log"
REGISTRY   = "/opt/gpu-scheduler/registry/out/models.json"
STARVE_LOOKBACK_H = 6        # first run looks back this far
STARVE_REALERT_H  = 6        # re-alert a starving source at most this often
REGISTRY_STALE_H  = 24       # registry cron runs every 6 h
EXPIRY_RX  = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d+ WARNING \[gpu-sched\] "
                        r"Expired stale queued job (\S+) from (.+) after (\d+)s\s*$")
ENV_LINE   = r"^\s*([A-Z0-9_]*MODEL)\s*=\s*['\"]?([^'\"\s#]+)"
SOURCES    = {                                       # name: (file, regex -> (key, model) or (model,))
    "falken-pipeline": ("/opt/wopr-falken/pipeline/.env", ENV_LINE),
    "protovision": ("/opt/protovision/.env", ENV_LINE),
    "reactor-chat-default": ("/opt/reactor-mcp/backend/server.py",
                             r"model = data\.get\(\"model\", \"([^\"]+)\"\)"),
    "reactor-cli-default": ("/opt/reactor-mcp/backend/reactor_cli.py",
                            r"os\.getenv\(\"REACTOR_MODEL\", \"([^\"]+)\"\)"),
}


def ntfy(title, msg, priority="high", tags="rotating_light,brain"):
    try:
        req = urllib.request.Request(NTFY_URL + "/" + NTFY_TOPIC, data=msg.encode(),
            headers={"Title": title, "Priority": priority, "Tags": tags}, method="POST")
        with urllib.request.urlopen(req, timeout=10):
            pass                                     # close the connection (was leaking a socket per alert)
    except Exception:
        pass


def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(path, st):
    try:
        with open(path, "w") as f:
            json.dump(st, f)
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
    """[(service, key, model)] for every model setting each source names."""
    out = []
    for svc, (path, rx) in sources.items():
        try:
            found = 0
            with open(path) as f:
                for line in f:
                    m = re.search(rx, line)
                    if m:
                        found += 1
                        g = m.groups()
                        out.append((svc, g[0], g[1]) if len(g) == 2 else (svc, "default", g[0]))
            if not found and rx != ENV_LINE:
                out.append((svc, "UNREADABLE", f"{path}: default model pattern not found"))
        except Exception as e:
            out.append((svc, "UNREADABLE", f"{path}: {e}"))
    return out


# ---- GPU queue starvation + model registry (WOPR-113) -------------------------
# Propose-only: these checks read the scheduler log and the model registry and send
# an ntfy digest with evidence and a proposed fix. They never change, restart, evict
# or run anything (no automatic fixer may act on its own here - BINK, WOPR-088).

def read_lines(paths):
    for p in paths:
        try:
            with open(p, errors="replace") as f:
                yield from f
        except OSError:
            pass


def scan_expiries(lines, since):
    """Queue-expiry cancellations per source logged after `since` ('YYYY-mm-dd HH:MM:SS').
    Returns ({source: {"count", "max_wait", "last", "jobs"}}, newest_timestamp_seen)."""
    out, newest = {}, since
    for line in lines:
        m = EXPIRY_RX.match(line)
        if not m or m.group(1) <= since:
            continue
        ts, jid, src, wait = m.group(1), m.group(2), m.group(3).strip(), int(m.group(4))
        d = out.setdefault(src, {"count": 0, "max_wait": 0, "last": ts, "jobs": []})
        d["count"] += 1
        d["max_wait"] = max(d["max_wait"], wait)
        d["last"] = max(d["last"], ts)
        if len(d["jobs"]) < 5:
            d["jobs"].append(jid)
        newest = max(newest, ts)
    return out, newest


def gpu_holder(sched_url):
    """Who holds the GPU right now, as evidence for a starvation alert."""
    try:
        with urllib.request.urlopen(sched_url + "/jobs", timeout=10) as r:
            j = json.loads(r.read().decode())
        run = j.get("running")
        q = len(j.get("queued") or [])
        if not run:
            return f"nothing running now, {q} queued"
        return (f"{run.get('source')} ({run.get('job_type')}, priority {run.get('priority')}, "
                f"started {str(run.get('started_at') or '')[:19]}), {q} queued behind it")
    except Exception as e:
        return f"scheduler /jobs unreadable ({e})"


def starvation_digest(counts, holder):
    lines = [f"- {src}: {d['count']} job(s) cancelled after waiting up to {d['max_wait']}s "
             f"(last {d['last']}, e.g. {', '.join(d['jobs'][:3])})"
             for src, d in sorted(counts.items(), key=lambda kv: -kv[1]["count"])]
    return ("GPU queue starvation - jobs gave up waiting for the GPU:\n" + "\n".join(lines) +
            f"\nHolding the GPU now: {holder}.\n"
            "Proposed fixes (none applied): callers that poll the scheduler should send "
            "queue_timeout and treat 'cancelled' as a failure (/usr/local/bin/gpu_job does both); "
            "if long batch jobs are ahead in the queue, split them or run them off-hours. "
            "Evidence: grep 'Expired stale queued job' /opt/gpu-scheduler/scheduler.log. Nothing was changed.")


def registry_findings(path, now_epoch, stale_h=REGISTRY_STALE_H):
    """(missing_comfyui_refs:list[str], stale_hours:float|None). (None, None) if no registry yet."""
    try:
        with open(path) as f:
            reg = json.load(f)
    except FileNotFoundError:
        return None, None
    except Exception as e:
        return [f"registry unreadable: {e}"], None
    age_h = (now_epoch - os.path.getmtime(path)) / 3600
    missing = []
    for m in reg.get("missing_references") or []:
        if m.get("kind") != "comfyui":
            continue                    # Ollama names are covered by the env check above
        users = ", ".join(sorted({os.path.basename(os.path.dirname(p)) + "/" + os.path.basename(p)
                                  for p in m.get("referenced_by") or []})[:3])
        missing.append(f"{m.get('name')} (referenced by {users or 'unknown'})")
    return sorted(missing), (age_h if age_h > stale_h else None)


def check_gpu_and_registry(a, st, prefix, now):
    """Run the propose-only GPU/registry checks; mutates and returns state. Returns summary str."""
    summary = []
    # 1) starvation digest
    since = st.get("expiry_since") or (now.timestamp() - STARVE_LOOKBACK_H * 3600)
    if isinstance(since, (int, float)):
        since = datetime.fromtimestamp(since).strftime("%Y-%m-%d %H:%M:%S")
    logs = [a.sched_log]
    rotated = a.sched_log + ".1"
    if os.path.exists(rotated) and datetime.fromtimestamp(os.path.getmtime(rotated)).strftime("%Y-%m-%d %H:%M:%S") > since:
        logs.insert(0, rotated)        # rotation happened since the last run
    counts, newest = scan_expiries(read_lines(logs), since)
    st["expiry_since"] = newest
    alerted = st.setdefault("starve_alerted", {})
    due = {s: d for s, d in counts.items()
           if now.timestamp() - alerted.get(s, 0) >= STARVE_REALERT_H * 3600}
    if due:
        ntfy(prefix + "GPU queue starvation", starvation_digest(due, gpu_holder(a.sched_url)),
             "default", "hourglass,brain")
        for s in due:
            alerted[s] = now.timestamp()
    summary.append(f"expired_since_last={sum(d['count'] for d in counts.values())}")
    # 2) registry: missing ComfyUI checkpoints + stale registry
    missing, stale_h = registry_findings(a.registry, now.timestamp())
    if missing is not None:
        key = "|".join(missing)
        if missing and key != st.get("missing_refs"):
            ntfy(prefix + "model file missing",
                 "Pipelines reference model files that are not on disk:\n- " + "\n- ".join(missing) +
                 "\nProposed fix (not applied): restore the file under /mnt/wopr-ai-models or change "
                 "the reference. Source: " + a.registry + ". Nothing was changed.")
        elif not missing and st.get("missing_refs"):
            ntfy(prefix + "model files OK", "Every referenced model file is on disk again.",
                 "default", "white_check_mark")
        st["missing_refs"] = key
        if stale_h and not st.get("registry_stale"):
            ntfy(prefix + "model registry stale",
                 f"{a.registry} is {stale_h:.0f} h old (cron refreshes it every 6 h). "
                 "Check the nodez3r0 crontab and registry/out/build.log. Nothing was changed.",
                 "default", "warning")
        st["registry_stale"] = bool(stale_h)
        summary.append(f"missing_refs={len(missing)} registry_stale={bool(stale_h)}")
    else:
        summary.append("registry=absent")
    return " ".join(summary)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", action="append", help="name=/path/to/env (replaces the built-in list)")
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--test", action="store_true", help="prefix alert titles with TEST")
    ap.add_argument("--sched-log", default=SCHED_LOG)
    ap.add_argument("--sched-url", default=SCHED)
    ap.add_argument("--registry", default=REGISTRY)
    ap.add_argument("--no-gpu-checks", action="store_true", help="only the original Ollama env check")
    a = ap.parse_args()
    sources = ({n: (p, ENV_LINE) for n, p in (s.split("=", 1) for s in a.source)}
               if a.source else SOURCES)
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
    extra = "" if a.no_gpu_checks else check_gpu_and_registry(a, st, prefix, datetime.now())
    save_state(a.state, st)
    print(datetime.now().strftime("%F %T"), "missing=", len(missing),
          "problem=", problem or "none", extra)


if __name__ == "__main__":
    main()
