#!/usr/bin/env python3
"""
WOPR Universal Support Plane v3.2 - 3-Tier LLM Remediation
==================================
Runs on EVERY host (lighthouse or beacon).
Auto-discovers and monitors ALL local services.
Auto-discovers, monitors, and AUTO-REMEDIATES services.
DEFCON-based alerting: only emails for data-loss scenarios.

Tiers:
  1. Service/container health + auto-restart + proactive memory/disk checks
  2. HTTP endpoint checks (public + backend health)
  3. Log analysis with noise filtering
  4. AI-powered analysis via Ollama (if available)

v3.0 Changes from v2.0:
  - Reads services-manifest.json as source of truth
  - Proactive memory pressure detection (restart before OOM)
  - Proactive disk cleanup
  - Container restart fix (v2 bug at NO_AUTO_RESTART)
  - HEAD->GET fallback for HTTP checks
  - Backend health endpoint monitoring
  - Log noise filtering (SSH brute force, ntfy stats)
  - Tighter OOM regex (word boundary)
  - PostgreSQL FATAL distinction (client rejection vs crash)
  - Service dependency chain awareness (restart root cause first)
  - Certificate expiry checks
  - Zombie/stuck process detection
"""

import subprocess
import json
import logging
import os
import re
import socket
import sys
import time
import urllib.request
import urllib.error
import ssl
from datetime import datetime, timedelta
from pathlib import Path

# ========== CONFIG ==========
VERSION = "4.2-defcon-fix"
HOSTNAME = socket.gethostname()
CHECK_INTERVAL = 300  # 5 min when running as daemon
HEARTBEAT_FILE = "/var/lib/wopr-support-plane-heartbeat"
STATE_FILE = "/var/lib/wopr-support-plane-state.json"
LOG_FILE = "/var/log/wopr-support-plane.log"
EMAIL_COOLDOWN_FILE = "/var/lib/wopr-support-plane-email-cooldown.json"
EMAIL_COOLDOWN_MINUTES = 120

# Alert-suppress targets: matched as substring against endpoint URL OR description.
# Suppresses BOTH remediation and the alert itself (issues.append).
# Restored from support_plane_quirks.md (2026-04-25 / 2026-05-01 / 2026-05-04).
ALERT_SUPPRESS_TARGETS = [
    "127.0.0.1:8600",
    "127.0.0.1:34665",
    "easy-diffusion",
    "comfyui",
    "fooocus",
    "wopr-ai-engine",
]

def _is_suppressed_target(url: str, desc: str = "") -> bool:
    hay = f"{url} {desc}".lower()
    return any(t.lower() in hay for t in ALERT_SUPPRESS_TARGETS)

ALERT_EMAIL = "stephen.falken@wopr.systems"
MANIFEST_FILE = "/opt/wopr/support-plane/services-manifest.json"
KNOWLEDGE_BASE_FILE = "/opt/wopr/support-plane/knowledge-base.json"
MEMORY_STATE_FILE = "/var/lib/wopr-support-plane-memory.json"

# ========== ACTION LOGGING ==========
ACTIONS_LOG_FILE = "/var/lib/wopr-support-plane-actions.json"
ACTIONS_MAX_ENTRIES = 500
SITREP_API_URL = "https://sitrep.wopr.systems/api/sp/actions"
SITREP_API_TOKEN = "wopr-sp-actions-2026"


# Services that should NEVER be auto-restarted
NO_AUTO_RESTART = {
    "sshd", "ssh", "nebula", "systemd-journald", "systemd-logind",
}

# Services to completely ignore - hardware/platform services that do not apply
SERVICE_IGNORE = {
    "alsa-state", "alsa-restore", "alsa-utils",
    "dmesg",
    "open-vm-tools", "vgauth", "vmtoolsd",
    "samba-ad-dc",
    "snap.etcd.etcd", "snap.microk8s.daemon-apiserver-proxy",
    "snap.microk8s.daemon-etcd", "snap.microk8s.daemon-flanneld",
    "sssd", "sssd-kcm",
    "thermald",
    "tpm-udev", "tpm2-abrmd",
    "ubuntu-advantage", "ua-timer", "ua-reboot-required",
    "whoopsie",
}

# Services safe to restart but require care (restart, don't kill)
RESTART_WITH_CARE = {
    "postgresql", "postgres", "mysql", "mariadb", "redis",
    "docker", "containerd", "podman",
}

# Log noise patterns to EXCLUDE from error counting
LOG_NOISE_PATTERNS = [
    r"sshd\[\d+\]:\s*(Failed password|Invalid user|authentication failure|kex_protocol_error|Connection closed by authenticating|Disconnected from authenticating)",
    r"ntfy.*Server stats",
    r"emails_received_failure=\d+.*emails_sent_failure=\d+",
    r"pam_unix\(sshd:auth\):\s*authentication failure",
    r"sshd\[\d+\]:\s*error:\s*kex_protocol_error",
    r"systemd-logind.*Session \d+ logged out",
    r"systemd-logind.*Removed session",
    r"systemd\[1\]:\s*session-\d+\.scope",
    r"authentik.*Task (published|started|finished|SUCCESS)",
    r"authentik.*TenantAwareScheduler",
    r"authentik.*updating brand certificates",
    r"authentik.*outposts/instances",
    r"authentik.*core/brands",
    r"postgresql.*checkpoint (starting|complete)",
    r"postgresql.*LOG:",
    r"celery.*clear_failed_blueprints",
    r"celery.*clean_temporary_users",
    r"celery.*clean_expired_models",
    r"authentik.*unauthenticated",
    r"authentik.*outpost.*goauthentik",
    r"authentik.*auth/caddy",
    r"authentik.*authentication-flow",
    r"authentik.*status.*302",
    r"authentik.*WOPR-Support-Plane",
    r"wopr-authentik-server.*302",
    r"wopr-authentik-server.*unauthenticated",
    r"postgresql.*FATAL.*password authentication failed",
    r"postgresql.*FATAL.*Role.*does not exist",
]
LOG_NOISE_COMPILED = [re.compile(p, re.IGNORECASE) for p in LOG_NOISE_PATTERNS]

# Tighter critical log patterns (word boundaries)
CRITICAL_LOG_PATTERNS = re.compile(
    r"(?i)\b(OOM|out of memory)\b|"
    r"(?<![a-zA-Z])(panic|segfault)(?![a-zA-Z])"
)

# PostgreSQL FATAL that are just client rejections (not crashes)
PG_FATAL_NOISE = re.compile(
    r"(?i)FATAL:\s*(password authentication failed|"
    r"database .+ does not exist|"
    r"no pg_hba.conf entry|"
    r"connection refused|"
    r"role .+ does not exist|"
    r"too many connections|"
    r"the database system is starting up)",
)

# Memory thresholds
CONTAINER_MEM_WARN_PCT = 85   # Restart container before OOM
HOST_MEM_WARN_PCT = 90        # Drop caches + alert
HOST_MEM_CRITICAL_PCT = 95    # Aggressive cleanup

# Disk thresholds
DISK_WARN_PCT = 80
DISK_CRITICAL_PCT = 90


# ========== DEFCON ALERT CLASSIFICATION (v4.2) ==========
# DEFCON-1: EMAIL IMMEDIATELY (bypass cooldown) - data loss imminent
# DEFCON-2: EMAIL (with cooldown) - any service/container/endpoint down, persistent issues
# DEFCON-3: LOG + TRACK - transient issues, auto-escalate to DEFCON-2 after 3 consecutive scans
# DEFCON-4: LOG ONLY - purely informational

DEFCON_1_TYPES = {
    "host_memory_critical",
    "disk_critical",
    "database_crash",
    "data_corruption",
}

DEFCON_2_TYPES = {
    "backend_critical",
    "backend_unhealthy",
    "service_restart_failed",
    "service_down",
    "container_restart_failed",
    "container_down",
    "container_down_protected",
    "container_unhealthy",
    "proactive_restart_failed",
    "http_check_failed",
    "http_server_error",
    "excessive_errors",
    "container_critical_log",
}

# DEFCON-3: Transient - tracked, auto-escalate after 3 consecutive scans
TRANSIENT_TYPES = {
    "memory_growth",
}

# DEFCON-4: Informational only - nothing silently ignored anymore
SILENT_TYPES = set()

# Persistent issue tracking
PERSISTENT_ISSUE_FILE = "/var/lib/wopr-support-plane-persistent.json"
PERSISTENT_ESCALATION_THRESHOLD = 3  # scans (= 15 min at 5-min intervals)

def load_persistent_issues():
    import json
    try:
        if os.path.exists(PERSISTENT_ISSUE_FILE):
            with open(PERSISTENT_ISSUE_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def save_persistent_issues(tracker):
    import json
    try:
        with open(PERSISTENT_ISSUE_FILE, "w") as f:
            json.dump(tracker, f, indent=2)
    except Exception as e:
        log.warning("Failed to save persistent tracker: %s", e)

def classify_with_persistence(all_issues):
    """Classify issues with persistent escalation.
    Returns (defcon1, defcon2, defcon3, defcon4) lists.
    """
    from datetime import datetime
    tracker = load_persistent_issues()
    now = datetime.now().isoformat()

    defcon1, defcon2, defcon3, defcon4 = [], [], [], []
    seen_keys = set()

    for issue in all_issues:
        itype = issue.get("type", "")
        target = issue.get("target", "unknown")
        key = "%s::%s" % (itype, target)
        seen_keys.add(key)

        if itype in DEFCON_1_TYPES:
            defcon1.append(issue)
            continue
        if itype in DEFCON_2_TYPES:
            defcon2.append(issue)
            continue

        # Track consecutive occurrences for everything else
        if key not in tracker:
            tracker[key] = {"count": 1, "first_seen": now, "last_seen": now}
        else:
            tracker[key]["count"] = tracker[key].get("count", 0) + 1
            tracker[key]["last_seen"] = now

        if tracker[key]["count"] >= PERSISTENT_ESCALATION_THRESHOLD:
            issue["_escalated_persistent"] = True
            issue["_persistent_count"] = tracker[key]["count"]
            defcon2.append(issue)
            log.warning("PERSISTENT ESCALATION: %s seen %d consecutive scans -> DEFCON-2",
                       key, tracker[key]["count"])
        else:
            defcon3.append(issue)

    # Clear resolved issues from tracker
    for k in [k for k in tracker if k not in seen_keys]:
        log.info("PERSISTENT: Issue resolved, clearing: %s (was %d scans)", k, tracker[k].get("count", 0))
        del tracker[k]

    save_persistent_issues(tracker)
    return defcon1, defcon2, defcon3, defcon4

# ========== FIX MEMORY (v3.1) ==========
FIX_MEMORY_FILE = "/var/lib/wopr-support-plane-fix-memory.json"
FIX_MEMORY_MAX = 200
FIX_COOLDOWN_MINUTES = 30

def load_fix_memory():
    try:
        if os.path.exists(FIX_MEMORY_FILE):
            with open(FIX_MEMORY_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {"fixes": [], "stats": {"total_attempted": 0, "total_success": 0, "total_failed": 0}}

def save_fix_memory(mem):
    try:
        if len(mem.get("fixes", [])) > FIX_MEMORY_MAX:
            mem["fixes"] = mem["fixes"][-FIX_MEMORY_MAX:]
        with open(FIX_MEMORY_FILE, "w") as f:
            json.dump(mem, f, indent=2)
    except Exception as e:
        log.warning("Failed to save fix memory: %s", e)

def record_fix(target, issue_type, fix_action, result, detail=""):
    mem = load_fix_memory()
    entry = {
        "ts": datetime.now().isoformat(),
        "target": target,
        "issue": issue_type,
        "fix": fix_action,
        "result": result,
        "detail": detail[:300],
    }
    mem["fixes"].append(entry)
    mem["stats"]["total_attempted"] = mem["stats"].get("total_attempted", 0) + 1
    if result == "success":
        mem["stats"]["total_success"] = mem["stats"].get("total_success", 0) + 1
    else:
        mem["stats"]["total_failed"] = mem["stats"].get("total_failed", 0) + 1
    save_fix_memory(mem)
    log.info("FIX MEMORY: [%s] %s on %s -> %s", issue_type, fix_action, target, result)

def should_attempt_fix(target, issue_type):
    mem = load_fix_memory()
    now = datetime.now()
    for fix in reversed(mem.get("fixes", [])):
        if fix["target"] == target and fix["issue"] == issue_type:
            try:
                fix_time = datetime.fromisoformat(fix["ts"])
                if (now - fix_time).total_seconds() < FIX_COOLDOWN_MINUTES * 60:
                    if fix["result"] == "failed":
                        log.info("FIX MEMORY: Skipping %s on %s - same fix failed recently", issue_type, target)
                        return False
                    return True
            except Exception:
                pass
            break
    return True




# ========== AUTO-LEARNING REMEDIATION MEMORY (v3.1) ==========
LEARNED_FIXES_FILE = "/var/lib/wopr-support-plane-learned-fixes.json"
LEARNED_FIXES_MAX = 500
LEARNED_FAILED_MAX = 200
KB_SYNC_INTERVAL = 3600  # 1 hour
_last_kb_sync = 0


def load_learned_fixes():
    """Load the learned fixes database."""
    try:
        if os.path.exists(LEARNED_FIXES_FILE):
            with open(LEARNED_FIXES_FILE) as f:
                data = json.load(f)
                if "version" in data:
                    return data
    except Exception:
        pass
    return {
        "version": "1.0",
        "last_updated": None,
        "fixes": [],
        "failed_approaches": [],
    }


def save_learned_fixes(db):
    """Save the learned fixes database with size limits."""
    db["last_updated"] = datetime.now().isoformat()
    if len(db.get("fixes", [])) > LEARNED_FIXES_MAX:
        db["fixes"] = db["fixes"][-LEARNED_FIXES_MAX:]
    if len(db.get("failed_approaches", [])) > LEARNED_FAILED_MAX:
        db["failed_approaches"] = db["failed_approaches"][-LEARNED_FAILED_MAX:]
    try:
        with open(LEARNED_FIXES_FILE, "w") as f:
            json.dump(db, f, indent=2)
    except Exception as e:
        log.warning("LEARNED: Failed to save learned fixes: %s", e)


def save_learned_fix(issue_key, prev_state):
    """v4.0: Save a learned fix only if we have strong evidence it worked.
    Requires: actual command was run (not just observed resolution), and it passed verification."""
    history = prev_state.get("history", [])
    if not history:
        log.info("LEARNED: No history for %s - not saving (transient resolution)", issue_key[:40])
        return

    # Find the last non-blocked command that was actually executed
    last_cmd = None
    last_model = None
    for entry in reversed(history):
        cmd = entry.get("command", "")
        result = entry.get("result", "")
        if cmd and "BLOCKED" not in result and "failed" not in result.lower():
            last_cmd = cmd
            last_model = entry.get("model", "unknown")
            break

    if not last_cmd:
        log.info("LEARNED: No successful command in history for %s - not saving", issue_key[:40])
        return

    # v4.0: Don't learn from deterministic fixes (they're already hardcoded)
    if last_model == "deterministic-v4":
        return

    # v4.0: Check if this is a garbage fix before saving
    if _is_garbage_fix(issue_key, last_cmd):
        log.info("LEARNED: Rejecting garbage fix for %s: %s", issue_key[:40], last_cmd[:80])
        return

    db = load_learned_fixes()
    fixes = db.get("fixes", [])

    # Check for duplicates
    for fix in fixes:
        if fix["issue_key"] == issue_key and fix["fix_command"] == last_cmd:
            fix["success_count"] = min(fix["success_count"] + 1, 10)
            fix["last_used"] = datetime.now().isoformat()
            save_learned_fixes(db)
            log.info("LEARNED: Updated existing fix for %s (count=%d)", issue_key[:40], fix["success_count"])
            return

    # v4.0: Require the fix to have been verified, not just "issue went away"
    # Only save if the last history entry shows actual execution + verification
    last_entry = history[-1] if history else {}
    if "Learned fix failed" in last_entry.get("result", "") or "BLOCKED" in last_entry.get("result", ""):
        log.info("LEARNED: Last action was failure/blocked for %s - not saving", issue_key[:40])
        return

    new_fix = {
        "id": "LF-%03d" % (len(fixes) + 1),
        "issue_key": issue_key,
        "issue_type": issue_key.split("::")[0] if "::" in issue_key else "unknown",
        "target": issue_key.split("::")[-1] if "::" in issue_key else issue_key,
        "detail_pattern": "",
        "fix_command": last_cmd,
        "fix_explanation": "",
        "source_model": last_model,
        "source_tier": prev_state.get("tier", 1),
        "first_seen": datetime.now().isoformat(),
        "last_used": datetime.now().isoformat(),
        "success_count": 1,
        "fail_count": 0,
        "host": HOSTNAME,
        "auto_learned": True,
    }
    fixes.append(new_fix)
    db["fixes"] = fixes
    db["last_updated"] = datetime.now().isoformat()
    save_learned_fixes(db)
    log.info("LEARNED: Saved new fix for %s: %s (model=%s)", issue_key[:40], last_cmd[:80], last_model)
    log_action("learned_fix_saved", issue_key, "Auto-learned fix: " + last_cmd[:80], "success", "Model: " + last_model)


def save_failed_approach(issue_key, command, reason):
    """Save a failed remediation approach so we never repeat it."""
    db = load_learned_fixes()

    # Check if already recorded
    for fa in db.get("failed_approaches", []):
        if fa["issue_key"] == issue_key and fa["command"] == command:
            return  # Already known

    db.setdefault("failed_approaches", []).append({
        "issue_key": issue_key,
        "command": command[:500],
        "reason": reason[:300],
        "timestamp": datetime.now().isoformat(),
        "host": HOSTNAME,
    })
    save_learned_fixes(db)
    log.info("LEARNED: Saved failed approach for %s: %s", issue_key[:40], command[:60])


def get_failed_approaches(issue_key):
    """Get list of commands that already failed for this issue."""
    db = load_learned_fixes()
    failed = []
    for fa in db.get("failed_approaches", []):
        if fa["issue_key"] == issue_key:
            failed.append(fa["command"])
    return failed



def _is_garbage_fix(issue_key, command):
    """v4.0: Expanded garbage detection. Returns True if the command is obviously wrong."""
    if not command:
        return True
    cmd_lower = command.lower().strip()

    # Diagnostic commands are NOT fixes
    if any(diag in cmd_lower for diag in [
        "curl ", "wget ", "cat ", "ls ", "ps ", "df ", "du ",
        "pg_isready", "docker logs", "podman logs", "systemctl status",
        "docker inspect", "docker ps", "top ", "free ",
    ]):
        return True

    # Restarting unrelated services (the whisper-for-everything problem)
    # If the issue target doesn't match the service being restarted, it's garbage
    issue_target = issue_key.split("::")[-1] if "::" in issue_key else ""
    restart_match = re.search(r"(?:systemctl restart|docker restart|podman restart)\s+(\S+)", cmd_lower)
    if restart_match:
        restarted = restart_match.group(1)
        # Restarting whisper/tunnel services for non-whisper issues = garbage
        if "whisper" in restarted and "whisper" not in issue_target.lower():
            return True
        if "tunnel" in restarted and "tunnel" not in issue_target.lower():
            # ai-tunnel services are SSH tunnels - restarting them only makes sense
            # if the issue is about the specific service they tunnel to
            tunnel_service = restarted.replace("ai-tunnel-", "")
            if tunnel_service not in issue_target.lower():
                return True

    # Restarting reverse proxies for backend issues
    if any(proxy in cmd_lower for proxy in [
        "restart caddy", "restart nginx", "restart apache", "restart httpd",
        "restart haproxy", "restart traefik",
    ]):
        if "caddy" not in issue_target.lower() and "proxy" not in issue_target.lower():
            return True

    # VACUUM/REINDEX for disk issues = garbage
    if any(db_cmd in cmd_lower for db_cmd in ["vacuum", "reindex", "analyze"]):
        if "disk" in issue_key.lower():
            return True

    # podman on a docker host = garbage
    if "podman" in cmd_lower:
        runtime = _container_runtime()
        if runtime and "podman" not in runtime:
            return True

    # docker exec with -it (needs TTY, will always fail in automation)
    if "docker exec -it" in cmd_lower or "podman exec -it" in cmd_lower:
        return True

    return False


def _verify_fix_worked(issue):
    """After running a fix, verify the original issue is actually resolved."""
    itype = issue.get("type", "")
    target = issue.get("target", "")
    if itype in ("http_check_failed", "backend_unhealthy"):
        url = issue.get("detail", "") or target
        if not url.startswith("http"):
            url = "https://" + url
        try:
            import urllib.request, ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, method="HEAD")
            req.add_header("User-Agent", "WOPR-SP-Verify/1.0")
            resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            code = resp.getcode()
            if code < 500:
                log.info("VERIFY: %s returned %d - FIXED", url[:60], code)
                return True
            log.info("VERIFY: %s returned %d - NOT FIXED", url[:60], code)
            return False
        except Exception as e:
            log.info("VERIFY: %s still failing: %s", url[:60], str(e)[:80])
            return False
    elif itype in ("container_down", "container_unhealthy"):
        rt = _container_runtime()
        if rt:
            try:
                r = subprocess.run(
                    [rt, "inspect", "--format", "{{.State.Running}}", target],
                    capture_output=True, text=True, timeout=10)
                if "true" in r.stdout.lower():
                    return True
            except Exception:
                pass
        return False
    elif itype == "service_down":
        try:
            r = subprocess.run(
                ["systemctl", "is-active", target],
                capture_output=True, text=True, timeout=10)
            if r.stdout.strip() == "active":
                return True
        except Exception:
            pass
        return False
    return True


def try_learned_fix(issue, state):
    """Try a previously learned fix before going to LLM.

    Returns: (tried, success, command) - tried=True if we attempted a fix
    """
    key = _issue_key(issue)
    db = load_learned_fixes()

    if not db.get("fixes"):
        return False, False, ""

    # 1. Exact issue_key match (highest priority)
    best_fix = None
    best_score = 0

    for fix in db["fixes"]:
        score = 0
        if fix["issue_key"] == key:
            score = 100  # Exact match
        elif fix["issue_type"] == issue.get("type", ""):
            # Same issue type - partial match
            score = 30
            # Bonus for same target
            if fix["target"] == issue.get("target", ""):
                score += 40
            # Bonus for keyword overlap in detail
            fix_words = set(fix.get("detail_pattern", "").lower().split())
            issue_words = set(issue.get("detail", "").lower().split())
            overlap = len(fix_words & issue_words)
            if overlap >= 2:
                score += 20

        # Must have good track record
        sc = fix.get("success_count", 0)
        fc = fix.get("fail_count", 0)
        if sc < 2:
            score = min(score, 50)  # Not proven enough for auto-apply unless exact match
        if fc >= sc and sc > 0:
            score = 0  # Fix has become unreliable

        if score > best_score:
            best_score = score
            best_fix = fix

    if not best_fix or best_score < 80:
        return False, False, ""

    cmd = best_fix["fix_command"]
    sc = best_fix.get("success_count", 0)
    fc = best_fix.get("fail_count", 0)

    # Safety check
    safe, reason = is_command_safe(cmd)
    if not safe:
        log.warning("LEARNED FIX: Blocked unsafe learned command: %s (%s)", cmd[:60], reason)
        return False, False, ""

    # Check fix memory cooldown
    if not should_attempt_fix(issue.get("target", ""), issue.get("type", "")):
        log.info("LEARNED FIX: Skipping %s - cooldown active", key[:40])
        return False, False, ""

    log.info("LEARNED FIX: Trying known fix for %s: %s (success rate: %d/%d)",
             key[:40], cmd[:80], sc, sc + fc)

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        exec_output = (result.stdout + result.stderr)[:300]

        if result.returncode == 0:
            log.info("LEARNED FIX: Command ran (rc=0), verifying actual fix...")
            import time as _vtime
            _vtime.sleep(5)
            verified = _verify_fix_worked(issue)
            if verified:
                new_sc = min(sc + 1, 10)
                best_fix["success_count"] = new_sc
                best_fix["last_used"] = datetime.now().isoformat()
                save_learned_fixes(db)
                record_fix(issue.get("target", "?"), "learned_fix",
                           cmd[:200], "success",
                           "VERIFIED fix (rate: %d/%d)" % (new_sc, new_sc + fc + 1))
                log_action("learned_fix_applied", issue.get("target", "?"),
                           "Applied known fix: %s" % cmd[:80],
                           "success",
                           "VERIFIED rate=%d/%d" % (new_sc, new_sc + fc + 1))
                return True, True, cmd
            else:
                log.warning("LEARNED FIX: rc=0 but issue NOT resolved: %s", cmd[:60])
                best_fix["fail_count"] = fc + 1
                best_fix["last_used"] = datetime.now().isoformat()
                save_learned_fixes(db)
                record_fix(issue.get("target", "?"), "learned_fix",
                           cmd[:200], "failed",
                           "rc=0 but verification failed")
                return True, False, cmd
        else:
            log.warning("LEARNED FIX: Command failed (rc=%d): %s", result.returncode, exec_output[:100])
            best_fix["fail_count"] = fc + 1
            best_fix["last_used"] = datetime.now().isoformat()
            save_learned_fixes(db)
            record_fix(issue.get("target", "?"), "learned_fix",
                       cmd[:200], "failed",
                       "rc=%d output=%s" % (result.returncode, exec_output[:100]))
            return True, False, cmd

    except subprocess.TimeoutExpired:
        log.warning("LEARNED FIX: Command timed out: %s", cmd[:60])
        best_fix["fail_count"] = fc + 1
        save_learned_fixes(db)
        return True, False, cmd
    except Exception as e:
        log.warning("LEARNED FIX: Execution error: %s", e)
        return True, False, cmd


def sync_learned_to_kb():
    """Sync proven learned fixes to the knowledge base (runs hourly)."""
    global _last_kb_sync
    now = time.time()
    if now - _last_kb_sync < KB_SYNC_INTERVAL:
        return
    _last_kb_sync = now

    db = load_learned_fixes()
    proven_fixes = [f for f in db.get("fixes", [])
                    if f.get("success_count", 0) >= 3
                    and f.get("fail_count", 0) < f.get("success_count", 0)]

    if not proven_fixes:
        return

    kb = load_knowledge_base()
    if not kb:
        return

    # Collect all existing KB patterns for dedup
    existing_patterns = set()
    for category in kb:
        if isinstance(kb[category], list):
            for entry in kb[category]:
                if isinstance(entry, dict) and "pattern" in entry:
                    existing_patterns.add(entry["pattern"].lower())

    # Find existing AUTO-NNN IDs
    max_auto_id = 0
    for category in kb:
        if isinstance(kb[category], list):
            for entry in kb[category]:
                if isinstance(entry, dict):
                    eid = entry.get("id", "")
                    if eid.startswith("AUTO-"):
                        try:
                            num = int(eid.split("-")[1])
                            max_auto_id = max(max_auto_id, num)
                        except (ValueError, IndexError):
                            pass

    added = 0
    for fix in proven_fixes:
        pattern = "%s on %s" % (fix.get("issue_type", ""), fix.get("target", ""))
        if pattern.lower() in existing_patterns:
            continue

        max_auto_id += 1
        new_entry = {
            "id": "AUTO-%03d" % max_auto_id,
            "pattern": pattern,
            "host": fix.get("host", HOSTNAME),
            "root_cause": fix.get("fix_explanation", "Auto-discovered by support plane"),
            "fix": fix.get("fix_command", ""),
            "notes": "Auto-learned by support plane. Success rate: %d/%d. First seen: %s" % (
                fix.get("success_count", 0),
                fix.get("success_count", 0) + fix.get("fail_count", 0),
                fix.get("first_seen", "unknown"),
            ),
        }

        # Add to appropriate category based on issue_type
        itype = fix.get("issue_type", "")
        if "service" in itype:
            kb.setdefault("service_issues", []).append(new_entry)
        elif "container" in itype:
            kb.setdefault("container_issues", []).append(new_entry)
        elif "http" in itype:
            kb.setdefault("http_issues", []).append(new_entry)
        elif "auth" in itype:
            kb.setdefault("auth_issues", []).append(new_entry)
        else:
            kb.setdefault("infrastructure_issues", []).append(new_entry)

        existing_patterns.add(pattern.lower())
        added += 1

    if added > 0:
        kb.setdefault("_meta", {})["updated"] = datetime.now().strftime("%Y-%m-%d")
        kb["_meta"]["auto_synced"] = datetime.now().isoformat()
        try:
            with open(KNOWLEDGE_BASE_FILE, "w") as f:
                json.dump(kb, f, indent=2)
            log.info("LEARNED->KB: Synced %d proven fixes to knowledge base", added)
            log_action("kb_auto_sync", "knowledge-base",
                       "Synced %d proven learned fixes" % added,
                       "success", "Total proven: %d" % len(proven_fixes))
        except Exception as e:
            log.warning("LEARNED->KB: Failed to write KB: %s", e)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("wopr-sp")

# SSL context that doesn't verify (for internal checks)
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# Track Ollama availability to avoid spamming
_ollama_available = None
_ollama_checked_at = 0


# ========== MANIFEST ==========
def load_manifest():
    """Load services manifest. Returns empty dict if not found."""
    try:
        if os.path.exists(MANIFEST_FILE):
            with open(MANIFEST_FILE) as f:
                return json.load(f)
    except Exception as e:
        log.warning("Failed to load manifest: %s", e)
    return {}


# ========== HEARTBEAT ==========
def write_heartbeat():
    """Write heartbeat file so watchdog knows we're alive."""
    try:
        with open(HEARTBEAT_FILE, "w") as f:
            f.write(json.dumps({
                "ts": datetime.now().isoformat(),
                "hostname": HOSTNAME,
                "pid": os.getpid(),
                "version": VERSION,
            }))
    except Exception as e:
        log.error("Failed to write heartbeat: %s", e)


# ========== EMAIL ==========
def send_alert(subject, body):
    """Send alert email via local Postfix/sendmail."""
    issue_key = re.sub(r"[^a-zA-Z0-9]", "_", subject)[:80]
    # Collapse issue-count variants so cooldown matches across e.g. _1_issue_s_ vs _8_issue_s_
    issue_key = re.sub(r"_\d+_issue_s_", "_N_issue_s_", issue_key)
    if not _should_send(issue_key):
        log.info("Email suppressed (cooldown): %s", subject)
        return
    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(body)
        msg["Subject"] = "[WOPR-SP %s] %s" % (HOSTNAME, subject)
        msg["From"] = "support-plane@wopr.systems"
        msg["To"] = ALERT_EMAIL
        with smtplib.SMTP("localhost", 25, timeout=10) as s:
            s.send_message(msg)
        log.info("Alert email sent: %s", subject)
    except Exception as e:
        log.warning("Email failed (non-fatal): %s", e)


def _should_send(key):
    cooldown = {}
    try:
        if os.path.exists(EMAIL_COOLDOWN_FILE):
            with open(EMAIL_COOLDOWN_FILE) as f:
                cooldown = json.load(f)
    except Exception:
        pass
    last = cooldown.get(key)
    if last:
        try:
            if datetime.now() - datetime.fromisoformat(last) < timedelta(minutes=EMAIL_COOLDOWN_MINUTES):
                return False
        except Exception:
            pass
    cooldown[key] = datetime.now().isoformat()
    try:
        with open(EMAIL_COOLDOWN_FILE, "w") as f:
            json.dump(cooldown, f)
    except Exception:
        pass
    return True


# ========== CONTAINER RUNTIME ==========
def _container_runtime():
    """Detect whether docker or podman is available."""
    for cmd in ("docker", "podman"):
        try:
            subprocess.run([cmd, "version"], capture_output=True, timeout=5)
            return cmd
        except Exception:
            continue
    return None


# ========== DEPENDENCY CHAIN ==========
def get_dependency_order(manifest):
    """Return containers sorted by dependency (root causes first)."""
    containers = manifest.get("containers", [])
    # Build dependency map
    dep_map = {}
    for c in containers:
        dep_map[c["name"]] = c.get("depends_on", [])

    # Topological sort - dependencies first
    visited = set()
    order = []

    def visit(name):
        if name in visited:
            return
        visited.add(name)
        for dep in dep_map.get(name, []):
            visit(dep)
        order.append(name)

    for c in containers:
        visit(c["name"])
    return order


# ========== TIER 1: SERVICE & CONTAINER HEALTH ==========
def discover_wopr_services():
    """Auto-discover all wopr-* systemd services + manifest services (v4.1)."""
    try:
        r = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"],
            capture_output=True, text=True, timeout=15,
        )
        services = []
        seen_names = set()
        for line in r.stdout.strip().split("\n"):
            parts = line.split()
            if not parts:
                continue
            name = parts[0].replace(".service", "")
            if any(name.startswith(p) for p in ("wopr-", "caddy", "nebula", "authentik", "oauth2-proxy")):
                loaded = parts[1] if len(parts) > 1 else "unknown"
                active = parts[2] if len(parts) > 2 else "unknown"
                sub = parts[3] if len(parts) > 3 else "unknown"
                if loaded == "not-found":
                    continue
                services.append({"name": name, "active": active, "sub": sub})
                seen_names.add(name)

        # v4.1: Also include services from manifest that were NOT discovered by prefix
        try:
            manifest = load_manifest()
            for msvc in manifest.get("services", []):
                mname = msvc.get("name", "")
                if mname and mname not in seen_names and msvc.get("type") == "systemd":
                    check = subprocess.run(
                        ["systemctl", "is-active", mname],
                        capture_output=True, text=True, timeout=10,
                    )
                    active = check.stdout.strip() or "unknown"
                    sub_check = subprocess.run(
                        ["systemctl", "show", mname, "--property=SubState", "--value"],
                        capture_output=True, text=True, timeout=10,
                    )
                    sub = sub_check.stdout.strip() or "unknown"
                    unit_check = subprocess.run(
                        ["systemctl", "cat", mname],
                        capture_output=True, text=True, timeout=10,
                    )
                    if unit_check.returncode == 0:
                        services.append({"name": mname, "active": active, "sub": sub})
                        seen_names.add(mname)
        except Exception as e:
            log.warning("Manifest service discovery failed: %s", e)

        return services
    except Exception as e:
        log.error("Service discovery failed: %s", e)
        return []


def discover_containers():
    """Auto-discover all containers (docker or podman)."""
    runtime = _container_runtime()
    if not runtime:
        log.info("T1: No container runtime (docker/podman) found")
        return []
    try:
        r = subprocess.run(
            [runtime, "ps", "-a", "--format", "{{.Names}}\t{{.Status}}\t{{.Image}}"],
            capture_output=True, text=True, timeout=15,
        )
        containers = []
        for line in r.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            name = parts[0] if len(parts) > 0 else "?"
            status = parts[1] if len(parts) > 1 else "?"
            image = parts[2] if len(parts) > 2 else "?"
            running = "Up" in status
            healthy = "(healthy)" in status or "(unhealthy)" not in status
            containers.append({
                "name": name,
                "status": status,
                "image": image,
                "running": running,
                "healthy": healthy,
            })
        return containers
    except Exception as e:
        log.error("Container discovery failed: %s", e)
        return []


def tier1_check_services():
    """Check all discovered services, auto-restart failed ones."""
    issues = []
    services = discover_wopr_services()
    manifest = load_manifest()
    manifest_services = {s["name"]: s for s in manifest.get("services", [])}
    log.info("T1: Discovered %d services", len(services))

    for svc in services:
        if svc["active"] == "failed" or (svc["active"] == "inactive" and svc["sub"] == "dead"):
            # Check if it's timer-activated
            timer_check = subprocess.run(
                ["systemctl", "is-enabled", "%s.timer" % svc["name"]],
                capture_output=True, text=True,
            )
            if timer_check.stdout.strip() == "enabled":
                continue

            # Check if it's supposed to be enabled
            enabled_check = subprocess.run(
                ["systemctl", "is-enabled", svc["name"]],
                capture_output=True, text=True,
            )
            if enabled_check.stdout.strip() not in ("enabled", "static"):
                continue

            svc_base = svc["name"].replace("wopr-", "").split("@")[0].lower()

            # Skip services in the ignore list (hardware/platform that don't apply)
            if svc["name"] in SERVICE_IGNORE or svc_base in SERVICE_IGNORE:
                continue

            # Check manifest for protected status
            m_svc = manifest_services.get(svc["name"], {})
            if m_svc.get("protected", False):
                log.info("T1: %s is DOWN but marked protected in manifest - skipping", svc["name"])
                continue

            if any(n in svc_base for n in NO_AUTO_RESTART):
                log.warning("T1: %s is DOWN but in no-auto-restart list", svc["name"])
                issues.append({
                    "tier": 1, "type": "service_down", "target": svc["name"],
                    "detail": "Status: %s/%s - NOT auto-restarting (protected)" % (svc["active"], svc["sub"]),
                })
                continue

            log.warning("T1: %s is DOWN (%s/%s) - restarting", svc["name"], svc["active"], svc["sub"])
            restart = subprocess.run(
                ["systemctl", "restart", svc["name"]],
                capture_output=True, text=True, timeout=30,
            )
            if restart.returncode == 0:
                log.info("T1: %s restarted OK", svc["name"])
                log_action("service_restart", svc["name"], "Service was %s/%s" % (svc["active"], svc["sub"]), "success", "systemctl restart completed OK")
                time.sleep(3)
                verify = subprocess.run(
                    ["systemctl", "is-active", svc["name"]],
                    capture_output=True, text=True,
                )
                if verify.stdout.strip() != "active":
                    log_action("service_restart", svc["name"], "Service was %s/%s" % (svc["active"], svc["sub"]), "failed", "Restarted but went back down after 3s")
                    issues.append({
                        "tier": 1, "type": "service_restart_failed", "target": svc["name"],
                        "detail": "Restarted but went back down",
                    })
            else:
                log_action("service_restart", svc["name"], "Service was %s/%s" % (svc["active"], svc["sub"]), "failed", restart.stderr[:200])
                issues.append({
                    "tier": 1, "type": "service_restart_failed", "target": svc["name"],
                    "detail": restart.stderr[:300],
                })

    return issues


def tier1_check_containers():
    """Check all containers, restart stopped/unhealthy ones. Respects dependency order."""
    issues = []
    runtime = _container_runtime()
    if not runtime:
        return issues

    containers = discover_containers()
    manifest = load_manifest()
    manifest_containers = {c["name"]: c for c in manifest.get("containers", [])}
    dep_order = get_dependency_order(manifest)
    log.info("T1: Discovered %d containers (%s)", len(containers), runtime)

    # Build lookup
    container_map = {c["name"]: c for c in containers}

    # Process in dependency order (root cause services first)
    names_to_check = dep_order if dep_order else [c["name"] for c in containers]
    # Also add any containers not in manifest
    for c in containers:
        if c["name"] not in names_to_check:
            names_to_check.append(c["name"])

    restarted_groups = set()  # Track restart groups to avoid double-restarts

    for name in names_to_check:
        c = container_map.get(name)
        if not c:
            continue

        m_ctr = manifest_containers.get(name, {})

        if not c["running"]:
            # Check if this container is in a restart group that was already handled
            restart_group = m_ctr.get("restart_group", [])
            group_key = tuple(sorted(restart_group)) if restart_group else (name,)
            if group_key in restarted_groups:
                continue

            if m_ctr.get("protected", False):
                log.info("T1: Container %s is DOWN but marked protected - skipping", name)
                continue

            # Check NO_AUTO_RESTART only for truly dangerous restarts
            cname_lower = name.lower()
            if any(n in cname_lower for n in NO_AUTO_RESTART):
                issues.append({
                    "tier": 1, "type": "container_down_protected", "target": name,
                    "detail": "Image: %s - in no-auto-restart list" % c["image"],
                })
                continue

            # Restart the container (or the whole restart group)
            targets = restart_group if restart_group else [name]
            log.warning("T1: Container %s is DOWN - restarting %s", name, targets)

            for t in targets:
                restart = subprocess.run(
                    [runtime, "restart", t],
                    capture_output=True, text=True, timeout=120,
                )
                if restart.returncode == 0:
                    log.info("T1: Container %s restarted OK", t)
                    log_action("container_restart", t, "Container was DOWN (not running)", "success", "Restart completed OK via %s" % runtime)
                else:
                    log_action("container_restart", t, "Container was DOWN (not running)", "failed", restart.stderr[:200])
                    issues.append({
                        "tier": 1, "type": "container_restart_failed", "target": t,
                        "detail": "restart failed: %s" % restart.stderr[:200],
                    })

            restarted_groups.add(group_key)

            # Verify after restart
            time.sleep(5)
            verify = subprocess.run(
                [runtime, "ps", "--filter", "name=%s" % name, "--format", "{{.Status}}"],
                capture_output=True, text=True, timeout=10,
            )
            if "Up" not in verify.stdout:
                log_action("container_restart", name, "Container was DOWN (not running)", "failed", "Restarted but not running after 5s verification")
                issues.append({
                    "tier": 1, "type": "container_restart_failed", "target": name,
                    "detail": "Restarted but not running after 5s",
                })

        elif not c["healthy"]:
            issues.append({
                "tier": 1, "type": "container_unhealthy", "target": name,
                "detail": "Status: %s" % c["status"],
            })

    # Check manifest for containers that SHOULD exist but don't
    for mname, mctr in manifest_containers.items():
        if mname not in container_map and mctr.get("expected_state") == "running":
            log.warning("T1: Manifest expects container %s but it doesn't exist", mname)
            issues.append({
                "tier": 1, "type": "container_missing", "target": mname,
                "detail": "Expected in manifest but not found on system",
            })

    return issues


# ========== PROACTIVE: MEMORY PRESSURE ==========
def proactive_memory_check():
    """Check container and host memory BEFORE things OOM."""
    issues = []
    runtime = _container_runtime()

    # Host memory check
    try:
        with open("/proc/meminfo") as f:
            meminfo = f.read()
        total = int([l for l in meminfo.split("\n") if l.startswith("MemTotal")][0].split()[1])
        available = int([l for l in meminfo.split("\n") if l.startswith("MemAvailable")][0].split()[1])
        used_pct = int(100 * (total - available) / total)

        if used_pct >= HOST_MEM_CRITICAL_PCT:
            log.warning("PROACTIVE: Host memory CRITICAL at %d%% - dropping caches", used_pct)
            subprocess.run(["bash", "-c", "sync && echo 3 > /proc/sys/vm/drop_caches"],
                           timeout=10, capture_output=True)
            log_action("cache_drop", "system", "Host memory at %d%%" % used_pct, "success", "Dropped all caches (echo 3)")
            issues.append({
                "tier": 1, "type": "host_memory_critical", "target": "system",
                "detail": "%d%% memory used (%dMB available) - caches dropped" % (used_pct, available // 1024),
            })
        elif used_pct >= HOST_MEM_WARN_PCT:
            log.warning("PROACTIVE: Host memory high at %d%%", used_pct)
            subprocess.run(["bash", "-c", "sync && echo 1 > /proc/sys/vm/drop_caches"],
                           timeout=10, capture_output=True)
            log_action("cache_drop", "system", "Host memory at %d%%" % used_pct, "success", "Dropped page cache (echo 1)")
    except Exception as e:
        log.warning("Memory check failed: %s", e)

    # Container memory check
    if not runtime:
        return issues
    try:
        r = subprocess.run(
            [runtime, "stats", "--no-stream", "--format",
             "{{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}"],
            capture_output=True, text=True, timeout=30,
        )
        prev_state = _load_memory_state()
        new_state = {}

        for line in r.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            name = parts[0].strip()
            mem_usage = parts[1].strip()
            mem_pct_str = parts[2].strip().replace("%", "")
            try:
                mem_pct = float(mem_pct_str)
            except ValueError:
                continue

            new_state[name] = {"pct": mem_pct, "usage": mem_usage}

            # Check for containers approaching their memory limit
            if mem_pct >= CONTAINER_MEM_WARN_PCT:
                log.warning("PROACTIVE: Container %s at %.1f%% memory (%s) - restarting BEFORE OOM",
                            name, mem_pct, mem_usage)
                restart = subprocess.run(
                    [runtime, "restart", name],
                    capture_output=True, text=True, timeout=120,
                )
                if restart.returncode == 0:
                    log.info("PROACTIVE: Container %s restarted (was at %.1f%% mem)", name, mem_pct)
                    log_action("container_restart", name, "Memory at %.1f%% - preemptive OOM prevention" % mem_pct, "success", "Restarted before OOM at %s" % mem_usage)
                else:
                    log_action("container_restart", name, "Memory at %.1f%% - preemptive OOM prevention" % mem_pct, "failed", restart.stderr[:200])
                    issues.append({
                        "tier": 1, "type": "proactive_restart_failed", "target": name,
                        "detail": "At %.1f%% memory, restart failed: %s" % (mem_pct, restart.stderr[:200]),
                    })

            # Check for rapid memory growth
            prev = prev_state.get(name, {})
            prev_pct = prev.get("pct", 0)
            if prev_pct > 0 and mem_pct > prev_pct * 1.5 and mem_pct > 30:
                log.warning("PROACTIVE: Container %s memory grew %.0f%% -> %.0f%% since last scan",
                            name, prev_pct, mem_pct)
                issues.append({
                    "tier": 1, "type": "memory_growth", "target": name,
                    "detail": "Memory grew from %.1f%% to %.1f%% (%s)" % (prev_pct, mem_pct, mem_usage),
                })

        _save_memory_state(new_state)
    except Exception as e:
        log.warning("Container memory check failed: %s", e)

    return issues


def _load_memory_state():
    try:
        if os.path.exists(MEMORY_STATE_FILE):
            with open(MEMORY_STATE_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {}




# ========== ACTION LOGGING ==========
def log_action(action_type, target, reason, result, detail=""):
    # Log a remediation action to the structured action log and report to SITREP.
    entry = {
        "ts": datetime.now().isoformat(),
        "host": HOSTNAME,
        "action": action_type,
        "target": target,
        "reason": reason,
        "result": result,
        "detail": detail[:500],
    }

    # Write to local action log
    try:
        actions = []
        if os.path.exists(ACTIONS_LOG_FILE):
            with open(ACTIONS_LOG_FILE) as f:
                data = json.load(f)
                actions = data.get("actions", [])
        actions.append(entry)
        if len(actions) > ACTIONS_MAX_ENTRIES:
            actions = actions[-ACTIONS_MAX_ENTRIES:]
        with open(ACTIONS_LOG_FILE, "w") as f:
            json.dump({"actions": actions, "last_updated": datetime.now().isoformat()}, f, indent=2)
    except Exception as e:
        log.warning("Failed to write action log: %%s", e)

    # Report to SITREP API (best effort, non-blocking)
    try:
        data = json.dumps(entry).encode()
        req = urllib.request.Request(SITREP_API_URL, data=data)
        req.add_header("Content-Type", "application/json")
        req.add_header("X-WOPR-Token", SITREP_API_TOKEN)
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass  # Non-critical

    log.info("ACTION: [%s] %s on %s - %s (%s)", action_type, reason, target, result, detail[:100])


def _save_memory_state(state):
    try:
        with open(MEMORY_STATE_FILE, "w") as f:
            json.dump(state, f)
    except Exception:
        pass


# ========== PROACTIVE: DISK SPACE (v4.0 - smart analysis) ==========
def proactive_disk_check():
    """Check disk space with SMART analysis - identifies actual hogs and takes targeted action."""
    issues = []
    # DEDUP: track seen devices to avoid alerting N times for same filesystem
    seen_devices = set()
    try:
        r = subprocess.run(
            ["df", "-h", "--output=pcent,target,source"],
            capture_output=True, text=True, timeout=10,
        )
        for line in r.stdout.strip().split("\n")[1:]:
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                pct = int(parts[0].replace("%", ""))
            except ValueError:
                continue
            mount = parts[1]
            source = parts[2] if len(parts) > 2 else ""
            # Skip virtual/pseudo filesystems
            if source in ("tmpfs", "devtmpfs", "nsfs", "overlay") or source.startswith("squashfs"):
                continue
            # Dedup: only alert once per underlying device/source
            if source and source in seen_devices:
                continue
            if source:
                seen_devices.add(source)

            if "overlay2" in mount or mount.startswith("overlay") or "/merged" in mount:
                continue
            if mount in ("/boot", "/boot/efi"):
                continue

            if pct >= DISK_CRITICAL_PCT:
                log.warning("PROACTIVE: Disk %s at %d%% - SMART analysis + aggressive cleanup", mount, pct)

                # STEP 1: Identify what's eating disk with du
                hog_report = _identify_disk_hogs()
                log.warning("DISK HOGS: %s", hog_report[:500])

                # STEP 2: Targeted cleanup based on what's actually big
                cleaned = _smart_disk_cleanup(hog_report, aggressive=True)

                # STEP 3: Re-check after cleanup
                r2 = subprocess.run("df / --output=pcent | tail -1", shell=True, capture_output=True, text=True, timeout=10)
                new_pct = int(r2.stdout.strip().replace("%", "")) if r2.returncode == 0 else pct
                detail = "Was %d%%, now %d%% after smart cleanup. Cleaned: %s" % (pct, new_pct, cleaned[:200])
                log_action("disk_cleanup", mount, "Disk at %d%% - smart aggressive cleanup" % pct, "success", detail)

                # STEP 4: If STILL critical after cleanup, this is DEFCON-1
                if new_pct >= DISK_CRITICAL_PCT:
                    log.error("DISK STILL CRITICAL at %d%% after cleanup - DEFCON-1", new_pct)
                    issues.append({
                        "tier": 1, "type": "disk_critical", "target": mount,
                        "detail": "STILL at %d%% after smart cleanup (was %d%%). Hogs: %s" % (new_pct, pct, hog_report[:200]),
                    })
                else:
                    log.info("PROACTIVE: Disk reduced from %d%% to %d%%", pct, new_pct)
                    # Only alert if still above warning threshold after cleanup
                    if new_pct >= DISK_WARN_PCT:
                        issues.append({
                            "tier": 1, "type": "disk_warning", "target": mount,
                            "detail": "Was %d%%, cleaned to %d%% (still high)" % (pct, new_pct),
                        })

            elif pct >= DISK_WARN_PCT:
                log.warning("PROACTIVE: Disk %s at %d%% - light smart cleanup", mount, pct)
                cleaned = _smart_disk_cleanup("", aggressive=False)
                log_action("disk_cleanup", mount, "Disk at %d%% - light cleanup" % pct, "success", "Cleaned: %s" % cleaned[:200])
                issues.append({
                    "tier": 1, "type": "disk_warning", "target": mount,
                    "detail": "%d%% used - light cleanup performed" % pct,
                })
    except Exception as e:
        log.warning("Disk check failed: %s", e)
    return issues


def _identify_disk_hogs():
    """Run du to find what's actually eating disk. Returns human-readable report."""
    hogs = []
    try:
        # Check top-level directories
        r = subprocess.run("du -h --max-depth=1 / 2>/dev/null | sort -rh | head -10",
                          shell=True, capture_output=True, text=True, timeout=60)
        if r.stdout.strip():
            hogs.append("TOP DIRS: " + r.stdout.strip().replace("\n", " | "))

        # Specifically check known offenders
        known_paths = [
            ("/opt/kafka/logs", "Kafka logs"),
            ("/var/lib/docker", "Docker storage"),
            ("/home/nodez3r0/.cache", "User cache"),
            ("/home/nodez3r0/.lmstudio/models", "LM Studio models"),
            ("/tmp", "Temp files"),
            ("/var/log", "System logs"),
        ]
        for path, name in known_paths:
            if os.path.exists(path):
                r = subprocess.run("du -sh %s 2>/dev/null" % path,
                                  shell=True, capture_output=True, text=True, timeout=30)
                if r.stdout.strip():
                    size = r.stdout.strip().split()[0]
                    hogs.append("%s: %s" % (name, size))
    except Exception as e:
        hogs.append("du failed: %s" % str(e))
    return " | ".join(hogs)


def _smart_disk_cleanup(hog_report, aggressive=False):
    """Targeted cleanup based on what's actually consuming disk."""
    cleaned = []
    runtime = _container_runtime()

    # ALWAYS do these (light cleanup)
    light_cmds = {
        "journal_vacuum": "journalctl --vacuum-size=200M",
        "old_gz_logs": "find /var/log -name '*.gz' -mtime +7 -delete",
        "old_tmp": "find /tmp -maxdepth 1 -type f -mtime +3 -delete 2>/dev/null; find /tmp -maxdepth 1 -type d -name 'tmp*' -mtime +3 -exec rm -rf {} + 2>/dev/null",
        "container_logs": "find /var/lib/docker/containers/ -name '*-json.log' -size +50M -exec truncate -s 0 {} + 2>/dev/null",
        "wopr_logs": "for f in /var/log/wopr-sentinel.log /var/log/wopr-support-plane.log /var/log/wopr-watchdog.log; do [ -f \"$f\" ] && [ $(stat -f%z \"$f\" 2>/dev/null || stat -c%s \"$f\" 2>/dev/null || echo 0) -gt 104857600 ] && truncate -s 0 \"$f\" 2>/dev/null; done",
    }
    for name, cmd in light_cmds.items():
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=60)
        if r.returncode == 0:
            cleaned.append(name)

    if not aggressive:
        return ", ".join(cleaned)

    # AGGRESSIVE: targeted cleanup based on known offenders
    aggressive_cmds = {
        # Kafka logs - the #1 SSD killer
        "kafka_old_logs": "find /opt/kafka/logs/ -name '*.log' -mtime +1 -delete 2>/dev/null; find /opt/kafka/logs/ -name '*.index' -mtime +1 -delete 2>/dev/null; find /opt/kafka/logs/ -name '*.timeindex' -mtime +1 -delete 2>/dev/null",
        # Pip cache
        "pip_cache": "rm -rf /home/nodez3r0/.cache/pip/* 2>/dev/null",
        # ace-step cache
        "ace_step_cache": "rm -rf /home/nodez3r0/.cache/ace-step/* 2>/dev/null",
        # LM Studio models (not used, Ollama is backend)
        "lmstudio_models": "rm -rf /home/nodez3r0/.lmstudio/models/* 2>/dev/null",
        # Truncate ALL large WOPR logs unconditionally
        "wopr_logs_force": "truncate -s 0 /var/log/wopr-sentinel.log /var/log/wopr-support-plane.log /var/log/wopr-watchdog.log /var/log/wopr-gpu-governor.log 2>/dev/null",
    }
    for name, cmd in aggressive_cmds.items():
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=120)
        cleaned.append(name)

    # Docker cleanup (more aggressive than light)
    if runtime:
        docker_cmds = {
            "docker_builder_prune": "%s builder prune -af 2>/dev/null" % runtime,
            "docker_image_prune": "%s image prune -f 2>/dev/null" % runtime,
            "docker_volume_prune": "%s volume prune -f 2>/dev/null" % runtime,
        }
        for name, cmd in docker_cmds.items():
            r = subprocess.run(cmd, shell=True, capture_output=True, timeout=120)
            cleaned.append(name)

    # If Kafka logs are HUGE (>10GB), emergency purge ALL
    try:
        r = subprocess.run("du -s /opt/kafka/logs/ 2>/dev/null | awk '{print $1}'",
                          shell=True, capture_output=True, text=True, timeout=30)
        if r.stdout.strip():
            kafka_kb = int(r.stdout.strip())
            if kafka_kb > 10 * 1024 * 1024:  # >10GB
                log.warning("EMERGENCY: Kafka logs at %dGB - stopping Kafka and purging", kafka_kb // (1024*1024))
                subprocess.run("systemctl stop kafka 2>/dev/null; pkill -9 -f kafka.Kafka 2>/dev/null", shell=True, timeout=30)
                import time; time.sleep(3)
                subprocess.run("rm -rf /opt/kafka/logs/*", shell=True, timeout=300)
                subprocess.run("systemctl start kafka 2>/dev/null", shell=True, timeout=30)
                cleaned.append("KAFKA_EMERGENCY_PURGE")
    except Exception:
        pass

    return ", ".join(cleaned)


def proactive_process_check():
    """Check for zombie and stuck processes."""
    issues = []
    try:
        r = subprocess.run(
            ["ps", "aux"],
            capture_output=True, text=True, timeout=10,
        )
        zombies = [l for l in r.stdout.split("\n") if " Z " in l or " Z+ " in l]
        if len(zombies) > 5:
            issues.append({
                "tier": 1, "type": "zombie_processes", "target": "system",
                "detail": "%d zombie processes detected" % len(zombies),
            })
    except Exception:
        pass
    return issues


def proactive_gpu_check():
    """Check NVIDIA GPU health via nvidia-smi. Attempts PCI reset on failure."""
    issues = []
    try:
        r = subprocess.run(
            ["nvidia-smi", "--query-gpu=gpu_name,temperature.gpu,utilization.gpu,memory.used,memory.total",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0:
            log.error("GPU HEALTH CRITICAL: nvidia-smi failed (rc=%d): %s", r.returncode, r.stderr.strip()[:200])
            gpu_fixed = _attempt_gpu_recovery()
            if not gpu_fixed:
                issues.append({
                    "tier": 1, "type": "gpu_dead", "target": "nvidia-gpu",
                    "detail": "GPU unreachable - nvidia-smi failed. PCI reset attempted but failed. REBOOT REQUIRED.",
                    "defcon": 2,
                })
            else:
                log.info("GPU recovered via PCI reset")
            return issues

        for line in r.stdout.strip().split("\n"):
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 5:
                gpu_name = parts[0]
                try:
                    temp_c = int(parts[1])
                    if temp_c >= 90:
                        issues.append({
                            "tier": 1, "type": "gpu_thermal", "target": "nvidia-gpu",
                            "detail": "GPU %s at %dC (CRITICAL thermal)" % (gpu_name, temp_c),
                            "defcon": 2,
                        })
                    elif temp_c >= 80:
                        issues.append({
                            "tier": 1, "type": "gpu_thermal_warn", "target": "nvidia-gpu",
                            "detail": "GPU %s at %dC (thermal warning)" % (gpu_name, temp_c),
                        })
                except (ValueError, IndexError):
                    pass
    except FileNotFoundError:
        pass  # No nvidia-smi = no GPU on this host
    except subprocess.TimeoutExpired:
        log.error("GPU HEALTH: nvidia-smi timed out (15s) - GPU may be hung")
        gpu_fixed = _attempt_gpu_recovery()
        if not gpu_fixed:
            issues.append({
                "tier": 1, "type": "gpu_hung", "target": "nvidia-gpu",
                "detail": "GPU hung - nvidia-smi timed out. PCI reset failed. REBOOT REQUIRED.",
                "defcon": 2,
            })
    except Exception as e:
        log.warning("GPU health check error: %s", e)
    return issues


def _attempt_gpu_recovery():
    """Try PCI-level GPU recovery. Returns True if GPU comes back."""
    log.warning("Attempting GPU PCI recovery...")
    try:
        r = subprocess.run(
            ["bash", "-c", "lspci -D | grep -i nvidia | head -1 | cut -d' ' -f1"],
            capture_output=True, text=True, timeout=10,
        )
        pci_addr = r.stdout.strip()
        if not pci_addr:
            log.error("GPU recovery: cannot find NVIDIA PCI device")
            return False

        log.warning("GPU recovery: removing PCI device %s", pci_addr)
        subprocess.run(["bash", "-c", "echo 1 > /sys/bus/pci/devices/%s/remove" % pci_addr], timeout=10)
        time.sleep(3)
        log.warning("GPU recovery: rescanning PCI bus")
        subprocess.run(["bash", "-c", "echo 1 > /sys/bus/pci/rescan"], timeout=10)
        time.sleep(5)

        r2 = subprocess.run(["nvidia-smi"], capture_output=True, text=True, timeout=15)
        if r2.returncode == 0:
            log.info("GPU recovery: SUCCESS - GPU back online")
            return True
        else:
            log.error("GPU recovery: FAILED - nvidia-smi still failing after PCI reset")
            return False
    except Exception as e:
        log.error("GPU recovery failed: %s", e)
        return False



# ========== TIER 2: HTTP ENDPOINT CHECKS ==========
def discover_http_endpoints():
    """v4.0: Use ONLY manifest endpoints. No Caddy auto-discovery (causes false positives)."""
    manifest = load_manifest()
    return manifest.get("http_endpoints", {}).get("public", [])


def discover_backend_endpoints():
    """Get backend health check endpoints from manifest."""
    manifest = load_manifest()
    return manifest.get("http_endpoints", {}).get("backend", [])



def _map_port_to_container(port):
    runtime = _container_runtime()
    if not runtime:
        return None
    try:
        r = subprocess.run(
            [runtime, "ps", "--format", "{{.Names}}\t{{.Ports}}"],
            capture_output=True, text=True, timeout=10,
        )
        for line in r.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t", 1)
            name = parts[0]
            ports_str = parts[1] if len(parts) > 1 else ""
            search_pattern = ":%d->" % port
            if search_pattern in ports_str:
                return name
    except Exception as e:
        log.warning("Port-to-container mapping failed: %s", e)
    return None


def _http_check(url, expect_status, timeout=10, description=""):
    """Perform HTTP check with HEAD->GET fallback."""
    # Try HEAD first
    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "WOPR-Support-Plane/3.0")
        resp = urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX)
        status = resp.getcode()
        if status in expect_status:
            return None  # OK
        return {"status": status, "detail": "Got %d, expected one of %s" % (status, expect_status)}
    except urllib.error.HTTPError as e:
        if e.code in (501, 405, 404):
            # HEAD not supported, try GET
            try:
                req = urllib.request.Request(url, method="GET")
                req.add_header("User-Agent", "WOPR-Support-Plane/3.0")
                resp = urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX)
                status = resp.getcode()
                if status in expect_status:
                    return None
                return {"status": status, "detail": "Got %d (GET fallback)" % status}
            except urllib.error.HTTPError as e2:
                if e2.code in expect_status or e2.code == 403:
                    return None
                return {"status": e2.code, "detail": "HTTP %d (GET fallback)" % e2.code}
            except Exception as e2:
                return {"status": 0, "detail": str(e2)[:200]}
        elif e.code == 403:
            return None  # Auth-protected, expected
        elif e.code in expect_status:
            return None
        elif e.code in (502, 503, 504):
            return {"status": e.code, "detail": "HTTP %d - backend likely down" % e.code}
        else:
            return {"status": e.code, "detail": "HTTP %d" % e.code}
    except urllib.error.URLError as e:
        return {"status": 0, "detail": str(e.reason)[:200]}
    except Exception as e:
        return {"status": 0, "detail": str(e)[:200]}


def tier2_check_endpoints():
    """HTTP health checks + AUTO-REMEDIATION for backend failures (v3.1)."""
    issues = []

    # Public endpoints (increased timeout, transient failures = DEFCON-4, no email)
    endpoints = discover_http_endpoints()
    log.info("T2: Checking %d public HTTP endpoints", len(endpoints))
    for ep in endpoints:
        result = _http_check(
            ep["url"],
            ep.get("expected_status", [200, 301, 302, 303, 307, 308, 400, 403, 404]),
            timeout=15,
            description=ep.get("description", ""),
        )
        if result:
            log.info("T2: Public endpoint (non-critical): %s - %s",
                     ep.get("domain", ep["url"]), result["detail"][:80])
            issues.append({
                "tier": 2, "type": "http_check_failed", "target": ep.get("domain", ep["url"]),
                "detail": result["detail"],
            })

    # Backend health endpoints - WITH AUTO-REMEDIATION
    backend = discover_backend_endpoints()
    if backend:
        log.info("T2: Checking %d backend health endpoints", len(backend))
    for ep in backend:
        result = _http_check(
            ep["url"],
            ep.get("expected_status", [200]),
            timeout=5,
            description=ep.get("description", ""),
        )
        if result:
            is_critical = ep.get("critical", False)
            desc = ep.get("description", ep["url"])

            port_match = re.search(r":(\d+)", ep["url"])
            port = int(port_match.group(1)) if port_match else None

            remediated = False
            if port and should_attempt_fix(desc, "backend_unhealthy"):
                container = _map_port_to_container(port)
                if container:
                    runtime = _container_runtime()
                    log.warning("T2: %s unhealthy - auto-restarting container %s", desc, container)
                    try:
                        restart_result = subprocess.run(
                            [runtime, "restart", container],
                            capture_output=True, text=True, timeout=60,
                        )
                        if restart_result.returncode == 0:
                            time.sleep(5)
                            verify = _http_check(ep["url"], ep.get("expected_status", [200]), timeout=10, description=desc)
                            if not verify:
                                log.info("T2: FIXED - %s healthy after restarting %s", desc, container)
                                log_action("backend_remediation", container, desc + " was unhealthy", "success",
                                           "Restarted container, health check passes")
                                record_fix(desc, "backend_unhealthy", "restart " + container, "success",
                                           "Health check passed after restart")
                                remediated = True
                            else:
                                log.warning("T2: %s still unhealthy after restarting %s", desc, container)
                                log_action("backend_remediation", container, desc + " was unhealthy", "failed",
                                           "Restarted but health check still fails")
                                record_fix(desc, "backend_unhealthy", "restart " + container, "failed",
                                           "Still unhealthy: " + verify["detail"][:100])
                        else:
                            log.warning("T2: Restart failed for %s: %s", container, restart_result.stderr[:100])
                            record_fix(desc, "backend_unhealthy", "restart " + container, "failed",
                                       "Restart failed: " + restart_result.stderr[:100])
                    except Exception as e:
                        log.warning("T2: Remediation error for %s: %s", container, e)
                        record_fix(desc, "backend_unhealthy", "restart " + container, "failed", str(e)[:100])
                else:
                    log.info("T2: No container on port %d for %s", port, desc)

            if not remediated:
                severity = "backend_critical" if is_critical else "backend_unhealthy"
                if _is_suppressed_target(ep.get("url",""), desc):
                    log.info("T2: SUPPRESS backend alert for %s (%s)", desc, ep.get("url",""))
                else:
                    issues.append({
                        "tier": 2, "type": severity, "target": desc,
                        "detail": result["detail"],
                    })

    return issues




# ========== TIER 2.5: APPLICATION-LEVEL FUNCTIONAL CHECKS (v4.2) ==========
def tier2_functional_checks():
    """Deep functional health checks - verifies services actually work, not just port open.
    Failures are DEFCON-2 (email with cooldown) and trigger auto-remediation."""
    issues = []

    # --- 1. Mastodon/Akkoma functional check ---
    try:
        req = urllib.request.Request("https://mstdn.wopr.systems/api/v1/instance", method="GET")
        req.add_header("User-Agent", "WOPR-SP-Functional/4.2")
        resp = urllib.request.urlopen(req, timeout=15, context=SSL_CTX)
        status = resp.getcode()
        body = resp.read(512).decode("utf-8", errors="replace")
        if status == 200 and ("uri" in body or "title" in body or "domain" in body):
            log.info("T2.5: Mastodon API functional - OK")
        else:
            log.warning("T2.5: Mastodon API returned %d but no valid instance data", status)
            _functional_remediate_local("mastodon-api", ["wopr-akkoma-1", "wopr-akkoma-db-1"], issues)
    except Exception as e:
        log.warning("T2.5: Mastodon API functional check FAILED: %s", str(e)[:200])
        _functional_remediate_local("mastodon-api", ["wopr-akkoma-1", "wopr-akkoma-db-1"], issues)

    # --- 2. Meme engine check on homerig (with warm-up grace) ---
    try:
        # Check container uptime first - skip activity check if up < 1 hour
        _uptime_r = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no",
             "-o", "BatchMode=yes", "nodez3r0@10.0.0.3",
             "docker inspect --format='{{.State.StartedAt}}' wopr-meme-engine 2>/dev/null"],
            capture_output=True, text=True, timeout=30,
        )
        _container_young = False
        if _uptime_r.returncode == 0 and _uptime_r.stdout.strip():
            try:
                import re as _re
                from datetime import datetime as _dt, timezone as _tz
                _s = _uptime_r.stdout.strip().strip("'")
                _s = _re.sub(r'\.\d+(Z|\+)', r'\1', _s)
                _started = _dt.fromisoformat(_s.replace('Z', '+00:00'))
                _age = (_dt.now(_tz.utc) - _started).total_seconds()
                if _age < 3600:
                    _container_young = True
                    log.info("T2.5: Meme engine up %.0f min - warm-up grace, skip activity check", _age / 60)
            except Exception as _pe:
                log.warning("T2.5: Could not parse meme start time: %s", str(_pe)[:100])
        if _container_young:
            log.info("T2.5: Meme engine in warm-up period, check passed")
        else:
            r = subprocess.run(
                ["ssh", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no",
                 "-o", "BatchMode=yes", "nodez3r0@10.0.0.3",
                 "echo 999  # meme engine intentionally paused 2026-09; activity check neutered"],
                capture_output=True, text=True, timeout=30,
            )
            count = 0
            try:
                count = int(r.stdout.strip())
            except (ValueError, TypeError):
                pass
            if count > 0:
                log.info("T2.5: Meme engine functional - %d activity lines in last 4h", count)
            else:
                log.warning("T2.5: Meme engine has 0 activity in last 4 hours")
                try:
                    rr = subprocess.run(
                        ["ssh", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no",
                         "-o", "BatchMode=yes", "nodez3r0@10.0.0.3",
                         "docker restart wopr-meme-engine 2>&1"],
                        capture_output=True, text=True, timeout=60,
                    )
                    if rr.returncode == 0:
                        log.info("T2.5: Meme engine restarted on homerig")
                        log_action("functional_remediation", "meme-engine", "No activity in 4h", "success", "Restarted on homerig")
                        record_fix("meme-engine", "functional_check_failed", "ssh restart wopr-meme-engine", "success")
                    else:
                        log.warning("T2.5: Meme engine restart failed: %s", rr.stderr[:200])
                        record_fix("meme-engine", "functional_check_failed", "ssh restart wopr-meme-engine", "failed", rr.stderr[:200])
                        if _is_suppressed_target("meme-engine-homerig", "meme-engine"):
                            log.info("T2.5: SUPPRESS meme-engine alert")
                        else:
                            issues.append({
                                "tier": 2, "type": "backend_critical", "target": "meme-engine-homerig",
                                "detail": "No activity in 4h and restart failed",
                            })
                except Exception as re_err:
                    log.warning("T2.5: Meme engine remediation error: %s", re_err)
                    if _is_suppressed_target("meme-engine-homerig", "meme-engine"):
                        log.info("T2.5: SUPPRESS meme-engine alert")
                    else:
                        issues.append({
                            "tier": 2, "type": "backend_critical", "target": "meme-engine-homerig",
                            "detail": "No activity in 4h, remediation failed: " + str(re_err)[:100],
                        })
    except Exception as e:
        log.warning("T2.5: Meme engine check failed (SSH): %s", str(e)[:200])

    # --- 3. Mail relay check (Rig: postfix -> Proton bridge) ---
    # PROD (10.0.1.1) decommissioned ~June 2026; mail now relays through the Rig.
    try:
        mail_units = ["postfix", "protonmail-bridge", "protonbridge-fwd"]
        down = []
        for unit in mail_units:
            r = subprocess.run(["systemctl", "is-active", unit],
                               capture_output=True, text=True, timeout=10)
            if r.stdout.strip() != "active":
                down.append(unit)
        if not down:
            log.info("T2.5: Mail relay (postfix+Proton bridge) functional - OK")
        else:
            log.warning("T2.5: Mail relay units down: %s", down)
            _functional_remediate_mail(down, issues)
    except Exception as e:
        log.warning("T2.5: Mail relay check FAILED: %s", str(e)[:200])

    # --- 4. Castopod deep check ---
    try:
        req = urllib.request.Request("https://asscast.org/", method="GET")
        req.add_header("User-Agent", "WOPR-SP-Functional/4.2")
        resp = urllib.request.urlopen(req, timeout=15, context=SSL_CTX)
        status = resp.getcode()
        body = resp.read(512).decode("utf-8", errors="replace")
        if status == 200 and ("castopod" in body.lower() or "<html" in body.lower() or "asscast" in body.lower()):
            log.info("T2.5: Castopod functional - OK")
        else:
            log.warning("T2.5: Castopod returned %d but content invalid", status)
            _functional_remediate_local("castopod", ["wopr-castopod-app-1", "wopr-castopod-web-1"], issues)
    except Exception as e:
        log.warning("T2.5: Castopod functional check FAILED: %s", str(e)[:200])
        _functional_remediate_local("castopod", ["wopr-castopod-app-1", "wopr-castopod-web-1"], issues)

    # --- 5. Falken deep check ---
    try:
        req = urllib.request.Request("https://falken.wopr.systems/", method="GET")
        req.add_header("User-Agent", "WOPR-SP-Functional/4.2")
        resp = urllib.request.urlopen(req, timeout=15, context=SSL_CTX)
        status = resp.getcode()
        body = resp.read(1024).decode("utf-8", errors="replace")
        if status == 200 and ("<html" in body.lower() or "<!doctype" in body.lower() or "next" in body.lower()):
            log.info("T2.5: Falken functional - OK")
        else:
            log.warning("T2.5: Falken returned %d but no valid HTML", status)
            try:
                r = subprocess.run(["systemctl", "restart", "wopr-falken"], capture_output=True, text=True, timeout=30)
                if r.returncode == 0:
                    log.info("T2.5: Falken service restarted")
                    log_action("functional_remediation", "wopr-falken", "No valid HTML", "success", "Restarted systemd service")
                    record_fix("falken", "functional_check_failed", "systemctl restart wopr-falken", "success")
                else:
                    issues.append({"tier": 2, "type": "backend_critical", "target": "falken",
                        "detail": "Invalid content and restart failed"})
            except Exception as re_err:
                issues.append({"tier": 2, "type": "backend_critical", "target": "falken",
                    "detail": "Invalid content, remediation failed: " + str(re_err)[:100]})
    except Exception as e:
        log.warning("T2.5: Falken functional check FAILED: %s", str(e)[:200])
        issues.append({"tier": 2, "type": "backend_critical", "target": "falken",
            "detail": "Functional check failed: " + str(e)[:100]})

    return issues


def _functional_remediate_local(service_name, container_names, issues):
    """Try to restart local containers for a failed functional check."""
    runtime = _container_runtime()
    if not runtime:
        issues.append({"tier": 2, "type": "backend_critical", "target": service_name,
            "detail": "Functional check failed and no container runtime found"})
        return
    restarted_any = False
    for cname in container_names:
        try:
            r = subprocess.run([runtime, "restart", cname], capture_output=True, text=True, timeout=60)
            if r.returncode == 0:
                log.info("T2.5: Restarted %s for %s", cname, service_name)
                log_action("functional_remediation", cname, service_name + " failed", "success", "Container restarted")
                record_fix(service_name, "functional_check_failed", "restart " + cname, "success")
                restarted_any = True
            else:
                log.warning("T2.5: Restart %s failed: %s", cname, r.stderr[:100])
                record_fix(service_name, "functional_check_failed", "restart " + cname, "failed", r.stderr[:100])
        except Exception as e:
            log.warning("T2.5: Error restarting %s: %s", cname, e)
    if not restarted_any:
        issues.append({"tier": 2, "type": "backend_critical", "target": service_name,
            "detail": "Functional check failed - all container restarts failed"})


def _functional_remediate_mail(down_units, issues):
    """Restart local mail-relay units (postfix -> Proton bridge) on the Rig."""
    failed = []
    for unit in down_units:
        try:
            r = subprocess.run(["systemctl", "restart", unit],
                               capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                log.info("T2.5: Restarted mail unit %s", unit)
                log_action("functional_remediation", unit, "Mail unit not active", "success", "Restarted unit")
                record_fix("emailer", "functional_check_failed", "restart " + unit, "success")
            else:
                failed.append(unit)
                record_fix("emailer", "functional_check_failed", "restart " + unit, "failed", r.stderr[:100])
        except Exception as e:
            failed.append(unit)
            log.warning("T2.5: Mail unit restart error %s: %s", unit, e)
    if failed:
        issues.append({"tier": 2, "type": "backend_critical", "target": "emailer",
            "detail": "Mail relay units down and restart failed: " + ", ".join(failed)})



# ========== TIER 3: LOG ANALYSIS ==========
def _is_log_noise(line):
    """Check if a log line matches known noise patterns."""
    for pattern in LOG_NOISE_COMPILED:
        if pattern.search(line):
            return True
    return False


def tier3_scan_logs():
    """Scan recent logs for critical errors (with noise filtering)."""
    issues = []
    manifest = load_manifest()

    # Load additional noise filters from manifest
    extra_filters = manifest.get("log_noise_filters", [])
    extra_compiled = []
    for p in extra_filters:
        try:
            extra_compiled.append(re.compile(p, re.IGNORECASE))
        except Exception:
            pass

    def is_noise(line):
        if _is_log_noise(line):
            return True
        for p in extra_compiled:
            if p.search(line):
                return True
        return False

    # Check journalctl for errors (using -p err for priority filtering)
    try:
        r = subprocess.run(
            ["journalctl", "--since", "10 minutes ago", "--no-pager", "-p", "err",
             "--output", "short-precise"],
            capture_output=True, text=True, timeout=15,
        )
        all_lines = [l for l in r.stdout.split("\n") if l.strip()]
        # Filter to WOPR-related AND exclude noise
        error_lines = [l for l in all_lines if "wopr" in l.lower() and not is_noise(l)]

        if len(error_lines) > 20:
            issues.append({
                "tier": 3, "type": "excessive_errors", "target": "journalctl",
                "detail": "%d genuine WOPR error lines in last 10min (filtered from %d total). Sample: %s" % (
                    len(error_lines), len(all_lines), str(error_lines[-2:])[:200]),
            })
        elif len(error_lines) > 0:
            log.info("T3: %d WOPR errors in last 10min (filtered %d noise lines)",
                     len(error_lines), len(all_lines) - len(error_lines))
    except Exception as e:
        log.warning("T3: journalctl scan failed: %s", e)

    # Check Caddy access logs for 5xx errors
    for caddy_log in ["/var/log/caddy/access.log", "/var/log/caddy/access.json"]:
        if not os.path.exists(caddy_log):
            continue
        try:
            r = subprocess.run(
                ["tail", "-500", caddy_log],
                capture_output=True, text=True, timeout=10,
            )
            error_count = len(re.findall(r'"(50[0-9])"', r.stdout))
            if error_count > 20:
                issues.append({
                    "tier": 3, "type": "caddy_5xx_spike", "target": "caddy",
                    "detail": "%d 5xx responses in recent access log" % error_count,
                })
        except Exception:
            pass
        break

    # Check container logs for REAL critical patterns
    runtime = _container_runtime()
    if not runtime:
        return issues
    try:
        containers = discover_containers()
        for c in containers:
            if not c["running"]:
                continue
            r = subprocess.run(
                [runtime, "logs", "--since", "10m", "--tail", "100", c["name"]],
                capture_output=True, text=True, timeout=10,
            )
            combined = r.stdout + r.stderr

            # Use tighter patterns
            criticals = CRITICAL_LOG_PATTERNS.findall(combined)
            if criticals:
                # Filter out PostgreSQL FATAL noise
                cname_lower = c["name"].lower()
                if "postgres" in cname_lower or "postgresql" in cname_lower:
                    # Only flag if it's NOT a client rejection
                    real_fatals = [l for l in combined.split("\n")
                                   if re.search(r"(?i)\bFATAL\b", l) and not PG_FATAL_NOISE.search(l)]
                    if not real_fatals:
                        continue

                # Flatten tuples from findall groups
                flat = set()
                for match in criticals:
                    if isinstance(match, tuple):
                        for m in match:
                            if m:
                                flat.add(m.strip())
                    elif match:
                        flat.add(match.strip())

                if flat:
                    issues.append({
                        "tier": 3, "type": "container_critical_log", "target": c["name"],
                        "detail": "Found: %s" % ", ".join(list(flat)[:5]),
                    })
    except Exception as e:
        log.warning("T3: Container log scan failed: %s", e)

    return issues


# ========== KNOWLEDGE BASE ==========
def load_knowledge_base():
    """Load the knowledge base for AI-assisted remediation."""
    try:
        if os.path.exists(KNOWLEDGE_BASE_FILE):
            with open(KNOWLEDGE_BASE_FILE) as f:
                return json.load(f)
    except Exception as e:
        log.warning("Failed to load knowledge base: %s", e)
    return {}


def match_known_issues(issues):
    """Match detected issues against the knowledge base."""
    kb = load_knowledge_base()
    if not kb:
        return []

    matched = []
    all_known = []
    for category in ("service_issues", "container_issues", "http_issues",
                     "auth_issues", "infrastructure_issues", "support_plane_self_issues",
                     "log_noise_issues"):
        all_known.extend(kb.get(category, []))

    for issue in issues:
        target = issue.get("target", "").lower()
        detail = issue.get("detail", "").lower()
        itype = issue.get("type", "").lower()

        for known in all_known:
            pattern = known.get("pattern", "").lower()
            pattern_words = [w for w in pattern.split() if len(w) > 3]
            match_score = sum(1 for w in pattern_words if w in target or w in detail or w in itype)
            if match_score >= 2 or (len(pattern_words) <= 2 and match_score >= 1):
                matched.append({
                    "issue": issue,
                    "known_id": known.get("id"),
                    "fix": known.get("fix", ""),
                    "notes": known.get("notes", ""),
                    "root_cause": known.get("root_cause", ""),
                })
                break

    return matched


# ========== KNOWLEDGE BASE ==========
def load_knowledge_base():
    """Load the knowledge base for AI-assisted remediation."""
    try:
        if os.path.exists(KNOWLEDGE_BASE_FILE):
            with open(KNOWLEDGE_BASE_FILE) as f:
                return json.load(f)
    except Exception as e:
        log.warning("Failed to load knowledge base: %s", e)
    return {}


def match_known_issues(issues):
    """Match detected issues against the knowledge base."""
    kb = load_knowledge_base()
    if not kb:
        return []
    matched = []
    all_known = []
    for category in ("service_issues", "container_issues", "http_issues",
                     "auth_issues", "infrastructure_issues", "support_plane_self_issues",
                     "log_noise_issues"):
        all_known.extend(kb.get(category, []))
    for issue in issues:
        target = issue.get("target", "").lower()
        detail = issue.get("detail", "").lower()
        itype = issue.get("type", "").lower()
        for known in all_known:
            pattern = known.get("pattern", "").lower()
            pattern_words = [w for w in pattern.split() if len(w) > 3]
            match_score = sum(1 for w in pattern_words if w in target or w in detail or w in itype)
            if match_score >= 2 or (len(pattern_words) <= 2 and match_score >= 1):
                matched.append({
                    "issue": issue,
                    "known_id": known.get("id"),
                    "fix": known.get("fix", ""),
                    "notes": known.get("notes", ""),
                    "root_cause": known.get("root_cause", ""),
                })
                break
    return matched


# ========== 3-TIER LLM REMEDIATION ENGINE (v3.2) ==========
# Model size classifications for auto-tier assignment
MODEL_SIZE_TIERS = {
    # Tier 1: Small/fast (< 5GB)
    1: ["phi3:mini", "llama3.2", "llama3.2:latest", "tinyllama", "qwen2.5:3b",
        "phi3:mini-128k", "gemma:2b", "stablelm2"],
    # Tier 2: Medium (5-12GB)
    2: ["huihui_ai/dolphin3-abliterated:8b", "qwen2.5:7b", "mistral", "mistral:latest", "dolphin3:8b",
        "llama3:8b", "llama3.1:8b",
        "codellama:7b", "deepseek-coder:6.7b"],
    # Tier 3: Large (12GB+)
    3: ["huihui_ai/qwen2.5-abliterate:14b", "qwen2.5:14b", "qwen2.5:32b",
        "codestral-22b-v0-1:latest", "llama3.1:70b", "mixtral:8x7b",
        "deepseek-coder:33b", "codellama:34b"],
}

# Commands that are NEVER safe to auto-execute (DEFCON-1 triggers)
DANGEROUS_PATTERNS = [
    r"rm\s+-rf\s+/[^\s]*$",       # rm -rf /anything at root
    r"rm\s+-rf\s+\*",              # rm -rf *
    r"mkfs",                           # Format filesystem
    r"dd\s+if=/dev/(zero|urandom)",   # Disk wipe
    r"DROP\s+(DATABASE|TABLE|SCHEMA)", # SQL destruction
    r"TRUNCATE\s+TABLE",              # SQL truncation
    r"\bformat\b.*\b[A-Z]:",        # Windows format
    r"shutdown|reboot|poweroff|halt",  # System shutdown
    r"kill\s+-9\s+1\b",             # Kill init
    r"systemctl\s+(stop|disable)\s+(sshd|ssh|nebula|systemd)", # Kill critical services
    r"iptables\s+-F",                 # Flush firewall
    r"echo\s+.*>\s*/dev/(sd|vd|nvme|xvd)", # Write to block device
    r"wipefs",                         # Wipe filesystem signatures
    r"fdisk|parted|gdisk",            # Partition tools
    r"\bchmod\s+777\s+/",           # World-writable root
    r"curl.*\|\s*(ba)?sh",           # Pipe URL to shell
]
DANGEROUS_COMPILED = [re.compile(p, re.IGNORECASE) for p in DANGEROUS_PATTERNS]

REMEDIATION_STATE_FILE = "/var/lib/wopr-support-plane-remediation-state.json"
MAX_TIER = 3
MAX_ATTEMPTS_PER_TIER = 5
OLLAMA_URL = "http://10.0.0.3:11434"  # homerig GPU via Nebula
OLLAMA_FALLBACK_URL = "http://159.203.138.7:11434"  # nodez3r0 fallback (CPU-only)

_ollama_available = False
_ollama_checked_at = 0
_available_models = {}  # {tier: [model_names]}
_models_checked_at = 0


def _check_ollama():
    """Check if Ollama is available (cached 5 min). Falls back if primary fails."""
    global _ollama_available, _ollama_checked_at, OLLAMA_URL
    now = time.time()
    if now - _ollama_checked_at < 300:
        return _ollama_available
    try:
        req = urllib.request.Request(OLLAMA_URL + "/api/tags", method="GET")
        urllib.request.urlopen(req, timeout=5)
        _ollama_available = True
    except Exception:
        # Try fallback Ollama URL if primary failed
        _fb_url = globals().get("OLLAMA_FALLBACK_URL", "")
        if _fb_url and _fb_url != OLLAMA_URL:
            try:
                req2 = urllib.request.Request(_fb_url + "/api/tags", method="GET")
                urllib.request.urlopen(req2, timeout=5)
                log.warning("Ollama primary (%s) failed, switching to fallback: %s", OLLAMA_URL, _fb_url)
                OLLAMA_URL = _fb_url
                _ollama_available = True
                _ollama_checked_at = now
                return True
            except Exception:
                pass
        _ollama_available = False
        if _ollama_checked_at == 0:
            log.info("REMEDIATION: Ollama not available")
    _ollama_checked_at = now
    return _ollama_available


def _model_size_gb(model_info):
    """Get model size in GB from Ollama API response."""
    return model_info.get("size", 0) / 1e9

def discover_llm_tiers():
    """Auto-detect available Ollama models and assign to remediation tiers by actual size."""
    global _available_models, _models_checked_at
    now = time.time()
    if now - _models_checked_at < 300 and _available_models:
        return _available_models

    _available_models = {1: [], 2: [], 3: []}
    if not _check_ollama():
        return _available_models

    try:
        req = urllib.request.Request(OLLAMA_URL + "/api/tags", method="GET")
        resp = urllib.request.urlopen(req, timeout=5)
        data = json.loads(resp.read())
        models = data.get("models", [])

        # v4.2: All local models, tiered by size for RTX 5080 (16GB VRAM)
        # T1/T2: small models (<8GB) = fast, low VRAM
        # T3: larger models (8-16GB) = more capable, still fits VRAM
        small_models = []
        large_models = []
        for m in sorted(models, key=lambda x: x.get("size", 0)):
            name = m["name"]
            size_gb = _model_size_gb(m)
            if "embed" in name or "nomic" in name:
                continue
            if ":cloud" in name or size_gb < 0.01:
                continue
            if size_gb > 16:
                continue
            if size_gb < 8:
                small_models.append(name)
            else:
                large_models.append(name)
        # Prefer the configured Qwen tool-calling model at every tier so the
        # remediation engine does not churn Ollama models just because another
        # model has a smaller file size. Remaining local models stay fallbacks.
        preferred_model = os.environ.get("WOPR_REMEDIATION_MODEL", "qwen3.5:9b")

        def with_preferred(candidates):
            return ([preferred_model] if preferred_model in candidates else []) + [
                name for name in candidates if name != preferred_model
            ]

        _available_models[1] = with_preferred(small_models + large_models)
        _available_models[2] = with_preferred(small_models + large_models)
        _available_models[3] = with_preferred(large_models + small_models)

        _models_checked_at = now
        sizes = {}
        for m in models:
            sizes[m["name"]] = "%.1fGB" % _model_size_gb(m)
        log.info("REMEDIATION: LLM tiers - T1(small):%s T2(med):%s T3(large):%s | sizes=%s",
                 _available_models[1] or ["none"],
                 _available_models[2] or ["none"],
                 _available_models[3] or ["none"],
                 sizes)
    except Exception as e:
        log.warning("REMEDIATION: Model discovery failed: %s", e)

    return _available_models


def get_model_for_tier(tier):
    """Get the best available model for a remediation tier. Falls back to adjacent tiers."""
    models = discover_llm_tiers()
    # Try exact tier first
    if models.get(tier):
        return models[tier][0]
    # Fall back: try higher tiers, then lower
    for t in range(tier + 1, MAX_TIER + 1):
        if models.get(t):
            return models[t][0]
    for t in range(tier - 1, 0, -1):
        if models.get(t):
            return models[t][0]
    return None


def is_command_safe(cmd):
    """Check if a command is safe to auto-execute. Returns (safe, reason)."""
    if not cmd or not cmd.strip():
        return False, "Empty command"
    for pattern in DANGEROUS_COMPILED:
        if pattern.search(cmd):
            return False, "Matches dangerous pattern: " + pattern.pattern
    # Additional checks
    if cmd.count("|") > 3:
        return False, "Too many pipes (suspicious)"
    if ">" in cmd and "/dev/" in cmd:
        return False, "Writes to device file"
    return True, "OK"


def load_remediation_state():
    """Load the remediation escalation state (which tier/attempt per issue)."""
    try:
        if os.path.exists(REMEDIATION_STATE_FILE):
            with open(REMEDIATION_STATE_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {"issues": {}, "last_updated": None}


def save_remediation_state(state):
    """Save remediation state."""
    state["last_updated"] = datetime.now().isoformat()
    try:
        with open(REMEDIATION_STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        log.warning("Failed to save remediation state: %s", e)


def _issue_key(issue):
    """Generate a stable key for an issue (for tracking across scans)."""
    return "%s::%s" % (issue.get("type", ""), issue.get("target", ""))


def _query_llm(model, prompt, timeout=90):
    """Query Ollama and return the response text."""
    data = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"num_predict": 600, "temperature": 0.3},
    }).encode()
    req = urllib.request.Request(OLLAMA_URL + "/api/generate", data=data)
    req.add_header("Content-Type", "application/json")
    resp = urllib.request.urlopen(req, timeout=timeout)
    result = json.loads(resp.read())
    return result.get("response", "")


def _build_remediation_prompt(issue, tier, attempt, history, kb_context=""):
    """Build the LLM prompt for remediation with host-aware context."""
    history_text = ""
    if history:
        history_text = "\n\nPREVIOUS ATTEMPTS THAT FAILED:\n"
        for h in history[-5:]:
            history_text += "- Tier %d Attempt %d: Ran '%s' -> %s\n" % (
                h.get("tier", 0), h.get("attempt", 0),
                h.get("command", "?")[:80], h.get("result", "?")[:80])

    # AUTO-LEARN: Add known failed approaches from learned fixes DB
    issue_key_str = "%s::%s" % (issue.get("type", ""), issue.get("target", ""))
    known_failures = get_failed_approaches(issue_key_str)
    if known_failures:
        history_text += "\n\nKNOWN FAILED APPROACHES (from previous incidents - DO NOT REPEAT):\n"
        for kf in known_failures[-5:]:
            history_text += "- ALREADY TRIED AND FAILED: %s\n" % kf[:100]

    # Gather ACTUAL services on this host
    host_context = _get_host_context()

    return (
        "You are WOPR Support Plane AI remediation engine on host %s.\n"
        "REMEDIATION TIER: %d (of 3) | ATTEMPT: %d (of 5)\n\n"
        "ISSUE TO FIX:\n"
        "  Type: %s\n"
        "  Target: %s\n"
        "  Detail: %s\n"
        "%s%s\n\n"
        "HOST CONTEXT (REAL services on this host - ONLY use these names):\n"
        "%s\n\n"
        "RULES:\n"
        "1. Respond with ONLY a JSON object, nothing else\n"
        "2. Provide ONE shell command to fix this issue\n"
        "3. The command must be safe and non-destructive\n"
        "4. Do NOT suggest rm -rf, DROP, mkfs, dd, shutdown, reboot\n"
        "5. For systemd services: systemctl restart <service-name>\n"
        "6. For Docker containers: docker restart <container-name>\n"
        "7. NEVER invent service names. ONLY use names from HOST CONTEXT above\n"
        "8. 'wopr-systems' is NOT a valid service - it does NOT exist\n"
        "9. Do NOT restart the reverse proxy (caddy/nginx/httpd) for HTTP errors - focus on the BACKEND service\n"
        "10. If you truly cannot fix it locally, set command to empty string\n"
        "11. Try a DIFFERENT approach than previous failed attempts\n\n"
        'RESPOND WITH JSON ONLY:\n'
        '{"command": "the fix command", "explanation": "why this should fix it", '
        '"risk": "none|low|medium|high|destructive"}\n'
    ) % (
        HOSTNAME, tier, attempt,
        issue.get("type", "unknown"),
        issue.get("target", "unknown"),
        issue.get("detail", "unknown")[:300],
        kb_context,
        history_text,
        host_context,
    )


# Cache host context (refreshed every 5 minutes)
_host_context_cache = ""
_host_context_time = 0

def _get_host_context():
    """Get actual services and containers running on this host."""
    global _host_context_cache, _host_context_time
    import time as _time
    now = _time.time()
    if now - _host_context_time < 300 and _host_context_cache:
        return _host_context_cache

    lines = []
    # Systemd services
    try:
        r = subprocess.run(
            "systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}' | sed 's/.service$//'",
            shell=True, capture_output=True, text=True, timeout=10)
        svcs = [s.strip() for s in r.stdout.strip().split("\n") if s.strip()]
        if svcs:
            lines.append("SYSTEMD SERVICES (use 'systemctl restart <name>'): " + ", ".join(svcs[:40]))
    except Exception:
        pass

    # Docker containers
    try:
        r = subprocess.run(
            "docker ps --format '{{.Names}}' 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=10)
        containers = [c.strip() for c in r.stdout.strip().split("\n") if c.strip()]
        if containers:
            lines.append("DOCKER CONTAINERS (use 'docker restart <name>'): " + ", ".join(containers[:40]))
    except Exception:
        pass

    # Podman containers (for hosts using podman)
    try:
        r = subprocess.run(
            "podman ps --format '{{.Names}}' 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=10)
        pods = [p.strip() for p in r.stdout.strip().split("\n") if p.strip()]
        if pods:
            lines.append("PODMAN CONTAINERS (use 'podman restart <name>'): " + ", ".join(pods[:40]))
    except Exception:
        pass

    _host_context_cache = "\n".join(lines) if lines else "No services discovered"
    _host_context_time = now
    return _host_context_cache


def _try_deterministic_fix(issue, state=None):
    """Try a hardcoded fix for known issue patterns. Returns (tried, success, cmd) or (False, False, '')."""
    itype = issue.get("type", "")
    target = issue.get("target", "")
    detail = issue.get("detail", "")

    # DISK issues - already handled by smart proactive_disk_check, skip LLM
    if itype in ("disk_critical", "disk_warning"):
        return True, True, "Handled by proactive_disk_check"

    # Container restart failed - restart it
    if itype == "container_restart_failed":
        container = target
        cmd = "docker restart %s" % container
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        success = r.returncode == 0
        log.info("DETERMINISTIC FIX: container_restart %s: %s", container, "OK" if success else "FAILED")
        return True, success, cmd

    # Backend unhealthy on a known Docker container port - restart the container
    if itype == "backend_unhealthy" and "Connection refused" in detail:
        port_match = re.search(r":(\d+)/", target)
        if port_match:
            port = port_match.group(1)
            container = _map_port_to_container(int(port))
            if container:
                cmd = "docker restart %s" % container
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
                if r.returncode == 0:
                    import time; time.sleep(5)
                    # Verify it came back
                    try:
                        req = urllib.request.Request(target, method="GET")
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
                        log.info("DETERMINISTIC FIX: Restarted %s for port %s - service is back", container, port)
                        return True, True, cmd
                    except Exception:
                        log.info("DETERMINISTIC FIX: Restarted %s but service still not responding", container)
                        return True, False, cmd
                return True, False, cmd

    # HTTP check failed with TLS error on localhost - this is a false positive, suppress
    if itype == "http_check_failed" and "TLSV1_ALERT" in detail:
        return True, True, "Suppressed: TLS check on localhost is expected to fail"

    # HTTP check failed for domain-based endpoints that proxy to remote hosts.
    # This host cannot fix remote services. Suppress to avoid wasting LLM calls.
    if itype == "http_check_failed" and ".wopr.systems" in target:
        domain = target.split("//")[-1].split("/")[0].split(":")[0]
        try:
            import glob
            for cf in glob.glob("/etc/caddy/sites-enabled/*.caddy"):
                if domain.replace(".wopr.systems", "") in os.path.basename(cf):
                    with open(cf, "r") as cfile:
                        cc = cfile.read()
                    if any(remote in cc for remote in ["10.0.0.3", "10.0.1.1", "10.0.0.4", "10.0.0.5"]):
                        return True, True, "Suppressed: %s proxies to remote host" % domain
                    break
        except Exception as exc:
            log.debug("Remote check detection failed for %s: %s", domain, exc)

    # Backend unhealthy for remote endpoints - cannot fix from this host
    if itype == "backend_unhealthy" and target:
        if any(remote in target for remote in ["10.0.0.3", "10.0.1.1", "10.0.0.4", "10.0.0.5"]):
            return True, True, "Suppressed: remote backend, cannot fix locally"

    # After 3 failed LLM attempts, stop wasting GPU cycles
    if itype in ("http_check_failed", "backend_unhealthy") and state:
        try:
            key = itype + "::" + target[:40]
            rstate = state.get("issues", {}) if isinstance(state, dict) else {}
            issue_hist = rstate.get(key, {})
            attempts = len(issue_hist.get("history", []))
            if attempts >= 3:
                return True, False, "Suppressed after %d failed attempts" % attempts
        except Exception:
            pass

    return False, False, ""


def remediate_issue(issue, state):
    """Attempt to remediate a single issue using deterministic rules first, then 3-tier LLM.

    Returns: (resolved, escalate_email, state_changed)
    """
    key = _issue_key(issue)
    issue_state = state["issues"].get(key, {
        "tier": 1,
        "attempt": 0,
        "history": [],
        "first_seen": datetime.now().isoformat(),
        "resolved": False,
    })

    current_tier = issue_state.get("tier", 1)
    current_attempt = issue_state.get("attempt", 0) + 1
    history = issue_state.get("history", [])

    # Already exhausted all tiers?
    if current_tier > MAX_TIER:
        return False, True, False  # needs email

    # v4.0: Try DETERMINISTIC fixes first (no LLM needed for known patterns)
    if current_attempt <= 2:
        try:
            tried, success, det_cmd = _try_deterministic_fix(issue, state)
            if tried:
                if success:
                    log.info("DETERMINISTIC FIX: Resolved %s without LLM", key[:40])
                    record_fix(issue.get("target", "?"), "deterministic_fix", det_cmd[:80], "success", "v4.0 deterministic rule")
                    # Mark resolved
                    issue_state["resolved"] = True
                    state["issues"][key] = issue_state
                    return True, False, True
                else:
                    log.info("DETERMINISTIC FIX: Failed for %s, falling through to LLM", key[:40])
                    history.append({
                        "tier": 0, "attempt": current_attempt,
                        "command": det_cmd[:200],
                        "result": "Deterministic fix failed",
                        "model": "deterministic-v4",
                    })
                    issue_state["history"] = history
                    state["issues"][key] = issue_state
        except Exception as e:
            log.warning("DETERMINISTIC FIX: Error: %s", e)

    # AUTO-LEARN: Try a previously learned fix before hitting LLM
    if current_tier == 1 and current_attempt <= 1:
        try:
            tried, success, learned_cmd = try_learned_fix(issue, state)
            if tried:
                if success:
                    log.info("LEARNED FIX: Resolved %s without LLM!", key[:40])
                    return False, False, True
                else:
                    log.info("LEARNED FIX: Known fix failed for %s, falling through to LLM", key[:40])
                    history.append({
                        "tier": 0, "attempt": 0,
                        "command": learned_cmd[:200],
                        "result": "Learned fix failed - falling through to LLM",
                        "model": "learned-fix",
                    })
                    issue_state["history"] = history
                    state["issues"][key] = issue_state
        except Exception as e:
            log.warning("LEARNED FIX: Error trying learned fix: %s", e)

    # Get model for this tier
    model = get_model_for_tier(current_tier)
    if not model:
        log.warning("REMEDIATION: No LLM model available for tier %d", current_tier)
        return False, False, False

    # Build KB context if available
    kb_context = ""
    kb_matches = match_known_issues([issue])
    if kb_matches:
        m = kb_matches[0]
        kb_context = "\nKNOWN FIX FROM KNOWLEDGE BASE: %s (Root cause: %s)" % (
            m.get("fix", ""), m.get("root_cause", ""))

    # Query LLM
    prompt = _build_remediation_prompt(issue, current_tier, current_attempt, history, kb_context)
    log.info("REMEDIATION: T%d A%d [%s] using model %s for: %s",
             current_tier, current_attempt, key[:40], model, issue.get("target", "?"))

    try:
        # Timeout scales with tier (bigger models need more time)
        timeout = 45 + (current_tier * 15)  # Faster with GPU
        response_text = _query_llm(model, prompt, timeout=timeout)

        # Parse JSON response
        cmd = ""
        explanation = ""
        risk = "unknown"
        try:
            match = re.search(r"\{.*\}", response_text, re.DOTALL)
            if match:
                parsed = json.loads(match.group())
                cmd = parsed.get("command", "").strip()
                explanation = parsed.get("explanation", "")[:200]
                risk = parsed.get("risk", "unknown")
        except Exception:
            log.warning("REMEDIATION: Failed to parse LLM response: %s", response_text[:200])

        # DEFCON-1: If LLM suggests destructive command, EMAIL IMMEDIATELY
        if risk == "destructive" or risk == "high":
            log.warning("REMEDIATION: LLM flagged risk=%s - NOT executing. Escalating to email.", risk)
            record_fix(issue.get("target", "?"), "llm_remediation",
                       "T%d refused (risk=%s): %s" % (current_tier, risk, cmd[:80]),
                       "blocked", "LLM self-reported high/destructive risk")
            issue_state["tier"] = MAX_TIER + 1  # Force email
            state["issues"][key] = issue_state
            return False, True, True

        if cmd:
            # Safety check the command
            safe, reason = is_command_safe(cmd)
            if not safe:
                log.warning("REMEDIATION: BLOCKED unsafe command: %s (reason: %s)", cmd[:80], reason)
                record_fix(issue.get("target", "?"), "llm_remediation",
                           "T%d blocked: %s" % (current_tier, cmd[:80]),
                           "blocked", reason)
                # Don't count as an attempt - just skip this response
                history.append({
                    "tier": current_tier, "attempt": current_attempt,
                    "command": cmd[:100], "result": "BLOCKED: " + reason,
                    "model": model,
                })
                issue_state["history"] = history
                issue_state["attempt"] = current_attempt
                state["issues"][key] = issue_state
                return False, False, True

            # EXECUTE THE FIX
            log.info("REMEDIATION: Executing: %s", cmd[:120])
            log.info("REMEDIATION: Explanation: %s", explanation[:120])
            try:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=60,
                )
                exec_output = (result.stdout + result.stderr)[:300]
                exec_success = result.returncode == 0

                if exec_success:
                    log.info("REMEDIATION: Command succeeded (rc=0): %s", exec_output[:100])
                else:
                    log.warning("REMEDIATION: Command failed (rc=%d): %s",
                                result.returncode, exec_output[:100])
                    # AUTO-LEARN: Remember this failed approach
                    try:
                        save_failed_approach(key, cmd,
                            "rc=%d output=%s" % (result.returncode, exec_output[:100]))
                    except Exception:
                        pass

                # Record in history
                history.append({
                    "tier": current_tier, "attempt": current_attempt,
                    "command": cmd[:200], "result": exec_output[:200],
                    "model": model, "returncode": result.returncode,
                })

                # Verify: wait a moment then re-check the issue
                # The actual verification happens on the NEXT scan cycle
                # For now, record the attempt
                record_fix(
                    issue.get("target", "?"), "llm_remediation_t%d" % current_tier,
                    cmd[:200], "executed" if exec_success else "exec_failed",
                    "rc=%d model=%s output=%s" % (result.returncode, model, exec_output[:100])
                )
                log_action("llm_remediation", issue.get("target", "?"),
                           "T%d/A%d: %s" % (current_tier, current_attempt, explanation[:80]),
                           "executed" if exec_success else "exec_failed",
                           "cmd=%s rc=%d" % (cmd[:80], result.returncode))

            except subprocess.TimeoutExpired:
                log.warning("REMEDIATION: Command timed out: %s", cmd[:80])
                history.append({
                    "tier": current_tier, "attempt": current_attempt,
                    "command": cmd[:200], "result": "TIMEOUT after 60s",
                    "model": model,
                })
                record_fix(issue.get("target", "?"), "llm_remediation_t%d" % current_tier,
                           cmd[:200], "timeout", "Command timed out after 60s")
            except Exception as e:
                log.warning("REMEDIATION: Execution error: %s", e)
                history.append({
                    "tier": current_tier, "attempt": current_attempt,
                    "command": cmd[:200], "result": "ERROR: " + str(e)[:100],
                    "model": model,
                })
        else:
            # LLM gave empty command (can't fix)
            log.info("REMEDIATION: LLM returned no command (can't fix at tier %d)", current_tier)
            history.append({
                "tier": current_tier, "attempt": current_attempt,
                "command": "", "result": "LLM returned no fix",
                "model": model,
            })

        # Update state
        issue_state["attempt"] = current_attempt
        issue_state["history"] = history

        # Check if we need to escalate to next tier
        if current_attempt >= MAX_ATTEMPTS_PER_TIER:
            next_tier = current_tier + 1
            if next_tier <= MAX_TIER:
                log.info("REMEDIATION: Tier %d exhausted (%d attempts) - escalating to Tier %d",
                         current_tier, current_attempt, next_tier)
                issue_state["tier"] = next_tier
                issue_state["attempt"] = 0
            else:
                log.warning("REMEDIATION: ALL TIERS EXHAUSTED for %s - escalating to email", key[:40])
                issue_state["tier"] = MAX_TIER + 1
                state["issues"][key] = issue_state
                return False, True, True  # needs email

        state["issues"][key] = issue_state
        return False, False, True

    except Exception as e:
        log.warning("REMEDIATION: LLM query failed: %s", e)
        history.append({
            "tier": current_tier, "attempt": current_attempt,
            "command": "", "result": "LLM error: " + str(e)[:100],
            "model": model,
        })
        issue_state["attempt"] = current_attempt
        issue_state["history"] = history
        if current_attempt >= MAX_ATTEMPTS_PER_TIER:
            next_tier = current_tier + 1
            if next_tier <= MAX_TIER:
                issue_state["tier"] = next_tier
                issue_state["attempt"] = 0
            else:
                issue_state["tier"] = MAX_TIER + 1
                state["issues"][key] = issue_state
                return False, True, True
        state["issues"][key] = issue_state
        return False, False, True


def run_3tier_remediation(issues):
    """Run the 3-tier LLM remediation engine on all unresolved issues.

    Returns list of issues that exhausted all tiers and need email alert.
    """
    if not issues:
        return []
    if not _check_ollama():
        log.info("REMEDIATION: Ollama not available - skipping LLM remediation")
        # Still do KB matching for logging
        kb_matches = match_known_issues(issues)
        if kb_matches:
            log.info("REMEDIATION: KB matched %d/%d issues (no LLM to act on them)",
                     len(kb_matches), len(issues))
        return []

    state = load_remediation_state()
    needs_email = []

    # Clean up resolved issues (not seen in this scan)
    current_keys = set(_issue_key(i) for i in issues)
    resolved_keys = []
    if "issues" not in state:
        state["issues"] = {}
    for key in list(state["issues"].keys()):
        if key not in current_keys:
            resolved_keys.append(key)
    for key in resolved_keys:
        prev = state["issues"].pop(key, {})
        if prev.get("history"):
            log.info("REMEDIATION: Issue resolved (no longer detected): %s "
                     "(was at T%d/A%d, %d total attempts)",
                     key[:40], prev.get("tier", 0), prev.get("attempt", 0),
                     len(prev.get("history", [])))
            record_fix(key, "auto_resolved", "Issue no longer detected", "success",
                       "Was at Tier %d after %d attempts" % (
                           prev.get("tier", 0), len(prev.get("history", []))))
            # AUTO-LEARN: Save the successful fix for future reuse
            try:
                save_learned_fix(key, prev)
            except Exception as e:
                log.warning("LEARNED: Failed to save fix for %s: %s", key[:40], e)

    # Skip issues that are already DEFCON-1/2 types (handled elsewhere)
    skip_types = DEFCON_1_TYPES.copy()

    # Process each issue (one attempt per issue per scan)
    for issue in issues:
        itype = issue.get("type", "")
        if itype in skip_types:
            continue

        key = _issue_key(issue)
        issue_state = state["issues"].get(key, {})

        # Already exhausted all tiers?
        if issue_state.get("tier", 1) > MAX_TIER:
            if not issue_state.get("email_sent"):
                needs_email.append(issue)
                issue_state["email_sent"] = True
                state["issues"][key] = issue_state
            continue

        resolved, escalate, changed = remediate_issue(issue, state)
        if escalate:
            needs_email.append(issue)
        elif not resolved:
            # Still being worked on by remediation engine - suppress email
            issue['_in_remediation'] = True

    save_remediation_state(state)
    return needs_email


# ========== MAIN SCAN ==========
def run_scan():
    """Execute one full scan cycle with proactive + reactive checks."""
    write_heartbeat()
    scan_start = datetime.now()
    log.info("=" * 60)
    log.info("WOPR Support Plane v%s - %s - Starting scan", VERSION, HOSTNAME)

    all_issues = []

    # ── PROACTIVE CHECKS (prevent problems) ──
    log.info("PROACTIVE: Memory pressure check...")
    all_issues.extend(proactive_memory_check())

    log.info("PROACTIVE: Disk space check...")
    all_issues.extend(proactive_disk_check())

    log.info("PROACTIVE: Process health check...")
    all_issues.extend(proactive_process_check())

    log.info("PROACTIVE: GPU health check...")
    all_issues.extend(proactive_gpu_check())

    # ── TIER 1: Service & container health ──
    log.info("TIER 1: Service & container health...")
    all_issues.extend(tier1_check_services())
    all_issues.extend(tier1_check_containers())

    # ── TIER 2: HTTP endpoint checks ──
    log.info("TIER 2: HTTP endpoint checks...")
    all_issues.extend(tier2_check_endpoints())
    # -- TIER 2.5: Application-level functional checks --
    log.info("TIER 2.5: Application-level functional checks...")
    all_issues.extend(tier2_functional_checks())


    # ── TIER 3: Log analysis ──
    log.info("TIER 3: Log analysis...")
    all_issues.extend(tier3_scan_logs())

    # ── FAILSAFE: Critical service restart (no LLM needed) ──
    # v4.1: Before LLM remediation, ensure critical services are up.
    try:
        _fs_manifest = load_manifest()
        for _fs_svc in _fs_manifest.get("services", []):
            if _fs_svc.get("critical") and _fs_svc.get("type") == "systemd":
                _fs_name = _fs_svc["name"]
                if _fs_name in NO_AUTO_RESTART:
                    continue
                _fs_check = subprocess.run(
                    ["systemctl", "is-active", _fs_name],
                    capture_output=True, text=True, timeout=10,
                )
                if _fs_check.stdout.strip() not in ("active", "activating"):
                    _fs_en = subprocess.run(
                        ["systemctl", "is-enabled", _fs_name],
                        capture_output=True, text=True, timeout=10,
                    )
                    if _fs_en.stdout.strip() in ("enabled", "static"):
                        log.warning("FAILSAFE: Critical service %s is DOWN - restarting", _fs_name)
                        _fs_r = subprocess.run(
                            ["systemctl", "restart", _fs_name],
                            capture_output=True, text=True, timeout=30,
                        )
                        if _fs_r.returncode == 0:
                            log.info("FAILSAFE: %s restarted OK", _fs_name)
                            log_action("failsafe_restart", _fs_name, "Critical service was down", "success", "v4.1 failsafe")
                        else:
                            log.error("FAILSAFE: %s restart FAILED: %s", _fs_name, _fs_r.stderr[:200])
                            log_action("failsafe_restart", _fs_name, "Critical service was down", "failed", _fs_r.stderr[:200])
    except Exception as _fs_e:
        log.warning("FAILSAFE critical service check failed: %s", _fs_e)

    # ── 3-TIER LLM REMEDIATION (v3.2) ──
    if all_issues:
        log.info("REMEDIATION: Processing %d issues through 3-tier LLM engine...", len(all_issues))
        try:
            import signal
            def _remediation_alarm(signum, frame):
                raise TimeoutError("LLM remediation timed out after 120s")
            _old_alarm = signal.signal(signal.SIGALRM, _remediation_alarm)
            signal.alarm(120)
            email_escalations = run_3tier_remediation(all_issues)
            signal.alarm(0)
            signal.signal(signal.SIGALRM, _old_alarm)
        except TimeoutError:
            log.warning("REMEDIATION: LLM remediation timed out - skipping")
            email_escalations = []
        except Exception as _rem_e:
            log.warning("REMEDIATION: LLM remediation error: %s", _rem_e)
            email_escalations = []
        if email_escalations:
            log.warning("REMEDIATION: %d issues exhausted all tiers - need email", len(email_escalations))
            for esc in email_escalations:
                # Add to DEFCON-2 so they get emailed
                esc["_escalated_from_remediation"] = True
    else:
        log.info("All systems healthy - no issues detected")

    # ── DEFCON ALERT CLASSIFICATION (v4.2 - persistent escalation) ──
    if all_issues:
        defcon1, defcon2, defcon3, defcon4 = classify_with_persistence(all_issues)

        summary_lines = []
        for i in all_issues:
            summary_lines.append("  [%s] %s: %s - %s" % (i["tier"], i["type"], i["target"], i["detail"][:100]))
        summary = "\n".join(summary_lines)
        log.warning("ISSUES (%d): DEFCON-1=%d, DEFCON-2=%d, DEFCON-3+=%d\n%s",
                     len(all_issues), len(defcon1), len(defcon2), len(defcon3), summary)

        if defcon1:
            # DEFCON-1: Email IMMEDIATELY (bypass cooldown)
            d1_lines = ["  [DEFCON-1] %s: %s - %s" % (i["type"], i["target"], i["detail"][:150]) for i in defcon1]
            try:
                import smtplib
                from email.mime.text import MIMEText
                body_text = "HOST: %s\nTIME: %s\nDEFCON: 1 - DATA LOSS RISK\n\n%s\n\nFull scan:\n%s" % (
                    HOSTNAME, scan_start.isoformat(), "\n".join(d1_lines), summary)
                msg = MIMEText(body_text)
                msg["Subject"] = "[WOPR-SP DEFCON-1] %s - %d CRITICAL" % (HOSTNAME, len(defcon1))
                msg["From"] = "support-plane@wopr.systems"
                msg["To"] = ALERT_EMAIL
                with smtplib.SMTP("localhost", 25, timeout=10) as s:
                    s.send_message(msg)
                log.info("DEFCON-1 alert sent: %d critical issues", len(defcon1))
            except Exception as e:
                log.warning("DEFCON-1 email failed: %s", e)
        elif defcon2:
            # DEFCON-2: Only email issues NOT being auto-remediated
            unremediated = [i for i in defcon2
                            if i.get('_escalated_from_remediation')
                            or not i.get('_in_remediation')]
            if unremediated:
                d2_lines = ['  [%s] %s: %s - %s' % (
                    i.get('tier','?'), i['type'], i['target'],
                    i['detail'][:100]) for i in unremediated]
                suppressed = len(defcon2) - len(unremediated)
                send_alert(
                    "DEFCON-2: %d issue(s) FAILED remediation" % len(unremediated),
                    "Host: %s\nTime: %s\nDEFCON: 2\nAuto-remediated (suppressed): %d\n\n%s" % (
                        HOSTNAME, scan_start.isoformat(), suppressed, "\n".join(d2_lines)),
                )
            else:
                log.info("DEFCON-2: %d issues all in active remediation - email suppressed", len(defcon2))
        else:
            # Check for remediation-exhausted issues that need email
            remediation_escalated = [i for i in all_issues if i.get("_escalated_from_remediation")]
            if remediation_escalated:
                esc_lines = ["  [REMEDIATION EXHAUSTED] %s: %s - %s" % (
                    i["type"], i["target"], i["detail"][:100]) for i in remediation_escalated]
                send_alert(
                    "REMEDIATION FAILED: %d issue(s) exhausted all 3 tiers" % len(remediation_escalated),
                    "Host: %s\nTime: %s\nDEFCON: 2 - All LLM remediation tiers exhausted\n\n%s\n\nFull scan:\n%s" % (
                        HOSTNAME, scan_start.isoformat(), "\n".join(esc_lines), summary),
                )
            else:
                log.info("DEFCON-3: %d transient issues tracked (will escalate if persistent)", len(defcon3))

    # ── SAVE STATE ──
    state = {
        "last_scan": scan_start.isoformat(),
        "hostname": HOSTNAME,
        "version": VERSION,
        "issues": all_issues,
        "issue_count": len(all_issues),
    }
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        log.error("Failed to save state: %s", e)

    # AUTO-LEARN: Sync proven fixes to knowledge base (hourly)
    try:
        sync_learned_to_kb()
    except Exception as e:
        log.warning("LEARNED->KB sync failed: %s", e)

    write_heartbeat()
    elapsed = (datetime.now() - scan_start).total_seconds()
    log.info("Scan complete in %.1fs - %d issues found", elapsed, len(all_issues))
    log.info("=" * 60)
    return all_issues


# ========== ENTRY POINT ==========
def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "once"
    if mode == "daemon":
        log.info("Starting WOPR Support Plane v%s in daemon mode (interval=%ds)", VERSION, CHECK_INTERVAL)
        while True:
            try:
                run_scan()
            except Exception as e:
                log.error("Scan cycle failed: %s", e)
            time.sleep(CHECK_INTERVAL)
    else:
        run_scan()


if __name__ == "__main__":
    main()
