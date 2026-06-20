#!/usr/bin/env python3
"""WOPR Failsafe v1.0 - Absolute last line of defense.

Runs every 2 min via cron. Zero dependencies on SP or watchdog.
Checks: Is the SP running? Are critical services up? Is the watchdog timer active?
If anything is wrong, fixes it. No LLM, no complex logic.

Install: echo "*/2 * * * * root /usr/bin/python3 /opt/wopr/support-plane/wopr-failsafe.py >> /var/log/wopr-failsafe.log 2>&1" > /etc/cron.d/wopr-failsafe
"""
import json
import os
import subprocess
import sys
from datetime import datetime

MANIFEST_FILE = "/opt/wopr/support-plane/services-manifest.json"
LOG_PREFIX = datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " [FAILSAFE]"

NO_AUTO_RESTART = {"sshd", "ssh", "nebula", "systemd-journald", "systemd-logind"}


def log(msg):
    print("%s %s" % (LOG_PREFIX, msg), flush=True)


def is_active(service):
    try:
        r = subprocess.run(
            ["systemctl", "is-active", service],
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout.strip() == "active"
    except Exception:
        return False


def is_enabled(service):
    try:
        r = subprocess.run(
            ["systemctl", "is-enabled", service],
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout.strip() in ("enabled", "static")
    except Exception:
        return False


def restart(service):
    log("Restarting %s" % service)
    try:
        r = subprocess.run(
            ["systemctl", "restart", service],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode == 0:
            log("  %s restarted OK" % service)
        else:
            log("  %s restart FAILED: %s" % (service, r.stderr[:150]))
    except Exception as e:
        log("  %s restart ERROR: %s" % (service, e))


def main():
    fixed = 0

    # 1. Is the support plane running?
    if not is_active("wopr-support-plane") and is_enabled("wopr-support-plane"):
        log("Support plane is DOWN")
        restart("wopr-support-plane")
        fixed += 1

    # 2. Is the watchdog timer running?
    if not is_active("wopr-sp-watchdog.timer"):
        log("Watchdog timer is DOWN")
        try:
            subprocess.run(["systemctl", "start", "wopr-sp-watchdog.timer"], timeout=10)
        except Exception:
            pass
        fixed += 1

    # 3. Check critical manifest services
    if os.path.exists(MANIFEST_FILE):
        try:
            with open(MANIFEST_FILE) as f:
                manifest = json.load(f)
            for svc in manifest.get("services", []):
                if not svc.get("critical") or svc.get("type") != "systemd":
                    continue
                name = svc["name"]
                if name in NO_AUTO_RESTART:
                    continue
                try:
                    if not is_active(name) and is_enabled(name):
                        # Check if timer-activated
                        try:
                            timer = subprocess.run(
                                ["systemctl", "is-enabled", "%s.timer" % name],
                                capture_output=True, text=True, timeout=10,
                            )
                            if timer.stdout.strip() == "enabled":
                                continue
                        except Exception:
                            pass
                        log("Critical service %s is DOWN" % name)
                        restart(name)
                        fixed += 1
                except Exception:
                    pass
        except Exception as e:
            log("Manifest read failed: %s" % e)

    if fixed:
        log("Fixed %d issues" % fixed)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log("FATAL: %s" % e)
