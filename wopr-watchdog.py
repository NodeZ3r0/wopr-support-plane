#!/usr/bin/env python3
"""WOPR Support Plane Watchdog v4.0 - Checks heartbeat AND critical services.

Runs every 5 min via systemd timer.
If SP heartbeat is stale (>15min), restarts the SP.
ALSO checks all critical manifest services and restarts them if down.
This is the last line of defense - works independently of SP.
"""
import json
import logging
import os
import subprocess
import time
from datetime import datetime, timedelta

HEARTBEAT_FILE = "/var/lib/wopr-support-plane-heartbeat"
SP_SERVICE = "wopr-support-plane.service"
MANIFEST_FILE = "/opt/wopr/support-plane/services-manifest.json"
LOG_FILE = "/var/log/wopr-watchdog.log"
MAX_HEARTBEAT_AGE_SECONDS = 900  # 15 min

NO_AUTO_RESTART = {
    "sshd", "ssh", "nebula", "systemd-journald", "systemd-logind",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [WATCHDOG] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)
log = logging.getLogger("watchdog")


def check_heartbeat():
    if not os.path.exists(HEARTBEAT_FILE):
        log.warning("No heartbeat file - restarting support plane")
        restart_service(SP_SERVICE, "no heartbeat file")
        return False
    try:
        with open(HEARTBEAT_FILE) as f:
            data = json.load(f)
        ts = datetime.fromisoformat(data["ts"])
        age = (datetime.now() - ts).total_seconds()
        if age > MAX_HEARTBEAT_AGE_SECONDS:
            log.warning("Heartbeat stale (%ds old) - restarting support plane", int(age))
            restart_service(SP_SERVICE, "stale heartbeat (%ds)" % int(age))
            return False
        log.info("Heartbeat OK (%ds old, v%s)", int(age), data.get("version", "?"))
        return True
    except Exception as e:
        log.error("Heartbeat read error: %s - restarting support plane", e)
        restart_service(SP_SERVICE, "heartbeat read error")
        return False


def restart_service(name, reason):
    log.warning("Restarting %s: %s", name, reason)
    r = subprocess.run(
        ["systemctl", "restart", name],
        capture_output=True, text=True, timeout=30,
    )
    if r.returncode == 0:
        log.info("%s restarted OK", name)
    else:
        log.error("%s restart failed: %s", name, r.stderr[:200])


def check_critical_services():
    """Check all critical services from manifest and restart if down."""
    if not os.path.exists(MANIFEST_FILE):
        log.info("No manifest file - skipping critical service check")
        return

    try:
        with open(MANIFEST_FILE) as f:
            manifest = json.load(f)
    except Exception as e:
        log.error("Failed to read manifest: %s", e)
        return

    fixed = 0
    for svc in manifest.get("services", []):
        if not svc.get("critical"):
            continue
        if svc.get("type") != "systemd":
            continue
        name = svc["name"]
        if name in NO_AUTO_RESTART:
            continue

        try:
            r = subprocess.run(
                ["systemctl", "is-active", name],
                capture_output=True, text=True, timeout=10,
            )
            status = r.stdout.strip()
            if status in ("active", "activating"):
                continue

            en = subprocess.run(
                ["systemctl", "is-enabled", name],
                capture_output=True, text=True, timeout=10,
            )
            if en.stdout.strip() not in ("enabled", "static"):
                continue

            timer_check = subprocess.run(
                ["systemctl", "is-enabled", "%s.timer" % name],
                capture_output=True, text=True, timeout=10,
            )
            if timer_check.stdout.strip() == "enabled":
                continue

            log.warning("CRITICAL SERVICE DOWN: %s (%s) - restarting", name, status)
            restart_service(name, "critical service down (%s)" % status)
            fixed += 1

        except Exception as e:
            log.error("Failed to check %s: %s", name, e)

    if fixed:
        log.info("Restarted %d critical services", fixed)


def check_critical_containers():
    """Check critical containers from manifest and restart if down."""
    if not os.path.exists(MANIFEST_FILE):
        return

    try:
        with open(MANIFEST_FILE) as f:
            manifest = json.load(f)
    except Exception:
        return

    runtime = "docker" if os.path.exists("/usr/bin/docker") else "podman" if os.path.exists("/usr/bin/podman") else None
    if not runtime:
        return

    for ctr in manifest.get("containers", []):
        if not ctr.get("critical"):
            continue
        name = ctr["name"]
        try:
            r = subprocess.run(
                [runtime, "inspect", "--format", "{{.State.Running}}", name],
                capture_output=True, text=True, timeout=10,
            )
            if "true" not in r.stdout.lower():
                log.warning("CRITICAL CONTAINER DOWN: %s - restarting", name)
                subprocess.run(
                    [runtime, "restart", name],
                    capture_output=True, text=True, timeout=60,
                )
                log.info("Container %s restart issued", name)
        except Exception as e:
            log.error("Failed to check container %s: %s", name, e)


def check_disk():
    try:
        r = subprocess.run(
            ["df", "-h", "--output=pcent,target"],
            capture_output=True, text=True, timeout=10,
        )
        for line in r.stdout.strip().split("\n")[1:]:
            parts = line.split()
            if len(parts) >= 2:
                pct = int(parts[0].replace("%", ""))
                if pct >= 90:
                    log.warning("DISK: %s at %d%%", parts[1], pct)
    except Exception:
        pass


def check_memory():
    try:
        with open("/proc/meminfo") as f:
            meminfo = f.read()
        total = int([l for l in meminfo.split("\n") if l.startswith("MemTotal")][0].split()[1])
        available = int([l for l in meminfo.split("\n") if l.startswith("MemAvailable")][0].split()[1])
        used_pct = int(100 * (total - available) / total)
        if used_pct >= 95:
            log.warning("MEMORY: %d%% used - dropping caches", used_pct)
            subprocess.run(
                ["bash", "-c", "sync && echo 3 > /proc/sys/vm/drop_caches"],
                timeout=10,
            )
        else:
            log.info("Memory OK (%d%%)", used_pct)
    except Exception:
        pass


if __name__ == "__main__":
    log.info("=" * 40)
    log.info("WOPR Watchdog v4.0 check starting")
    check_heartbeat()
    check_critical_services()
    check_critical_containers()
    check_disk()
    check_memory()
    log.info("Watchdog v4.0 check complete")
    log.info("=" * 40)
