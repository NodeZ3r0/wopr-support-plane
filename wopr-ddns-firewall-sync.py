#!/usr/bin/env python3
"""
WOPR Dynamic DNS Firewall Sync
===============================
Resolves wopr-home.ddns.net every run, updates UFW SSH rule if IP changed.
Run via cron every 5 minutes on all servers.

State file: /var/lib/wopr-ddns-home-ip.txt (stores last known IP)
"""
import socket
import subprocess
import sys
import os
from datetime import datetime

DDNS_HOST = "wopr-home.ddns.net"
STATE_FILE = "/var/lib/wopr-ddns-home-ip.txt"
LOG_FILE = "/var/log/wopr-ddns-sync.log"
UFW_COMMENT = "SSH wopr-home.ddns.net"
IPTABLES_COMMENT = "ddns-home-auto"
PORTS = [22, 222, 443, 80]  # Ports to allow from home IP


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
        # Keep log under 1000 lines
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
        if len(lines) > 1000:
            with open(LOG_FILE, "w") as f:
                f.writelines(lines[-500:])
    except Exception:
        pass


def resolve_ddns():
    """Resolve the DDNS hostname to current IP."""
    try:
        ip = socket.gethostbyname(DDNS_HOST)
        return ip
    except socket.gaierror as e:
        log(f"DNS resolution failed for {DDNS_HOST}: {e}")
        return None


def get_last_ip():
    """Read the last known IP from state file."""
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r") as f:
                return f.read().strip()
    except Exception:
        pass
    return None


def save_ip(ip):
    """Save current IP to state file."""
    with open(STATE_FILE, "w") as f:
        f.write(ip)


def detect_firewall():
    """Detect whether this host uses UFW or raw iptables."""
    r = subprocess.run(["which", "ufw"], capture_output=True, text=True, timeout=5)
    if r.returncode == 0:
        r2 = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5)
        if r2.returncode == 0 and "active" in r2.stdout.lower():
            return "ufw"
    return "iptables"


def remove_old_rules(old_ip):
    """Remove firewall rules for the old IP."""
    fw = detect_firewall()
    if fw == "ufw":
        _ufw_remove(old_ip)
    else:
        _iptables_remove(old_ip)


def _ufw_remove(old_ip):
    r = subprocess.run(
        ["ufw", "status", "numbered"],
        capture_output=True, text=True, timeout=10,
    )
    if r.returncode != 0:
        return
    import re
    rules_to_delete = []
    for line in r.stdout.split("\n"):
        if old_ip in line and UFW_COMMENT in line:
            m = re.search(r'\[\s*(\d+)\]', line)
            if m:
                rules_to_delete.append(int(m.group(1)))
    for num in sorted(rules_to_delete, reverse=True):
        subprocess.run(
            ["ufw", "--force", "delete", str(num)],
            capture_output=True, text=True, timeout=10,
        )
        log(f"Removed old UFW rule #{num} for {old_ip}")


def _iptables_remove(old_ip):
    for port in PORTS:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", old_ip, "-p", "tcp",
             "--dport", str(port), "-m", "comment", "--comment", IPTABLES_COMMENT,
             "-j", "ACCEPT"],
            capture_output=True, text=True, timeout=10,
        )
    log(f"Removed iptables rules for {old_ip}")
    _save_iptables()


def add_new_rules(new_ip):
    """Add firewall rules for the new IP."""
    fw = detect_firewall()
    if fw == "ufw":
        _ufw_add(new_ip)
    else:
        _iptables_add(new_ip)


def _ufw_add(new_ip):
    for port in PORTS:
        r = subprocess.run(
            ["ufw", "allow", "from", new_ip, "to", "any", "port", str(port),
             "comment", UFW_COMMENT],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            log(f"UFW: {new_ip} -> port {port}")
        else:
            log(f"UFW failed port {port}: {r.stderr.strip()}")


def _iptables_add(new_ip):
    for port in PORTS:
        # Insert at top of INPUT chain (position 1) so it's before any DROP
        r = subprocess.run(
            ["iptables", "-I", "INPUT", "1", "-s", new_ip, "-p", "tcp",
             "--dport", str(port), "-m", "comment", "--comment", IPTABLES_COMMENT,
             "-j", "ACCEPT"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            log(f"iptables: {new_ip} -> port {port}")
        else:
            log(f"iptables failed port {port}: {r.stderr.strip()}")
    _save_iptables()


def _save_iptables():
    """Persist iptables rules so they survive reboot."""
    for cmd in [
        "iptables-save > /etc/iptables/rules.v4",
        "netfilter-persistent save",
    ]:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            log(f"iptables saved via: {cmd.split()[0]}")
            return
    log("WARNING: could not persist iptables rules")


def reload_firewall():
    """Reload firewall to apply changes."""
    fw = detect_firewall()
    if fw == "ufw":
        r = subprocess.run(["ufw", "reload"], capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            log("UFW reloaded")
        else:
            log(f"UFW reload failed: {r.stderr.strip()}")
    else:
        log("iptables rules applied (no reload needed)")


def main():
    current_ip = resolve_ddns()
    if not current_ip:
        return 1

    last_ip = get_last_ip()

    if current_ip == last_ip:
        # No change, nothing to do
        return 0

    if last_ip:
        log(f"IP CHANGED: {last_ip} -> {current_ip}")
        remove_old_rules(last_ip)
    else:
        log(f"First run, setting home IP: {current_ip}")

    add_new_rules(current_ip)
    reload_firewall()
    save_ip(current_ip)

    log(f"Firewall updated for {DDNS_HOST} = {current_ip}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
