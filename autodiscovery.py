#!/usr/bin/env python3
"""
WOPR Support Plane - Universal Autodiscovery Engine v1.0
========================================================
Scans the ENTIRE host and rebuilds services-manifest.json.
Discovers everything that can fail. Leaves nothing unmonitored.
"""
import subprocess
import json
import os
import re
import socket
import sys
import glob
from datetime import datetime
from pathlib import Path

MANIFEST_FILE = "/opt/wopr/support-plane/services-manifest.json"
DISCOVERY_LOG = "/var/log/wopr-sp-autodiscovery.log"
HOSTNAME = socket.gethostname()

# Health check paths to probe when we find an HTTP port
HEALTH_PROBES = [
    "/health",
    "/api/health",
    "/ready",
    "/api/ready",
    "/status",
    "/api/status",
    "/healthz",
    "/api/v1/health",
    "/_health",
    "/",
]

# Ports that are NOT HTTP services (don't probe these)
NON_HTTP_PORTS = {
    22, 25, 53, 110, 143, 222, 389, 443, 465, 587, 631, 636, 993, 995,
    953, 1433, 1883, 2049, 2181, 2586, 3306, 4369, 5044, 5045, 5060,
    5432, 5433, 5434, 5672, 6123, 6379, 6380, 6381, 6443, 7891, 8883,
    9092, 9200, 9300, 9343, 11211, 11434, 15432, 25672, 27017,
    # Kubernetes / microk8s internal
    10250, 10257, 10259, 16443, 25000, 19001,
    # SOCKS proxies (TOR etc)
    9050, 9051,
    # Caddy admin API (404 on / is normal)
    2019,
    # Nebula VPN
    4242,
    # Wazuh
    1514, 1515, 55000,
    # MQTT
    1883, 8883,
    # DNS over TLS
    853,
    # Container runtime internals
    2375, 2376,
    # MongoDB
    27017, 27018, 27019,
    # Prometheus internal push
    9009,
    # Suricata / Zeek
    9997, 9998,
    # Netdata (responds 400 to plain HTTP)
    19999,
    # Docker internal API ports
    9443,
    # Prometheus push gateway
    9009,
    # Supervisord
    9001,
    # Flink internal
    6060,
    # Random high internal ports
    42000,
}

# Ports that are metrics/internal (monitor but low priority)
METRICS_PORTS = {
    9090, 9091, 9100, 9101, 9102, 9104, 9113, 9115, 9187,
    3100, 3200,  # Loki, Tempo
}

# Known critical services (override discovered as critical=True)
CRITICAL_SERVICES = {
    "caddy", "docker", "nebula", "crowdsec", "sshd", "ssh",
    "podman", "containerd", "systemd-resolved",
    # The money path: billing/provisioning/shop API. systemd restarts it on
    # crash, but marking it critical also lets the support-plane watchdog restart
    # it if it is ever down for another reason (WOPR-023).
    "wopr-control-plane",
}

CRITICAL_CONTAINERS = {
    "authentik-server", "authentik-worker", "authentik-postgresql",
}


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(DISCOVERY_LOG, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except Exception as e:
        return "", str(e), -1


def load_existing_manifest():
    try:
        if os.path.exists(MANIFEST_FILE):
            with open(MANIFEST_FILE) as f:
                return json.load(f)
    except Exception as e:
        log(f"WARNING: Failed to load existing manifest: {e}")
    return {}


def detect_container_runtime():
    for rt in ["docker", "podman"]:
        out, _, rc = run(f"which {rt}")
        if rc == 0:
            # Verify it's actually running
            out2, _, rc2 = run(f"{rt} info --format '{{{{.ServerVersion}}}}'")
            if rc2 == 0:
                return rt
    return None


# ========== DISCOVERY FUNCTIONS ==========

def discover_listening_ports():
    """Get all TCP ports in LISTEN state with their process info."""
    out, _, rc = run("ss -tlnpH 2>/dev/null || ss -tlnp 2>/dev/null | tail -n +2")
    ports = {}
    if rc != 0:
        return ports

    for line in out.split("\n"):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        local_addr = parts[3] if len(parts) > 3 else ""
        # Extract port
        port_match = re.search(r':(\d+)$', local_addr)
        if not port_match:
            continue
        port = int(port_match.group(1))
        # Extract process info
        proc_info = parts[-1] if len(parts) >= 6 else ""
        proc_match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', proc_info)
        process_name = proc_match.group(1) if proc_match else "unknown"
        pid = proc_match.group(2) if proc_match else "0"

        # Determine bind address
        bind = local_addr.rsplit(":", 1)[0]
        bind = bind.strip("[]")

        if port not in ports:
            ports[port] = {
                "port": port,
                "process": process_name,
                "pid": pid,
                "bind": bind,
            }
    return ports


def discover_caddy_backends():
    """Parse all Caddy site configs to find reverse proxy targets and domains."""
    backends = {}  # port -> {domain, path, backend_url}
    public_domains = {}  # domain -> list of backend ports

    caddy_dirs = [
        "/etc/caddy/sites-enabled/",
        "/etc/caddy/sites/",
        "/etc/caddy/conf.d/",
    ]

    for caddy_dir in caddy_dirs:
        if not os.path.isdir(caddy_dir):
            continue
        for fpath in sorted(glob.glob(os.path.join(caddy_dir, "*.caddy"))):
            try:
                with open(fpath) as f:
                    content = f.read()
            except Exception:
                continue

            fname = os.path.basename(fpath)

            # Skip fully-commented configs (all non-empty lines start with #)
            active_lines = [l.strip() for l in content.split("\n") if l.strip() and not l.strip().startswith("#")]
            if not active_lines:
                continue

            # Extract domain from first active line or filename
            domain = None
            for line in active_lines:
                if not line.startswith("{"):
                    # Could be "domain.com {" or "domain.com:443 {"
                    dm = re.match(r'^([\w.-]+\.[\w]+)', line)
                    if dm:
                        domain = dm.group(1)
                    break

            if not domain:
                domain = fname.replace(".caddy", "")

            # Skip domains that aren't real FQDNs
            if "." not in domain or domain.count(".") < 1:
                continue

            # Find all reverse_proxy directives
            for match in re.finditer(r'reverse_proxy\s+([\w.:/-]+)', content):
                target = match.group(1)
                port_match = re.search(r':(\d+)', target)
                if port_match:
                    port = int(port_match.group(1))
                    backends[port] = {
                        "domain": domain,
                        "target": target,
                        "caddy_file": fpath,
                    }
                    if domain not in public_domains:
                        public_domains[domain] = []
                    if port not in public_domains[domain]:
                        public_domains[domain].append(port)

    return backends, public_domains


def discover_containers(runtime):
    """Get all containers with their port mappings and status."""
    out, _, rc = run(f"{runtime} ps -a --format '{{{{.Names}}}}\\t{{{{.Status}}}}\\t{{{{.Image}}}}\\t{{{{.Ports}}}}'")
    containers = []
    if rc != 0:
        return containers

    for line in out.split("\n"):
        if not line.strip():
            continue
        parts = line.split("\t")
        name = parts[0] if len(parts) > 0 else "?"
        status = parts[1] if len(parts) > 1 else "?"
        image = parts[2] if len(parts) > 2 else "?"
        ports_str = parts[3] if len(parts) > 3 else ""

        # Extract port mappings
        port_maps = []
        for pm in re.finditer(r'(?:[\d.]+:)?(\d+)->(\d+)', ports_str):
            port_maps.append({
                "host": int(pm.group(1)),
                "container": int(pm.group(2)),
            })

        containers.append({
            "name": name,
            "status": status,
            "image": image,
            "running": "Up" in status,
            "healthy": "(unhealthy)" not in status,
            "ports": port_maps,
        })
    return containers


def discover_systemd_services():
    """Get ALL loaded systemd services, not just wopr-* prefixed ones."""
    out, _, rc = run("systemctl list-units --type=service --all --no-legend --no-pager")
    services = []
    if rc != 0:
        return services

    for line in out.split("\n"):
        parts = line.split()
        if not parts:
            continue
        name = parts[0].replace(".service", "")
        loaded = parts[1] if len(parts) > 1 else "unknown"
        active = parts[2] if len(parts) > 2 else "unknown"
        sub = parts[3] if len(parts) > 3 else "unknown"

        if loaded == "not-found":
            continue

        # Skip kernel/system internals that aren't monitorable
        skip_prefixes = (
            "systemd-", "dbus", "getty@", "serial-getty@", "user@",
            "modprobe@", "kmod-static-nodes", "ldconfig",
            "plymouth", "initrd-", "emergency", "rescue",
            "rc-local", "console-", "keyboard-",
        )
        if any(name.startswith(p) for p in skip_prefixes):
            continue

        # Skip oneshot services that ran and exited successfully
        if active == "inactive" and sub == "dead":
            # Check if it's a oneshot that's supposed to be dead
            type_out, _, _ = run(f"systemctl show {name} --property=Type --value")
            if type_out.strip() == "oneshot":
                continue

        services.append({
            "name": name,
            "type": "systemd",
            "active": active,
            "sub": sub,
            "critical": name in CRITICAL_SERVICES,
        })
    return services


def discover_systemd_timers():
    """Get all systemd timers."""
    out, _, rc = run("systemctl list-timers --all --no-legend --no-pager")
    timers = []
    if rc != 0:
        return timers

    for line in out.split("\n"):
        if not line.strip():
            continue
        # Timer lines have: NEXT LEFT LAST PASSED UNIT ACTIVATES
        parts = line.rsplit(None, 2)
        if len(parts) >= 2:
            timer_name = parts[-2] if parts[-2].endswith(".timer") else None
            service_name = parts[-1] if parts[-1].endswith(".service") else None
            if timer_name and service_name:
                timers.append({
                    "timer": timer_name,
                    "service": service_name.replace(".service", ""),
                })
    return timers


def discover_crontabs():
    """Get all cron jobs from all users + /etc/cron.*."""
    crons = []

    # Root crontab
    out, _, rc = run("crontab -l 2>/dev/null")
    if rc == 0 and out:
        for line in out.split("\n"):
            line = line.strip().replace("\r", "")
            if not line or line.startswith("#"):
                continue
            crons.append({"user": "root", "schedule": line[:30], "command": line, "source": "crontab"})

    # Other user crontabs
    out, _, _ = run("ls /var/spool/cron/crontabs/ 2>/dev/null")
    if out:
        for user in out.split("\n"):
            user = user.strip()
            if not user or user == "root":
                continue
            uout, _, urc = run(f"crontab -u {user} -l 2>/dev/null")
            if urc == 0 and uout:
                for line in uout.split("\n"):
                    line = line.strip().replace("\r", "")
                    if not line or line.startswith("#"):
                        continue
                    crons.append({"user": user, "schedule": line[:30], "command": line, "source": "crontab"})

    # System cron directories
    for cron_dir in ["/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/"]:
        if os.path.isdir(cron_dir):
            for fname in os.listdir(cron_dir):
                fpath = os.path.join(cron_dir, fname)
                if os.path.isfile(fpath):
                    try:
                        with open(fpath) as f:
                            content = f.read()
                        for line in content.split("\n"):
                            line = line.strip()
                            if not line or line.startswith("#") or line.startswith("SHELL") or line.startswith("PATH") or line.startswith("MAILTO"):
                                continue
                            if re.match(r'^[\d*/,-]+\s', line) or cron_dir.endswith("daily/") or cron_dir.endswith("hourly/"):
                                crons.append({"user": "system", "schedule": line[:30], "command": line, "source": fpath})
                    except Exception:
                        pass
    return crons


def discover_network():
    """Discover network interfaces, Nebula mesh, and routes."""
    interfaces = []

    out, _, rc = run("ip -j addr show 2>/dev/null")
    if rc == 0 and out:
        try:
            ifaces = json.loads(out)
            for iface in ifaces:
                name = iface.get("ifname", "")
                if name == "lo":
                    continue
                addrs = []
                for ai in iface.get("addr_info", []):
                    if ai.get("family") == "inet":
                        addrs.append(ai.get("local", ""))
                interfaces.append({
                    "name": name,
                    "state": iface.get("operstate", "unknown"),
                    "addresses": addrs,
                    "is_nebula": name.startswith("nebula") or name.startswith("wg"),
                    "is_docker": name.startswith("docker") or name.startswith("br-") or name.startswith("veth"),
                })
        except json.JSONDecodeError:
            pass

    # Nebula status
    nebula_ok = False
    out, _, rc = run("systemctl is-active nebula 2>/dev/null")
    if out.strip() == "active":
        nebula_ok = True

    return interfaces, nebula_ok


def discover_compose_projects(runtime):
    """Find docker-compose/compose.yml projects."""
    projects = []
    search_dirs = ["/opt/", "/srv/", "/home/"]

    for sdir in search_dirs:
        if not os.path.isdir(sdir):
            continue
        for root, dirs, files in os.walk(sdir):
            # Don't descend too deep
            depth = root.replace(sdir, "").count(os.sep)
            if depth > 3:
                dirs.clear()
                continue
            for fname in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
                if fname in files:
                    projects.append({
                        "path": os.path.join(root, fname),
                        "directory": root,
                        "name": os.path.basename(root),
                    })
                    break
    return projects


def probe_http_port(port, bind="127.0.0.1", timeout=3):
    """Try to find a working health endpoint on an HTTP port."""
    import urllib.request
    import urllib.error
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for path in HEALTH_PROBES:
        url = f"http://{bind}:{port}{path}"
        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", "WOPR-SP-Autodiscovery/1.0")
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            status = resp.getcode()
            if status in (200, 301, 302, 403):
                return {"url": url, "status": status, "path": path}
        except urllib.error.HTTPError as e:
            if e.code in (401, 403, 405):
                return {"url": url, "status": e.code, "path": path}
        except Exception:
            if path == "/":
                # If even / fails with connection, port isn't HTTP
                return None
            continue
    # Try root as last resort with any response
    url = f"http://{bind}:{port}/"
    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "WOPR-SP-Autodiscovery/1.0")
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return {"url": url, "status": resp.getcode(), "path": "/"}
    except urllib.error.HTTPError as e:
        return {"url": url, "status": e.code, "path": "/"}
    except Exception:
        return None


def map_port_to_container(port, containers):
    """Find which container owns a port."""
    for c in containers:
        for pm in c.get("ports", []):
            if pm["host"] == port:
                return c["name"]
    return None


def map_port_to_service(port, listen_ports):
    """Get service name from listening port info."""
    info = listen_ports.get(port, {})
    proc = info.get("process", "unknown")
    if proc in ("docker-proxy", "containerd-shim", "podman"):
        return None  # Container port, will be mapped separately
    return proc


# ========== MANIFEST BUILDER ==========

def build_manifest(runtime):
    """Run all discovery and build comprehensive manifest."""
    log(f"Starting full host discovery on {HOSTNAME}...")
    existing = load_existing_manifest()

    # Build lookup of existing pinned/customized entries
    existing_backends = {}
    for ep in existing.get("http_endpoints", {}).get("backend", []):
        existing_backends[ep.get("name", ep.get("url", ""))] = ep
    existing_publics = {}
    for ep in existing.get("http_endpoints", {}).get("public", []):
        existing_publics[ep.get("name", ep.get("url", ""))] = ep
    existing_svcs = {}
    for s in existing.get("services", []):
        existing_svcs[s.get("name", "")] = s
    existing_containers_map = {}
    for c in existing.get("containers", []):
        existing_containers_map[c.get("name", "")] = c

    # Run all discoveries
    log("Discovering listening ports...")
    listen_ports = discover_listening_ports()
    log(f"  Found {len(listen_ports)} listening TCP ports")

    log("Discovering Caddy backends...")
    caddy_backends, caddy_domains = discover_caddy_backends()
    log(f"  Found {len(caddy_backends)} backend ports, {len(caddy_domains)} public domains")

    log("Discovering containers...")
    containers = discover_containers(runtime) if runtime else []
    log(f"  Found {len(containers)} containers")

    log("Discovering systemd services...")
    services = discover_systemd_services()
    log(f"  Found {len(services)} services")

    log("Discovering timers...")
    timers = discover_systemd_timers()
    log(f"  Found {len(timers)} timers")

    log("Discovering cron jobs...")
    crons = discover_crontabs()
    log(f"  Found {len(crons)} cron entries")

    log("Discovering compose projects...")
    compose_projects = discover_compose_projects(runtime) if runtime else []
    log(f"  Found {len(compose_projects)} compose projects")

    log("Discovering network...")
    interfaces, nebula_ok = discover_network()
    log(f"  Found {len(interfaces)} interfaces, Nebula: {'OK' if nebula_ok else 'DOWN'}")

    # ===== BUILD HTTP ENDPOINTS =====
    log("Probing HTTP endpoints...")
    backend_endpoints = []
    public_endpoints = []
    seen_backend_urls = set()

    # 1. Caddy-backed services get public + backend entries
    for domain, ports in caddy_domains.items():
        # Public endpoint
        pub_url = f"https://{domain}/"
        pub_name = domain.replace(".wopr.systems", "").replace(".org", "").replace(".us", "").replace(".", "-")

        # Check if pinned in existing
        pub_existing = existing_publics.get(pub_name, existing_publics.get(pub_url, {}))
        # Accept 400 and 404 for public endpoints too — many APIs/websocket services return these on /
        public_endpoints.append({
            "url": pub_url,
            "name": pub_name,
            "expected_status": pub_existing.get("expected_status", [200, 301, 302, 400, 403, 404]),
            "critical": pub_existing.get("critical", False),
            **({"pinned": True} if pub_existing.get("pinned") else {}),
        })

        # Backend endpoints for each port behind this domain
        for port in ports:
            caddy_info = caddy_backends.get(port, {})
            target = caddy_info.get("target", f"127.0.0.1:{port}")
            bind = "127.0.0.1"
            if "10.0." in target:
                bind = re.search(r'(10\.0\.\d+\.\d+)', target).group(1)

            # Probe to find best health endpoint
            probe = probe_http_port(port, bind, timeout=3)
            if probe:
                url = probe["url"]
            else:
                url = f"http://{bind}:{port}/"

            if url in seen_backend_urls:
                continue
            seen_backend_urls.add(url)

            # Name: use domain-based name
            be_name = f"{pub_name}-backend"
            if len(ports) > 1:
                be_name = f"{pub_name}-{port}"

            container_name = map_port_to_container(port, containers)
            be_existing = None
            for ek, ev in existing_backends.items():
                if f":{port}" in ev.get("url", "") or ek == be_name:
                    be_existing = ev
                    break

            expected = [200]
            if probe and probe["status"] in (301, 302):
                expected = [200, 301, 302]
            elif probe and probe["status"] in (401, 403):
                expected = [200, 401, 403]
            elif probe and probe["status"] == 404:
                expected = [200, 404]
            if be_existing:
                expected = be_existing.get("expected_status", expected)

            ep = {
                "url": url,
                "name": be_name,
                "expected_status": expected,
                "critical": be_existing.get("critical", False) if be_existing else False,
                "discovered_via": "caddy",
            }
            if container_name:
                ep["container"] = container_name
            if "10.0." in bind:
                ep["remote"] = True
            if be_existing and be_existing.get("pinned"):
                ep["pinned"] = True
                if be_existing.get("url"):
                    ep["url"] = be_existing["url"]

            backend_endpoints.append(ep)

    # 2. Non-Caddy listening ports that respond to HTTP
    for port, info in sorted(listen_ports.items()):
        if port in NON_HTTP_PORTS:
            continue
        if port in (80, 443):
            continue  # Caddy itself
        if port in caddy_backends:
            continue  # Already covered above

        # Skip if bind is a container bridge only
        bind = info.get("bind", "0.0.0.0")
        if bind.startswith("172.") or bind.startswith("fd"):
            continue

        # Skip non-service host processes that bind many ephemeral ports (noise)
        if info.get("process", "") in ("rygel", "containerd", "forgejo-runner", "mongod"):
            continue

        probe_bind = "127.0.0.1" if bind in ("0.0.0.0", "*", "::") else bind
        probe = probe_http_port(port, probe_bind, timeout=2)
        if not probe:
            continue

        url = probe["url"]
        if url in seen_backend_urls:
            continue
        seen_backend_urls.add(url)

        proc = info.get("process", "unknown")
        container_name = map_port_to_container(port, containers)
        svc_name = container_name or proc

        be_name = f"{svc_name}-{port}"
        be_existing = None
        for ek, ev in existing_backends.items():
            if f":{port}" in ev.get("url", "") or ek == be_name:
                be_existing = ev
                break

        expected = [200]
        if probe["status"] in (301, 302):
            expected = [200, 301, 302]
        elif probe["status"] in (401, 403):
            expected = [200, 401, 403]
        elif probe["status"] == 404:
            expected = [200, 404]
        elif probe["status"] and probe["status"] not in (502, 503, 504):
            # Stable non-5xx response => process is alive (e.g. 400 streaming/HTTPS
            # port, 405/501 POST-only handler); accept it instead of false-alerting.
            expected = [200, probe["status"]]
        if be_existing:
            expected = be_existing.get("expected_status", expected)

        ep = {
            "url": url,
            "name": be_name,
            "expected_status": expected,
            "critical": be_existing.get("critical", False) if be_existing else False,
            "discovered_via": "port_scan",
        }
        if container_name:
            ep["container"] = container_name
        if be_existing and be_existing.get("pinned"):
            ep["pinned"] = True
            if be_existing.get("url"):
                ep["url"] = be_existing["url"]

        backend_endpoints.append(ep)

    log(f"  Discovered {len(public_endpoints)} public + {len(backend_endpoints)} backend endpoints")

    # ===== BUILD SERVICES LIST =====
    svc_list = []
    seen_svc = set()
    for svc in services:
        name = svc["name"]
        if name in seen_svc:
            continue
        seen_svc.add(name)

        ex = existing_svcs.get(name, {})
        svc_list.append({
            "name": name,
            "type": "systemd",
            "critical": ex.get("critical", svc.get("critical", name in CRITICAL_SERVICES)),
            **({"pinned": True} if ex.get("pinned") else {}),
        })

    # ===== BUILD CONTAINERS LIST =====
    container_list = []
    for c in containers:
        name = c["name"]
        ex = existing_containers_map.get(name, {})
        container_list.append({
            "name": name,
            "image": c.get("image", "?"),
            "critical": ex.get("critical", name in CRITICAL_CONTAINERS),
            **({"depends_on": ex["depends_on"]} if ex.get("depends_on") else {}),
            **({"pinned": True} if ex.get("pinned") else {}),
        })

    # ===== BUILD TIMERS LIST =====
    timer_list = []
    for t in timers:
        timer_list.append({
            "timer": t["timer"],
            "service": t["service"],
        })

    # ===== BUILD CRON LIST =====
    cron_list = []
    for c in crons:
        cron_list.append({
            "user": c["user"],
            "command": c["command"][:200],
            "source": c.get("source", "crontab"),
        })

    # ===== BUILD NETWORK =====
    net_info = {
        "interfaces": [
            {
                "name": i["name"],
                "state": i["state"],
                "addresses": i["addresses"],
                "type": "nebula" if i["is_nebula"] else ("docker" if i["is_docker"] else "physical"),
            }
            for i in interfaces if not i["is_docker"]  # Skip docker bridge noise
        ],
        "nebula_active": nebula_ok,
    }

    # ===== BUILD COMPOSE PROJECTS =====
    compose_list = []
    for p in compose_projects:
        compose_list.append({
            "name": p["name"],
            "path": p["path"],
            "directory": p["directory"],
        })

    # ===== ASSEMBLE MANIFEST =====
    manifest = {
        "version": "5.0-autodiscovery",
        "host": HOSTNAME,
        "generated": datetime.now().isoformat(),
        "container_runtime": runtime or "none",
        "autodiscovery": True,
        "services": svc_list,
        "containers": container_list,
        "http_endpoints": {
            "public": public_endpoints,
            "backend": backend_endpoints,
        },
        "timers": timer_list,
        "cron_jobs": cron_list,
        "network": net_info,
        "compose_projects": compose_list,
        "discovery_stats": {
            "listening_ports": len(listen_ports),
            "caddy_backends": len(caddy_backends),
            "containers_total": len(containers),
            "services_total": len(svc_list),
            "timers_total": len(timer_list),
            "cron_jobs_total": len(cron_list),
            "compose_projects": len(compose_list),
            "public_endpoints": len(public_endpoints),
            "backend_endpoints": len(backend_endpoints),
        },
    }

    return manifest


def write_manifest(manifest):
    """Write manifest with backup."""
    # Backup existing
    if os.path.exists(MANIFEST_FILE):
        backup = MANIFEST_FILE + ".pre-autodiscovery"
        try:
            import shutil
            shutil.copy2(MANIFEST_FILE, backup)
        except Exception:
            pass

    # Write new
    tmp = MANIFEST_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(manifest, f, indent=2)
    os.rename(tmp, MANIFEST_FILE)


def main():
    log("=" * 60)
    log(f"WOPR SP Autodiscovery v1.0 - {HOSTNAME}")
    log("=" * 60)

    runtime = detect_container_runtime()
    log(f"Container runtime: {runtime or 'none'}")

    manifest = build_manifest(runtime)

    stats = manifest.get("discovery_stats", {})
    log(f"Discovery complete:")
    log(f"  Services: {stats.get('services_total', 0)}")
    log(f"  Containers: {stats.get('containers_total', 0)}")
    log(f"  Listening ports: {stats.get('listening_ports', 0)}")
    log(f"  Caddy backends: {stats.get('caddy_backends', 0)}")
    log(f"  Public endpoints: {stats.get('public_endpoints', 0)}")
    log(f"  Backend endpoints: {stats.get('backend_endpoints', 0)}")
    log(f"  Timers: {stats.get('timers_total', 0)}")
    log(f"  Cron jobs: {stats.get('cron_jobs_total', 0)}")
    log(f"  Compose projects: {stats.get('compose_projects', 0)}")

    write_manifest(manifest)
    log(f"Manifest written to {MANIFEST_FILE}")
    log("=" * 60)


if __name__ == "__main__":
    main()
