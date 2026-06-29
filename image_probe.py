#!/usr/bin/env python3
"""WOPR image-404 prober (support-plane check).
Crawls public pages, extracts <img>/og:image/favicon URLs, checks each.
IMPORTANT: resolves via PUBLIC DNS (1.1.1.1) + curl --resolve, because this host's
local BIND is split-horizon and lacks many *.wopr.systems records (false positives
otherwise). Validates the LoveJoos MinIO pipeline. ntfy-alerts (6h per-image cooldown)."""
import re, json, os, time, subprocess
from urllib.parse import urljoin, urlparse

NTFY_URL = os.environ.get("NTFY_URL", "http://127.0.0.1:18081")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "wopr-alerts")
STATE = "/opt/wopr/support-plane/image_probe.state.json"
TIMEOUT = 15
MAX_IMAGES_PER_PAGE = 40

PAGES = [
    "https://lovejoos.com/", "https://thedudeabides.shop/", "https://wopr.foundation/",
    "https://wopr.systems/", "https://brainjoos.com/", "https://artjoos.art/",
    "https://commiesocialists.org/", "https://barterra.store/", "https://blackoutlabs.store/",
    "https://folkmoot.app/", "https://asscast.org/", "https://project2028.wopr.systems/",
    "https://powerforthepeople.party/", "https://statestreettheater.wopr.systems/",
]

_dns = {}
def pub_ip(host):
    if host in _dns: return _dns[host]
    ip = None
    try:
        out = subprocess.run(["dig", "+short", "@1.1.1.1", host], capture_output=True, text=True, timeout=8).stdout
        for line in out.splitlines():
            line = line.strip()
            if line and line[0].isdigit():
                ip = line; break
    except Exception:
        pass
    _dns[host] = ip
    return ip

def curl(url, body=False):
    """Fetch via curl using PUBLIC DNS resolution. Returns (status:int, content_type:str, body:bytes)."""
    p = urlparse(url)
    host = p.hostname or ""
    port = 443 if p.scheme == "https" else 80
    ip = pub_ip(host)
    args = ["curl", "-sL", "--max-time", str(TIMEOUT), "-A", "WOPR-image-probe/2.0",
            "-w", "\n__HTTP__%{http_code}__CT__%{content_type}"]
    if ip:
        args += ["--resolve", f"{host}:{port}:{ip}"]
    if not body:
        args += ["-o", "/dev/null"]
    args.append(url)
    try:
        r = subprocess.run(args, capture_output=True, timeout=TIMEOUT + 5)
        out = r.stdout
        m = re.search(rb"__HTTP__(\d+)__CT__([^\n]*)$", out)
        if not m:
            return 0, "", b""
        status = int(m.group(1)); ct = m.group(2).decode("utf-8", "replace")
        bod = out[:m.start()] if body else b""
        return status, ct, bod
    except Exception:
        return 0, "", b""

def extract_images(html, base):
    imgs = set()
    for pat in [r'<img[^>]+src=["\']([^"\']+)', r'<source[^>]+srcset=["\']([^"\' ]+)',
                r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]*href=["\']([^"\']+)',
                r'property=["\']og:image["\'][^>]*content=["\']([^"\']+)']:
        for m in re.finditer(pat, html, re.I):
            u = m.group(1).strip()
            if u and not u.startswith("data:"):
                imgs.add(urljoin(base, u))
    return list(imgs)[:MAX_IMAGES_PER_PAGE]

def main():
    broken = []
    for page in PAGES:
        status, _, body = curl(page, body=True)
        if status != 200:
            continue
        for img in extract_images(body.decode("utf-8", "replace"), page):
            s, ct, _ = curl(img)
            if not (s == 200 and ("image" in ct.lower() or ct == "")):
                broken.append((page, img, s or "conn-fail"))
    # lovejoos MinIO pipeline up?
    s, _, _ = curl("https://media.lovejoos.com/lovejoos-media/")
    if s not in (200, 403, 404):
        broken.append(("lovejoos media pipeline", "https://media.lovejoos.com/lovejoos-media/", s or "DOWN"))

    now = int(time.time())
    try: state = json.load(open(STATE))
    except Exception: state = {}
    fresh = [(p, i, c) for p, i, c in broken if now - state.get(i, 0) > 6 * 3600]
    for _, i, _ in fresh: state[i] = now
    state = {k: v for k, v in state.items() if now - v < 7 * 86400}
    json.dump(state, open(STATE, "w"))

    print(f"image-probe: {len(PAGES)} pages, {len(broken)} broken, {len(fresh)} new (public-DNS)")
    for p, i, c in broken: print(f"  [{c}] {i}  (on {p})")
    if fresh:
        msg = "Broken images (public edge):\n" + "\n".join(f"[{c}] {i}" for _, i, c in fresh[:15])
        try:
            import urllib.request
            urllib.request.urlopen(urllib.request.Request(f"{NTFY_URL}/{NTFY_TOPIC}", data=msg.encode(),
                headers={"Title": "WOPR image 404s", "Priority": "default"}), timeout=10)
        except Exception: pass

if __name__ == "__main__":
    main()
