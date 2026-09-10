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
    """All public A records, comma-joined for curl --resolve, so a single bad
    Cloudflare edge IP cannot fail the check (curl falls back to the others)."""
    if host in _dns: return _dns[host]
    ips = []
    try:
        out = subprocess.run(["dig", "+short", "@1.1.1.1", host], capture_output=True, text=True, timeout=8).stdout
        for line in out.splitlines():
            line = line.strip()
            if line and line[0].isdigit():
                ips.append(line)
    except Exception:
        pass
    val = ",".join(ips) if ips else None
    _dns[host] = val
    return val

CURL_ERR = {6: "dns-fail", 7: "connect-refused", 16: "http2-error", 28: "timeout",
            35: "tls-handshake", 52: "empty-reply", 56: "recv-error", 92: "http2-stream"}
_last_err = {}

def curl(url, body=False, attempts=3):
    """Fetch via curl using PUBLIC DNS resolution. Returns (status:int, content_type:str, body:bytes).
    Retries ONLY on hard connection failure (status 0) - a real 404/500 is returned immediately.
    Records WHY the last attempt failed in _last_err so the alert can name the fault."""
    rc = None
    for i in range(attempts):
        st, ct, bod, rc = _curl_once(url, body)
        if st != 0:
            _last_err.pop(url, None)
            return st, ct, bod
        if i < attempts - 1:
            time.sleep(2 * (i + 1))
    _last_err[url] = CURL_ERR.get(rc, f"curl{rc}")
    return 0, "", b""

def _curl_once(url, body=False):
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
            return 0, "", b"", r.returncode
        status = int(m.group(1)); ct = m.group(2).decode("utf-8", "replace")
        bod = out[:m.start()] if body else b""
        return status, ct, bod, r.returncode
    except subprocess.TimeoutExpired:
        return 0, "", b"", 28
    except Exception:
        return 0, "", b"", None

IMG_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".avif", ".bmp")
GENERIC_CT = ("application/octet-stream", "binary/octet-stream", "application/binary")

def is_image_ct(ct, url):
    """A CDN may serve a real image as a generic binary type; only trust that
    when the URL itself is clearly an image, so a genuine HTML error page still fails."""
    ct = (ct or "").split(";")[0].strip().lower()
    if ct == "" or "image" in ct:
        return True
    path = urlparse(url).path.lower()
    return ct in GENERIC_CT and path.endswith(IMG_EXT)

LOCAL_EDGE = os.environ.get("LOCAL_EDGE", "http://127.0.0.1:18080")

def _local(host, path):
    """One request to THIS rig's Caddy with a spoofed Host header. -> (status, content_type)"""
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "8", "-o", "/dev/null", "-H", f"Host: {host}",
             "-w", "%{http_code} %{content_type}", LOCAL_EDGE + path],
            capture_output=True, timeout=12)
        parts = r.stdout.decode("utf-8", "replace").strip().split(" ", 1)
        code = parts[0]
        return (int(code) if code.isdigit() else 0), (parts[1] if len(parts) > 1 else "")
    except Exception:
        return 0, ""

def origin_check(url):
    """Bypass Cloudflare and ask this rig directly, so an opaque failure becomes
    'edge broke' vs 'origin broke'. Returns (verdict, detail).
    Guards against two traps: a host this rig does not serve at all, and an SPA
    that answers 200 text/html for a missing image."""
    p = urlparse(url)
    host = p.hostname
    if not host:
        return "unknown", "no host"
    root_st, _ = _local(host, "/")
    if not (200 <= root_st < 400):
        return "not-served-here", f"rig returns {root_st or 'nothing'} for /"
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    st, ct = _local(host, path)
    if 200 <= st < 400 and is_image_ct(ct, url):
        return "origin-ok", str(st)
    if 200 <= st < 400:
        return "origin-bad", f"{st} but {ct or 'no content-type'} (SPA fallback, image missing)"
    return "origin-bad", str(st or "no response")

def classify(url, code):
    """Human-readable cause for one broken image."""
    why = _last_err.get(url)
    label = f"{code}" + (f"/{why}" if why else "")
    verdict, detail = origin_check(url)
    if verdict == "origin-ok":
        return f"{label}, ORIGIN OK ({detail}) -> EDGE/Cloudflare fault"
    if verdict == "origin-bad":
        return f"{label}, ORIGIN BAD ({detail}) -> fix the site"
    if verdict == "not-served-here":
        return f"{label}, origin not on this rig ({detail})"
    return label

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
            if not (s == 200 and is_image_ct(ct, img)):
                broken.append((page, img, classify(img, s or "conn-fail")))
    # lovejoos MinIO pipeline up?
    MEDIA = "https://media.lovejoos.com/lovejoos-media/"
    s, _, _ = curl(MEDIA)
    if s not in (200, 403, 404):
        broken.append(("lovejoos media pipeline", MEDIA, classify(MEDIA, s or "DOWN")))

    now = int(time.time())
    try: state = json.load(open(STATE))
    except Exception: state = {}
    if not isinstance(state.get("alerted"), dict):          # migrate old flat {url: ts}
        state = {"alerted": {k: v for k, v in state.items() if isinstance(v, int)}, "pending": {}}
    alerted, pending = state["alerted"], state.setdefault("pending", {})

    # A URL must fail in TWO CONSECUTIVE runs before it can alert. One-off blips
    # land in `pending` and are dropped silently on the next clean run.
    broken_urls = {i for _, i, _ in broken}
    confirmed = [(p, i, c) for p, i, c in broken if i in pending]
    for i in broken_urls:
        pending[i] = now
    for i in list(pending):
        if i not in broken_urls:
            del pending[i]

    fresh = [(p, i, c) for p, i, c in confirmed if now - alerted.get(i, 0) > 6 * 3600]
    for _, i, _ in fresh: alerted[i] = now
    state["alerted"] = {k: v for k, v in alerted.items() if now - v < 7 * 86400}
    json.dump(state, open(STATE, "w"))

    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    print(f"{ts} image-probe: {len(PAGES)} pages, {len(broken)} broken, "
          f"{len(confirmed)} confirmed, {len(fresh)} new (public-DNS)")
    for p, i, c in broken:
        print(f"  [{c}] {i}  (on {p}){'' if i in dict((x[1], 1) for x in confirmed) else '  <-unconfirmed'}")
    if fresh:
        msg = "Broken images (public edge, failed 2 runs in a row):\n" + "\n".join(f"[{c}] {i}" for _, i, c in fresh[:15])
        try:
            import urllib.request
            urllib.request.urlopen(urllib.request.Request(f"{NTFY_URL}/{NTFY_TOPIC}", data=msg.encode(),
                headers={"Title": "WOPR broken images", "Priority": "default"}), timeout=10)
        except Exception: pass

if __name__ == "__main__":
    main()
