"""Tests for the propose-only GPU/registry checks in model_presence_probe.py.

Run: python3 -m unittest -v test_model_presence_probe.py
Uses a fake scheduler + fake ntfy on localhost, temp log/registry/state files.
Nothing real is alerted, restarted or changed.
"""
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import model_presence_probe as probe  # noqa: E402


def ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def write_json(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f)


def expiry_line(dt, jid, src, wait):
    return f"{ts(dt)},123 WARNING [gpu-sched] Expired stale queued job {jid} from {src} after {wait}s\n"


class Fake:
    def __init__(self):
        self.posts = []
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                fake.posts.append((self.headers.get("Title"), self.rfile.read(n).decode()))
                self.send_response(200)
                self.end_headers()

            def do_GET(self):
                body = json.dumps({"running": {"source": "mh-qwen-batch", "job_type": "script",
                                               "priority": "high", "started_at": "2026-10-14T10:00:00"},
                                   "queued": [{}, {}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d" % self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


class PureFunctions(unittest.TestCase):
    def test_scan_expiries_filters_groups_and_tracks_newest(self):
        t0 = datetime(2026, 10, 14, 8, 0, 0)
        lines = [expiry_line(t0, "a1", "old-src", 999),                       # at 'since' -> excluded
                 expiry_line(t0 + timedelta(minutes=1), "b1", "ollama-proxy", 300),
                 expiry_line(t0 + timedelta(minutes=2), "b2", "ollama-proxy", 4225),
                 "2026-10-14 08:03:00,1 INFO [gpu-sched] Job x completed\n",
                 expiry_line(t0 + timedelta(minutes=3), "c1", "protovision-email", 3758)]
        counts, newest = probe.scan_expiries(lines, ts(t0))
        self.assertNotIn("old-src", counts)
        self.assertEqual(counts["ollama-proxy"]["count"], 2)
        self.assertEqual(counts["ollama-proxy"]["max_wait"], 4225)
        self.assertEqual(counts["protovision-email"]["jobs"], ["c1"])
        self.assertEqual(newest, ts(t0 + timedelta(minutes=3)))

    def test_jobs_list_capped(self):
        t0 = datetime(2026, 10, 14, 8, 0, 0)
        lines = [expiry_line(t0 + timedelta(seconds=i + 1), f"j{i}", "s", 10) for i in range(9)]
        counts, _ = probe.scan_expiries(lines, ts(t0))
        self.assertEqual(counts["s"]["count"], 9)
        self.assertEqual(len(counts["s"]["jobs"]), 5)

    def test_digest_is_a_proposal_with_evidence(self):
        msg = probe.starvation_digest({"ollama-proxy": {"count": 3, "max_wait": 4225, "last": "x",
                                                        "jobs": ["a", "b"]}}, "mh-qwen-batch (script)")
        self.assertIn("ollama-proxy: 3 job(s)", msg)
        self.assertIn("mh-qwen-batch", msg)
        self.assertIn("Nothing was changed", msg)
        self.assertIn("queue_timeout", msg)

    def test_registry_findings(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "models.json")
            self.assertEqual(probe.registry_findings(p, time.time()), (None, None))
            write_json(p, {"missing_references": [
                {"name": "gone.safetensors", "kind": "comfyui", "referenced_by": ["/x/pipeline/a.py"]},
                {"name": "llama9:latest", "kind": "ollama", "referenced_by": ["/y/.env"]}]})
            missing, stale = probe.registry_findings(p, time.time())
            self.assertEqual(len(missing), 1)
            self.assertIn("gone.safetensors", missing[0])
            self.assertIn("pipeline/a.py", missing[0])
            self.assertIsNone(stale)
            _, stale = probe.registry_findings(p, time.time() + 30 * 3600)
            self.assertGreater(stale, 24)


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.fake = Fake()
        self.d = tempfile.TemporaryDirectory()
        now = datetime.now()
        self.log = os.path.join(self.d.name, "scheduler.log")
        with open(self.log, "w") as f:
            f.write(expiry_line(now - timedelta(minutes=30), "e1", "protovision-email", 3758))
            f.write(expiry_line(now - timedelta(minutes=20), "e2", "ollama-proxy", 4225))
        self.reg = os.path.join(self.d.name, "models.json")
        write_json(self.reg, {"missing_references": [{"name": "gone.safetensors", "kind": "comfyui",
                                                      "referenced_by": ["/x/pipeline/a.py"]}]})
        self.env = os.path.join(self.d.name, "empty.env")
        open(self.env, "w").close()
        self.state = os.path.join(self.d.name, "state.json")

    def tearDown(self):
        self.fake.close()
        self.d.cleanup()

    def run_probe(self):
        argv = ["probe", "--test", "--source", "t=" + self.env, "--state", self.state,
                "--sched-log", self.log, "--sched-url", self.fake.url, "--registry", self.reg]
        with mock.patch.object(probe, "NTFY_URL", self.fake.url), \
             mock.patch.object(probe, "installed", lambda: set()), \
             mock.patch.object(sys, "argv", argv):
            probe.main()

    def test_alerts_once_then_dedupes_and_changes_nothing(self):
        self.run_probe()
        titles = [t for t, _ in self.fake.posts]
        self.assertEqual(sum("GPU queue starvation" in t for t in titles), 1)
        self.assertEqual(sum("model file missing" in t for t in titles), 1)
        body = next(b for t, b in self.fake.posts if "starvation" in t)
        self.assertIn("ollama-proxy", body)
        self.assertIn("protovision-email", body)
        self.assertIn("mh-qwen-batch", body)          # who holds the GPU, from /jobs
        self.assertTrue(all(t.startswith("[MODEL] TEST") for t in titles))
        before = len(self.fake.posts)
        self.run_probe()                              # no new log lines, same missing set
        self.assertEqual(len(self.fake.posts), before)


if __name__ == "__main__":
    unittest.main()
