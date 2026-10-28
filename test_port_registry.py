"""Tests for the owner-change check in port_registry.py.

Run: python3 -m unittest -v test_port_registry.py
Uses a fake ss snapshot, a temp registry file and a fake ntfy. Nothing real is alerted or changed.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import port_registry as pr  # noqa: E402


def held(owner, all_owners=None, cmd="", proc=None):
    return {"proc": proc or owner, "pid": "1", "user": "root", "container": "", "owner": owner,
            "cmd": cmd, "addr": "127.0.0.1", "all_owners": sorted(all_owners or [owner])}


class OwnerChange(unittest.TestCase):
    def run_once(self, known, snap):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "port_registry.json")
            with open(db, "w") as f:
                json.dump({"ports": known}, f)
            sent = []
            with mock.patch.object(pr, "DB", db), mock.patch.object(pr, "snapshot", return_value=snap), \
                    mock.patch.object(pr, "ntfy", side_effect=lambda t, m, **k: sent.append(m)):
                pr.main()
            return sent, json.load(open(db))["ports"]

    def rec(self, owner, expected=None, **extra):
        r = {"owner": owner, "proc": owner, "cmd": "", "container": "", "expected": expected, "note": ""}
        r.update(extra)
        return r

    def test_netdata_restart_holding_statsd_is_not_a_conflict(self):
        # 10-28 03:18: needrestart bounced netdata, which came back holding :8125 itself
        sent, ports = self.run_once({"8125": self.rec("bash", expected="apps.plugin")},
                                    {"8125": held("netdata")})
        self.assertEqual(sent, [])
        self.assertNotIn("last_conflict", ports["8125"])

    def test_netdata_bash_helper_is_netdata(self):
        cmd = "bash /usr/lib/netdata/plugins.d/tc-qos-helper.sh 1"
        sent, _ = self.run_once({"8125": self.rec("bash", expected="apps.plugin")},
                                {"8125": held("bash", cmd=cmd)})
        self.assertEqual(sent, [])

    def test_stale_conflict_marker_is_cleared(self):
        sent, ports = self.run_once({"8125": self.rec("bash", expected="apps.plugin",
                                                      last_conflict="8125:apps.plugin->netdata")},
                                    {"8125": held("netdata", ["apps.plugin", "bash", "netdata"])})
        self.assertEqual(sent, [])
        self.assertNotIn("last_conflict", ports["8125"])

    def test_other_process_on_netdata_port_still_alerts(self):
        sent, _ = self.run_once({"8125": self.rec("bash", expected="apps.plugin")},
                                {"8125": held("nginx", cmd="nginx: master process")})
        self.assertEqual(len(sent), 1)
        self.assertIn("port 8125: expected 'apps.plugin' but now held by 'nginx'", sent[0])

    def test_plain_bash_elsewhere_is_not_netdata(self):
        sent, _ = self.run_once({"8125": self.rec("bash", expected="apps.plugin")},
                                {"8125": held("bash", cmd="bash /home/someone/listen.sh")})
        self.assertEqual(len(sent), 1)

    def test_postfix_family_unchanged(self):
        sent, _ = self.run_once({"25": self.rec("master", expected="master")},
                                {"25": held("smtpd")})
        self.assertEqual(sent, [])


if __name__ == "__main__":
    unittest.main()
