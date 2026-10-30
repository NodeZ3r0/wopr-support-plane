#!/usr/bin/env python3
"""Prove the Prod-1 support plane cannot start anything held or switched off (WOPR-260). Read-only.

Checks, with the live manifest and hold file:
  - the manifest is strict;
  - every name in hold-until-switch.json is refused (units and containers);
  - every container that is not running now (created / exited) is refused;
  - every unit file that is disabled, static, masked or indirect is refused;
  - nebula is refused by the generic check (only the plain restart-if-down path may touch it);
  - every manifest entry is allowed (so the plane can still heal what runs).
Exit 0 = all good. Run as root: python3 /opt/wopr/support-plane/prod1_selftest.py
"""
import json
import subprocess
import sys

sys.path.insert(0, "/opt/wopr/support-plane")
import sp_guard  # noqa: E402


def out(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout


def main():
    bad = []
    m = sp_guard.manifest()
    if not sp_guard.strict(m):
        print("FAIL: manifest is not strict_manifest"); return 1
    hold = json.load(open(sp_guard.HOLD_FILE))
    held_units, held_ctrs = set(), set()
    for sec in ("until_switch", "off_for_good"):
        s = hold.get(sec) or {}
        held_units |= {sp_guard.unit_name(n) for n in (s.get("services") or [])}
        held_ctrs |= set(s.get("containers") or [])
    for u in sorted(held_units):
        if sp_guard.may_restart_unit(u, m)[0]:
            bad.append("held unit allowed: " + u)
    for c in sorted(held_ctrs):
        if sp_guard.may_restart_container(c, "docker", m)[0]:
            bad.append("held container allowed: " + c)
    stopped = [l.split("\t")[0] for l in out(["docker", "ps", "-a", "--format", "{{.Names}}\t{{.State}}"]).splitlines()
               if l and not l.endswith("\trunning")]
    for c in stopped:
        if sp_guard.may_restart_container(c, "docker", m)[0]:
            bad.append("non-running container allowed: " + c)
    off_units = []
    for l in out(["systemctl", "list-unit-files", "--type=service", "--no-legend", "--plain",
                  "--state=disabled,static,masked,indirect"]).splitlines():
        if l.split():
            off_units.append(sp_guard.unit_name(l.split()[0]))
    for u in off_units:
        if sp_guard.may_restart_unit(u, m)[0]:
            bad.append("disabled/static/masked unit allowed: " + u)
    if sp_guard.may_restart_unit("nebula", m)[0]:
        bad.append("nebula allowed by the generic restart check")
    ok_units = [s["name"] for s in m.get("services", []) if s["name"] != "nebula"]
    ok_ctrs = [c["name"] for c in m.get("containers", [])]
    for u in ok_units:
        r = sp_guard.may_restart_unit(u, m)
        if not r[0]:
            bad.append("manifest unit refused: %s (%s)" % (u, r[1]))
    for c in ok_ctrs:
        r = sp_guard.may_restart_container(c, "docker", m)
        if not r[0]:
            bad.append("manifest container refused: %s (%s)" % (c, r[1]))
    if bad:
        print("SELFTEST FAIL:\n  " + "\n  ".join(bad)); return 1
    print("SELFTEST OK: refused %d held units, %d held containers, %d non-running containers (%s), "
          "%d disabled/static/masked units, nebula; allowed %d manifest units + %d containers"
          % (len(held_units), len(held_ctrs), len(stopped), " ".join(stopped) or "none", len(off_units),
             len(ok_units), len(ok_ctrs)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
