#!/usr/bin/env python3
"""
ASScast pipeline health watchdog (support-plane, independent timer).

Runs after the daily 06:00 run+retry window. Verifies today's episode actually produced
audio + video. If not (and nothing is running), it:
  1) does the SAFE GPU-contention remediation (scheduler /gpu/clear unloads non-joshua
     ollama models; frees idle ComfyUI VRAM without killing it),
  2) reruns the pipeline ONCE (stamped so it never loops),
  3) ALWAYS alerts via ntfy + email so a human notices and can fix it manually if the
     auto-remediation also fails.
On a later run, if the episode is STILL missing after the auto-rerun, it escalates with a
"manual intervention" alert. Deliberately does NOT kill Chatterbox (it can be the live TTS
server) and runs as user nodez3r0 (same as the cron) so file ownership stays correct.
"""
import os, json, subprocess, datetime, smtplib
import urllib.request
from email.mime.text import MIMEText

ASS = "/opt/asscast"
TODAY = datetime.date.today().isoformat()
DIR = f"{ASS}/scripts/{TODAY}"
MP3, MP4 = f"{DIR}/episode.mp3", f"{DIR}/episode_video.mp4"
RERUN_STAMP = f"{ASS}/.sp_asscast_rerun_{TODAY}"
ESC_STAMP = f"{ASS}/.sp_asscast_escalated_{TODAY}"
SCHED = "http://127.0.0.1:18099"
COMFY = "http://127.0.0.1:8188"
NTFY = "http://127.0.0.1:18081/wopr-alerts"
FROM_EMAIL, TO_EMAIL = "asscast@wopr.systems", "stephen.falken@wopr.systems"


def alert(title, body, priority="high"):
    try:
        req = urllib.request.Request(NTFY, data=body.encode(),
            headers={"Title": title, "Priority": priority, "Tags": "rotating_light,asscast"})
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass
    try:
        m = MIMEText(body); m["Subject"] = title; m["From"] = FROM_EMAIL; m["To"] = TO_EMAIL
        with smtplib.SMTP("localhost", 25) as s:
            s.sendmail(FROM_EMAIL, [TO_EMAIL], m.as_string())
    except Exception:
        pass


def running():
    return subprocess.run(["pgrep", "-f", "orchestrate.py|daily_pipeline.py"],
                          capture_output=True).returncode == 0


def episode_done():
    return (os.path.exists(MP4) and os.path.getsize(MP4) > 100_000 and
            os.path.exists(MP3) and os.path.getsize(MP3) > 10_000)


def post(url, payload=None):
    try:
        data = json.dumps(payload).encode() if payload is not None else b"{}"
        urllib.request.urlopen(urllib.request.Request(url, data=data, method="POST",
            headers={"Content-Type": "application/json"}), timeout=20)
    except Exception:
        pass


def main():
    if running():
        return                      # a run is in progress -- do not interfere
    if episode_done():
        return                      # success today -- nothing to do

    # episode missing and nothing running == failure
    if os.path.exists(RERUN_STAMP):
        # already auto-reran today and STILL no episode -> escalate (once)
        if not os.path.exists(ESC_STAMP):
            open(ESC_STAMP, "w").write(datetime.datetime.now().isoformat())
            alert("ASScast STILL FAILING -- manual fix needed",
                  f"ASScast episode for {TODAY} did NOT produce a video even after the support-plane "
                  f"auto-remediation + rerun. MANUAL intervention required.\n\n"
                  f"Check: nvidia-smi (VRAM contention) | curl -s :18099/health (scheduler) | "
                  f"systemctl is-active gpu-gatekeeper | Falken overnight window | "
                  f"tail /opt/asscast/orchestrator.log\n\n"
                  f"Unstick: curl -XPOST :18099/gpu/clear ; "
                  f"curl -XPOST :8188/free -d '{{\"unload_models\":true,\"free_memory\":true}}' ; "
                  f"cd /opt/asscast && setsid venv/bin/python3 daily_pipeline.py &")
        return

    # first failure today -> remediate + rerun once
    post(f"{SCHED}/gpu/clear")                                   # unload non-joshua ollama models
    post(f"{COMFY}/free", {"unload_models": True, "free_memory": True})  # free idle ComfyUI VRAM
    open(RERUN_STAMP, "w").write(datetime.datetime.now().isoformat())    # stamp BEFORE rerun (no loop)
    subprocess.Popen(["/opt/asscast/venv/bin/python3", "/opt/asscast/daily_pipeline.py"],
                     cwd=ASS, stdin=subprocess.DEVNULL,
                     stdout=open(f"{ASS}/cron.log", "a"), stderr=subprocess.STDOUT,
                     start_new_session=True)
    alert("ASScast failed -- auto-remediation + rerun launched",
          f"ASScast episode for {TODAY} was missing and no run was active.\n\n"
          f"Support-plane cleared GPU VRAM (scheduler /gpu/clear + freed idle ComfyUI) and relaunched "
          f"the pipeline. Track it at asscast.org/cp-admin.\n\n"
          f"If it fails again you'll get a 'STILL FAILING -- manual fix needed' alert.")


if __name__ == "__main__":
    main()
