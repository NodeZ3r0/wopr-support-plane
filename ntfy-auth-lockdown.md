# ntfy public lockdown -- FINAL (2026-06-22): deny-all at caddy

notify.wopr.systems was world read+write (ntfy auth-default-access: read-write). ntfy is only
bound to 127.0.0.1:18081 and is reachable publicly ONLY via Cloudflare tunnel -> caddy-rig. So
the public door is caddy. Locked it there instead of tokenizing every publisher.

WHAT CHANGED:
- caddy-rig vhost notify.wopr.systems: added basic_auth (user scott). Anon read AND publish from
  the internet now 401. (see notify.wopr.systems.caddy; real bcrypt hash on rig only.)
- 13 internal publishers repointed from https://notify|ntfy.wopr.systems -> http://127.0.0.1:18081
  so they bypass the public door (no creds needed). Backups: *.bak.ntfylocal. Files: asscast
  daily_pipeline/orchestrate, gpu-scheduler scheduler.py, wopr-{mesh,sms}-bridge, sms-gateway,
  sentinel/log_sentinel, support-plane {asscast_watchdog, gpu_scheduler_watchdog, image_probe,
  mesh_probe, og_audit, synthetic_probe}.
- ntfy auth-default-access reverted read-write (localhost-trusted; caddy is the boundary).
- ntfy admin user "scott" + forwarder reader-token drop-in remain but are now vestigial (harmless).

PHONE: ntfy app -> server https://notify.wopr.systems -> sign in scott / <pw> -> subscribe wopr-alerts.
VERIFIED: anon read=401, anon publish=401, scott read=200, localhost publish=200, SMS pipeline intact.
