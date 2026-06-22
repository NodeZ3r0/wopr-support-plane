# ntfy auth lockdown (2026-06-22)

Problem: notify.wopr.systems was world readable+writable -- ntfy auth-default-access was
"read-write", so anyone could read every alert topic and publish to them.

Fix: auth-default-access: "write-only" in /opt/wopr-monitoring/ntfy/config/server.yml (wopr-ntfy
container). Anonymous can still PUBLISH (rig publishers unchanged) but can no longer READ/subscribe.
- Admin user "scott" for the phone app + reads.
- Reader token for the SMS forwarder via /etc/systemd/system/wopr-alert-sms.service.d/ntfy-token.conf
  (real token on the rig only, NOT committed).
- Verified: anon read=403, anon write=200, authed read=200, SMS pipeline intact.

Residual: anonymous WRITE still allowed (publishers need no creds); rate-capped 8/hr by the forwarder.
Full close = deny-all + tokenize every writer.
