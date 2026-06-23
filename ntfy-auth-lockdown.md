# ntfy public lockdown -- CORRECTED (2026-06-22): per-topic, multi-tenant safe

notify.wopr.systems is MULTI-TENANT: it carries Scott infra alerts AND end-user app push
(LoveJoos posts per-user topics lovejoos-{uid}; users subscribe anonymously). It was
auth-default-access: read-write so anyone could read every topic incl. infra alerts.

WRONG FIRST ATTEMPT (reverted): basic_auth on the whole caddy vhost -> 401s LoveJoos/app push
(end users cannot sign in as scott). Do NOT lock the whole server.

CORRECT FIX = ntfy per-topic ACL (anon write-only on infra topics; everything else stays public):
  docker exec wopr-ntfy ntfy access everyone wopr-alerts   write-only
  docker exec wopr-ntfy ntfy access everyone gpu-scheduler write-only
  docker exec wopr-ntfy ntfy access everyone asscast       write-only
  docker exec wopr-ntfy ntfy access everyone sms-inbox     write-only
- anon can PUBLISH to infra topics (publishers need no creds) but CANNOT read them.
- lovejoos-* and all other topics stay read-write (app push unaffected).
- ntfy default left read-write. Forwarder reads infra topics via admin user scott token
  (/etc/systemd/system/wopr-alert-sms.service.d/ntfy-token.conf). Scott phone: sign in scott.

ALSO: 13 infra publishers repointed to http://127.0.0.1:18081 (backups *.bak.ntfylocal); to stop
them sharing/exhausting the 127.0.0.1 rate bucket added to server.yml:
  visitor-request-limit-exempt-hosts: "127.0.0.0/8,::1,10.0.0.0/8"
  (must be a comma STRING, not a YAML list, or ntfy crash-loops.)

NOT AFFECTED: LoveJoos SMS / 2FA-OTP -- separate path via SMS gateway http://10.0.0.3:7890/send.

VERIFIED: anon read wopr-alerts=403, anon read lovejoos=200, anon publish wopr-alerts=200,
scott read=200, localhost publish=200, SMS pipeline intact.
