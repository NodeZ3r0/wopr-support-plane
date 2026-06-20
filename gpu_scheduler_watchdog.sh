#!/usr/bin/env bash
# gpu-scheduler :18099 silently WEDGES (systemd stays "active") and breaks asscast/meme
# LLM script-gen with 504s. Probe the real chat endpoint; restart the service if hung.
set -u
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 35 -X POST   -H 'Content-Type: application/json'   -d '{"model":"joshua:latest","messages":[{"role":"user","content":"ping"}],"stream":false}'   http://127.0.0.1:18099/ollama/chat-interactive 2>/dev/null)
if [ "$code" != "200" ]; then
  logger -t gpu-scheduler-watchdog "scheduler /ollama/chat-interactive returned $code; restarting gpu-scheduler"
  systemctl restart gpu-scheduler
  sleep 8
  curl -s -H "Title: GPU scheduler wedged" -H "Priority: high"     -d "gpu-scheduler :18099 was $code (wedged, systemd showed active); auto-restarted. Protects asscast + meme-engine LLM script-gen."     https://notify.wopr.systems/wopr-alerts >/dev/null 2>&1
fi
