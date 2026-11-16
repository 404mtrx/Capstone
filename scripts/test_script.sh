#!/bin/bash
# SentinelWatch backend test script (Sprint 2/3 evidence).
# Usage: bash scripts/test_script.sh [repo path]   (default: current directory's repo or ~/Capstone)
# Needs: docker compose up -d (postgres + opensearch healthy), the API running on :8000,
#        and AUTH_REQUIRED=false in backend/.env (or use scripts/test_auth.sh for the auth checks).
cd "${1:-$(git rev-parse --show-toplevel 2>/dev/null || echo $HOME/Capstone)}" || exit 1
source backend/.venv/bin/activate
mkdir -p docs/test-evidence
(
H='Content-Type: application/json'
B=http://localhost:8000
echo "=== TC-API-01 health ==="; curl -i -s $B/health; echo
echo; echo "=== TC-DB-01 containers ==="; docker compose ps
echo; echo "=== TC-SEC-03 env files ==="; git ls-files | grep -i "\.env"
echo; echo "=== EV-01 pytest ==="; (cd backend && pytest -q 2>&1 | tail -4)
echo; echo "=== TC-API-11 dedup: resend then count ==="
python collector/send_events.py normalized_events.json firewall_events.json
curl -s http://localhost:9200/sentinel-events/_count; echo
echo; echo "=== create alert ==="
R=$(curl -s -X POST $B/alerts -H "$H" -d '{"rule_name":"Failed Login Detected","severity":"medium","source_ip":"10.0.0.9","message":"409 test"}')
echo $R
ID=$(echo $R | python -c "import sys,json;print(json.load(sys.stdin)['id'])")
echo "alert id = $ID"
echo; echo "=== TC-API-05 illegal transition new->escalated (expect 409) ==="
curl -i -s -X PATCH $B/alerts/$ID -H "$H" -d '{"status":"escalated"}' | grep -E "HTTP|detail"
echo; echo "=== TC-API-06 first case (expect 201) ==="
curl -i -s -X POST $B/cases -H "$H" -d "{\"alert_id\":$ID,\"title\":\"first case\"}" | grep -E "HTTP|status"
echo; echo "=== TC-API-08 second open case (expect 409) ==="
curl -i -s -X POST $B/cases -H "$H" -d "{\"alert_id\":$ID,\"title\":\"second case\"}" | grep -E "HTTP|detail"
echo; echo "=== TC-API-07 case for missing alert (expect 404) ==="
curl -i -s -X POST $B/cases -H "$H" -d '{"alert_id":99999,"title":"x"}' | grep -E "HTTP|detail"
echo; echo "=== TC-SEC-09 short password refused ==="
(cd backend && python -c "import getpass,sys,runpy; getpass.getpass=lambda p='': 'abc123'; sys.argv=['x','shorttest']; runpy.run_module('app.create_user', run_name='__main__')")
echo; echo "=== TC-SEC-01 argon2 hash stored ==="
(cd backend && python -c "import getpass,sys,runpy; getpass.getpass=lambda p='': 'TestPass12345!'; sys.argv=['x','testanalyst','--role','analyst']; runpy.run_module('app.create_user', run_name='__main__')")
docker exec sentinelwatch-postgres psql -U sentinel -d sentinelwatch -c "select username, role, left(password_hash,30) as hash from \"user\";"
echo; echo "=== TC-API-13 OpenSearch down (expect 503) ==="
docker compose stop opensearch
python collector/send_events.py normalized_events.json
docker compose start opensearch
until curl -s http://localhost:9200 >/dev/null; do sleep 3; done
echo; echo "=== TC-DB-03 migration down/up (wipes data) ==="
(cd backend && alembic downgrade base 2>&1 | tail -2 && alembic upgrade head 2>&1 | tail -2)
echo; echo "ALL DONE"
) 2>&1 | tee docs/test-evidence/all_tests_output.txt
