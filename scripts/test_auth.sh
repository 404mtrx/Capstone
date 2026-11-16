#!/bin/bash
# SentinelWatch Sprint 3 checks: login, roles, API key, audit log, users, metrics.
# Usage: bash scripts/test_auth.sh [repo path]
# Needs: PostgreSQL up, `alembic upgrade head` done, the API running on :8000 with
#        AUTH_REQUIRED=true and API_KEY set in backend/.env.
cd "${1:-$(git rev-parse --show-toplevel 2>/dev/null || echo $HOME/Capstone)}" || exit 1
source backend/.venv/bin/activate
mkdir -p docs/test-evidence
KEY=$(grep -E '^API_KEY=' backend/.env | cut -d= -f2-)
(
B=http://localhost:8000; H='Content-Type: application/json'; N=$RANDOM
PW='TestPass12345!'
code() { curl -s -o /dev/null -w "HTTP %{http_code}" "$@"; }
field() { python -c "import sys,json;print(json.load(sys.stdin)$1)"; }
login() { curl -s -X POST $B/auth/login -H "$H" -d "{\"username\":\"$1\",\"password\":\"$PW\"}" | field "['access_token']"; }

echo "=== TC-AUTH-01 no token on a protected endpoint (expect 401) ==="; code $B/alerts; echo
echo; echo "=== TC-AUTH-02 wrong password (expect 401) ==="
curl -s -i -X POST $B/auth/login -H "$H" -d '{"username":"authadmin","password":"wrong-password-123"}' | grep -E "HTTP|detail"
echo; echo "=== create admin with the CLI (ok if it already exists) ==="
(cd backend && python -c "import getpass,sys,runpy; getpass.getpass=lambda p='': '$PW'; sys.argv=['x','authadmin','--role','admin']; runpy.run_module('app.create_user', run_name='__main__')")
echo; echo "=== TC-AUTH-03 login returns a token and the role ==="
AD=$(login authadmin); echo "token starts: ${AD:0:20}..."
curl -s $B/auth/me -H "Authorization: Bearer $AD"; echo
echo; echo "=== TC-AUTH-04 admin creates an analyst and a lead ==="
curl -s -X POST $B/users -H "$H" -H "Authorization: Bearer $AD" -d "{\"username\":\"analyst$N\",\"password\":\"$PW\",\"role\":\"analyst\"}"; echo
curl -s -X POST $B/users -H "$H" -H "Authorization: Bearer $AD" -d "{\"username\":\"lead$N\",\"password\":\"$PW\",\"role\":\"lead\"}"; echo
AN=$(login analyst$N); LD=$(login lead$N)
echo; echo "=== TC-AUTH-05 password under 12 characters refused by the API (expect 422) ==="
code -X POST $B/users -H "$H" -H "Authorization: Bearer $AD" -d "{\"username\":\"short$N\",\"password\":\"abc123\",\"role\":\"analyst\"}"; echo
echo; echo "=== TC-RBAC-01 analyst cannot manage users or read audit (expect 403, 403) ==="
code $B/users -H "Authorization: Bearer $AN"; echo; code $B/audit -H "Authorization: Bearer $AN"; echo
echo; echo "=== TC-RBAC-02 analyst cannot read metrics (403); lead can (200) ==="
code $B/metrics/summary -H "Authorization: Bearer $AN"; echo; code $B/metrics/summary -H "Authorization: Bearer $LD"; echo
echo; echo "=== TC-RBAC-03 analyst cannot create alerts by hand (expect 403) ==="
code -X POST $B/alerts -H "$H" -H "Authorization: Bearer $AN" -d '{"rule_name":"r","message":"m"}'; echo
echo; echo "=== TC-KEY-01 API key lets the engine post and read alerts (201, 200) ==="
R=$(curl -s -X POST $B/alerts -H "$H" -H "X-API-Key: $KEY" -d '{"rule_name":"Failed Login Detected","severity":"medium","source_ip":"10.0.0.9","message":"auth test"}')
echo "$R"; ID=$(echo "$R" | field "['id']")
code $B/alerts -H "X-API-Key: $KEY"; echo
echo; echo "=== TC-KEY-02 wrong key refused (401); key does not open cases or triage (401, 401) ==="
code -X POST $B/alerts -H "$H" -H "X-API-Key: wrong" -d '{"rule_name":"r","message":"m"}'; echo
code $B/cases -H "X-API-Key: $KEY"; echo; code -X PATCH $B/alerts/$ID -H "$H" -H "X-API-Key: $KEY" -d '{"status":"closed"}'; echo
echo; echo "=== TC-AUTH-06 tampered token refused (expect 401) ==="
code $B/alerts -H "Authorization: Bearer ${AN}x"; echo
echo; echo "=== TC-API-05 illegal transition new->escalated still 409 for an analyst ==="
curl -s -i -X PATCH $B/alerts/$ID -H "$H" -H "Authorization: Bearer $AN" -d '{"status":"escalated"}' | grep -E "HTTP|detail"
echo; echo "=== triage as the analyst: investigate, open a case ==="
curl -s -X PATCH $B/alerts/$ID -H "$H" -H "Authorization: Bearer $AN" -d '{"status":"investigating"}'; echo
curl -s -X POST $B/cases -H "$H" -H "Authorization: Bearer $AN" -d "{\"alert_id\":$ID,\"title\":\"auth test case\"}"; echo
echo; echo "=== TC-AUDIT-01 admin reads the audit log (latest actions) ==="
curl -s "$B/audit?limit=8" -H "Authorization: Bearer $AD" | python -c "
import sys,json
for r in json.load(sys.stdin): print(r['timestamp'][:19], r['username'].ljust(16), r['action'].ljust(20), r['target_type'], r['target_id'], r['detail'])"
echo; echo "=== TC-AUDIT-02 failed logins are recorded ==="
curl -s "$B/audit?action=login_failure&limit=3" -H "Authorization: Bearer $AD" | python -c "
import sys,json
for r in json.load(sys.stdin): print(r['timestamp'][:19], r['username'], r['action'])"
echo; echo "=== TC-METRICS-01 lead reads the metrics ==="
curl -s $B/metrics/summary -H "Authorization: Bearer $LD"; echo
echo; echo "=== TC-DB-03b migration check: current head ==="
(cd backend && alembic current 2>&1 | tail -1)
echo; echo "ALL DONE"
) 2>&1 | tee docs/test-evidence/auth_tests_output.txt
