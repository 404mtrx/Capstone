#!/bin/bash
# OpenSearch authentication evidence (NFR-15, FR-14).
# Usage: bash scripts/test_opensearch_auth.sh [repo path]
# Needs: docker compose up -d (healthy), scripts/opensearch_setup_user.sh done, the API running with
#        the same OPENSEARCH_* values in backend/.env, and API_KEY set in backend/.env.
cd "${1:-$(git rev-parse --show-toplevel 2>/dev/null || echo $HOME/Capstone)}" || exit 1
source backend/.venv/bin/activate
mkdir -p docs/test-evidence
ADMIN_PW="${OPENSEARCH_ADMIN_PASSWORD:-Os-Dev#7qZ4mWx9Lp2}"
OSU=$(grep -E '^OPENSEARCH_USER=' backend/.env | cut -d= -f2-)
OSP=$(grep -E '^OPENSEARCH_PASSWORD=' backend/.env | cut -d= -f2-)
KEY=$(grep -E '^API_KEY=' backend/.env | cut -d= -f2-)
(
code() { curl -sk -o /dev/null -w "HTTP %{http_code}" "$@"; }
echo "=== TC-OS-01 containers healthy ==="; docker compose ps
echo; echo "=== TC-OS-02 no credentials is refused (expect 401) ==="; code https://localhost:9200; echo
echo; echo "=== TC-OS-03 wrong password is refused (expect 401) ==="; code -u "admin:wrong-password" https://localhost:9200; echo
echo; echo "=== TC-OS-04 plain HTTP is not accepted (expect HTTP 000 or an error) ==="; curl -s --max-time 5 -o /dev/null -w "HTTP %{http_code}\n" http://localhost:9200 || true
echo; echo "=== TC-OS-05 the API's own user can log in (expect 200) ==="; code -u "$OSU:$OSP" https://localhost:9200; echo
echo; echo "=== TC-OS-06 the API user cannot read cluster settings or manage users (expect 403, 403) ==="
code -u "$OSU:$OSP" https://localhost:9200/_cluster/settings; echo
code -u "$OSU:$OSP" https://localhost:9200/_plugins/_security/api/internalusers; echo
echo; echo "=== TC-OS-07 the API stores events through the login (expect 201, then the count) ==="
SENTINEL_API_KEY=$KEY python collector/send_events.py normalized_events.json firewall_events.json
curl -sk -u "$OSU:$OSP" https://localhost:9200/sentinel-events/_count; echo
echo; echo "=== TC-OS-08 the API user cannot read any other index (expect 403) ==="; code -u "$OSU:$OSP" "https://localhost:9200/.opendistro_security/_search"; echo
echo; echo "ALL DONE"
) 2>&1 | tee docs/test-evidence/opensearch_auth_output.txt
