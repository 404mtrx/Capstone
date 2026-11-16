#!/bin/bash
# Create the least-privilege OpenSearch user the API logs in with (run once, OpenSearch healthy).
# Usage: bash scripts/opensearch_setup_user.sh [repo path]
cd "${1:-$(git rev-parse --show-toplevel 2>/dev/null || echo $HOME/Capstone)}" || exit 1
source backend/.venv/bin/activate
ADMIN_PW="${OPENSEARCH_ADMIN_PASSWORD:-Os-Dev#7qZ4mWx9Lp2}"
OSU=$(grep -E '^OPENSEARCH_USER=' backend/.env | cut -d= -f2-)
OSP=$(grep -E '^OPENSEARCH_PASSWORD=' backend/.env | cut -d= -f2-)
[ -n "$OSU" ] && [ -n "$OSP" ] || { echo "Set OPENSEARCH_USER and OPENSEARCH_PASSWORD in backend/.env first (see backend/.env.example)."; exit 1; }
API=https://localhost:9200/_plugins/_security/api
put() { curl -sk -u "admin:$ADMIN_PW" -X PUT "$API/$1" -H 'Content-Type: application/json' -d "$2"; echo; }

echo "== role: may only use the sentinel-events index =="
put roles/sentinel_events_rw '{"cluster_permissions":["cluster_composite_ops"],"index_permissions":[{"index_patterns":["sentinel-events*"],"allowed_actions":["indices_all"]}]}'
echo "== user: $OSU =="
put internalusers/$OSU "$(python -c "import json,sys;print(json.dumps({'password':sys.argv[1],'description':'SentinelWatch API'}))" "$OSP")"
echo "== map the user to the role =="
put rolesmapping/sentinel_events_rw "$(python -c "import json,sys;print(json.dumps({'users':[sys.argv[1]]}))" "$OSU")"
echo "== check: the new user can log in =="
curl -sk -o /dev/null -w "HTTP %{http_code}\n" -u "$OSU:$OSP" https://localhost:9200
