#!/bin/bash
# Run ON THE SERVER, from the repo folder:   bash deploy/setup.sh your-site-address
# your-site-address = a domain name, or  <server-ip-with-dashes>.sslip.io  (free, e.g. 203-0-113-5.sslip.io)
set -e
cd "$(dirname "$0")"
SITE="${1:?Usage: bash deploy/setup.sh your-site-address}"
rand() { openssl rand -hex 24; }   # letters+digits only, so no quoting problems

if [ ! -f .env ]; then
  OSADMIN="Os-$(rand)-Aa1!"
  cat > .env <<ENV
SITE_ADDRESS=$SITE
POSTGRES_PASSWORD=$(rand)
OPENSEARCH_ADMIN_PASSWORD=$OSADMIN
OPENSEARCH_APP_PASSWORD=$(rand)
SECRET_KEY=$(rand)$(rand)
API_KEY=$(rand)
ENV
  chmod 600 .env
  echo "Made deploy/.env with fresh random secrets (keep this file private, never commit it)."
fi
set -a; . ./.env; set +a
DC="docker compose -f docker-compose.prod.yml"

echo "== starting OpenSearch and Postgres =="
$DC up -d postgres opensearch
echo "== waiting for OpenSearch to be healthy (up to ~5 minutes) =="
for i in $(seq 1 60); do
  [ "$($DC ps --format '{{.Health}}' opensearch)" = "healthy" ] && break
  sleep 5
done

echo "== creating the least-privilege OpenSearch user =="
os() { $DC exec -T opensearch curl -sk -u "admin:$OPENSEARCH_ADMIN_PASSWORD" -X PUT "https://localhost:9200/_plugins/_security/api/$1" -H 'Content-Type: application/json' -d "$2"; echo; }
os roles/sentinel_events_rw '{"cluster_permissions":["cluster_composite_ops","cluster:monitor/main"],"index_permissions":[{"index_patterns":["sentinel-events*"],"allowed_actions":["indices_all"]}]}'
os internalusers/sentinel_app "{\"password\":\"$OPENSEARCH_APP_PASSWORD\"}"
os rolesmapping/sentinel_events_rw '{"users":["sentinel_app"]}'

echo "== building and starting the API and the website =="
$DC up -d --build

echo
echo "DONE. Site: https://$SITE"
echo "Next, make your admin login (it asks for a password, 12+ characters):"
echo "  docker compose -f deploy/docker-compose.prod.yml exec api python -m app.create_user --role admin YOURNAME"
echo "Service key for the collector/engine (keep private):  grep API_KEY deploy/.env"
