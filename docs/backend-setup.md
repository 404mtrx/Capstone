# Backend local setup

1. `docker compose up -d postgres`
2. `cd backend && python3 -m venv .venv && source .venv/bin/activate`
3. `pip install -r requirements.txt`
4. `cp .env.example .env`
5. `alembic upgrade head`
6. `uvicorn app.main:app --reload` (then open http://127.0.0.1:8000/health)

Note: `user` and `case` are reserved words in SQL. Quote them in hand-written
queries, e.g. `select * from "user";`.

## Services

`docker compose up -d` starts PostgreSQL (port 5432) and OpenSearch (port 9200).
OpenSearch needs about 1 GB of RAM; give Docker Desktop at least 4 GB.

OpenSearch security is ON: it uses HTTPS (a self-signed demo certificate) and needs a login.
- Admin login: user `admin`, password from `OPENSEARCH_ADMIN_PASSWORD` in a `.env` file next to
  `docker-compose.yml` (a development default is built in).
- The API does not use the admin account. Run `bash scripts/opensearch_setup_user.sh` once after the
  container is healthy; it creates the `sentinel_app` user that can only use the `sentinel-events` index.
  Put the same user and password in `backend/.env` (`OPENSEARCH_USER`, `OPENSEARCH_PASSWORD`).
- Check it: `curl -sk https://localhost:9200` must say 401, and
  `curl -sk -u admin:<password> https://localhost:9200` must show the cluster.
- If you start from an older OpenSearch volume that had security off, recreate it:
  `docker compose stop opensearch && docker compose rm -f opensearch && docker volume rm $(docker volume ls -q | grep osdata)`
  then `docker compose up -d` and resend your events (this keeps PostgreSQL).

## API (http://127.0.0.1:8000/docs)

- `POST /alerts`, `GET /alerts`, `GET /alerts/{id}`, `PATCH /alerts/{id}`
- `POST /cases`, `GET /cases`, `GET /cases/{id}`, `PATCH /cases/{id}`
- `POST /events` (list of normalized events), `GET /events?username=&source_ip=&event_type=&severity=`

`POST /alerts` accepts the dict the detection engine returns as-is
(`message` is stored as the alert reason, `timestamp` as `created_at`).

## Login and access

Copy `backend/.env.example` to `backend/.env` and set `SECRET_KEY` (a long random string) and `API_KEY`.

- `POST /auth/login` with `{"username": "...", "password": "..."}` returns `{"access_token", "token_type": "bearer", "user": {...}}`.
  Send the token as `Authorization: Bearer <token>` on every other request. Tokens expire after `ACCESS_TOKEN_MINUTES`.
- `GET /auth/me` returns the signed-in user.
- Wrong username, wrong password and inactive account all return the same 401 message.
- `AUTH_REQUIRED=false` in `.env` turns access checks off (for a demo only; never for real use).

## Users and tests

- Create a user: `python -m app.create_user <username> --role admin` (run from `backend/`)
- Run tests: `cd backend && pytest` (no Docker needed; uses in-memory SQLite and a fake event store)

## Run the demo

1. `docker compose up -d` and wait until `docker compose ps` shows both containers healthy.
2. `cd backend && source .venv/bin/activate && alembic upgrade head && uvicorn app.main:app --reload`
3. In a second terminal, from the repository root:
   `python collector/normalize_logs.py` (creates `normalized_events.json`)
4. Send the events (replace with Kritika's `send_events.py` when it exists):
   `curl -X POST http://127.0.0.1:8000/events -H "Content-Type: application/json" -d @normalized_events.json`
5. Search them: `curl "http://127.0.0.1:8000/events?event_type=failed_login"`
6. Run the detection engine, then list alerts: `curl http://127.0.0.1:8000/alerts`
7. Open a case: `curl -X POST http://127.0.0.1:8000/cases -H "Content-Type: application/json" -d '{"alert_id": 1, "title": "Investigate failed logins"}'`
8. Start the dashboard: `cd frontend/sentinelwatch-ui && npm install && npm run dev`

Error cases to show: a bad severity returns 422, an illegal status change returns 409,
a second open case on the same alert returns 409, and `docker compose stop opensearch`
makes `/events` return 503.

## Who may call what

| Endpoint | Allowed |
|---|---|
| `GET /health`, `POST /auth/login` | anyone |
| `GET /alerts`, `GET /events` | analyst, lead, admin, or the service API key |
| `POST /alerts`, `POST /events` | admin or the service API key |
| `PATCH /alerts/{id}`, all `/cases` endpoints | analyst, lead, admin |
| `GET /metrics/summary` | lead, admin |
| `/users` (list, create, change role or deactivate), `GET /audit` | admin |

The detection engine and `collector/send_events.py` send the key from the environment:
`export SENTINEL_API_KEY=<the API_KEY value from backend/.env>`.
No token gives 401; a signed-in user with the wrong role gives 403.

## Checking it

- `bash scripts/test_script.sh` runs the Sprint 2 checks (set `AUTH_REQUIRED=false` in `backend/.env` for that one).
- `bash scripts/test_auth.sh` runs the login, role, API key, audit, user and metrics checks
  (needs `AUTH_REQUIRED=true` and `API_KEY` in `backend/.env`, and the API running).
- Both save their output in `docs/test-evidence/`.
- Create the first administrator with `python -m app.create_user <name> --role admin`; after that, administrators create users with `POST /users`.
