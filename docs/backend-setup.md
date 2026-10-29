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
Check it with `curl http://localhost:9200` once the container is healthy.

## API (http://127.0.0.1:8000/docs)

- `POST /alerts`, `GET /alerts`, `GET /alerts/{id}`, `PATCH /alerts/{id}`
- `POST /cases`, `GET /cases`, `GET /cases/{id}`, `PATCH /cases/{id}`
- `POST /events` (list of normalized events), `GET /events?username=&source_ip=&event_type=&severity=`

`POST /alerts` accepts the dict the detection engine returns as-is
(`message` is stored as the alert reason, `timestamp` as `created_at`).

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
