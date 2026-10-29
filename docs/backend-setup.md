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
