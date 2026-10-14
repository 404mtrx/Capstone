# Backend local setup

1. `docker compose up -d postgres`
2. `cd backend && python3 -m venv .venv && source .venv/bin/activate`
3. `pip install -r requirements.txt`
4. `cp .env.example .env`
5. `alembic upgrade head`
6. `uvicorn app.main:app --reload` (then open http://127.0.0.1:8000/health)

Note: `user` and `case` are reserved words in SQL. Quote them in hand-written
queries, e.g. `select * from "user";`.
