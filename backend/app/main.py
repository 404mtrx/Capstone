from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import alerts, audit, auth, cases, events, metrics, users

app = FastAPI(title="SentinelWatch API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],  # Vite dev server
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)
app.include_router(auth.router)
app.include_router(alerts.router)
app.include_router(cases.router)
app.include_router(audit.router)
app.include_router(users.router)
app.include_router(metrics.router)
app.include_router(events.router)


@app.get("/health")
def health():
    return {"status": "ok"}
