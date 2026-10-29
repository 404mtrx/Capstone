from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import alerts, cases, events

app = FastAPI(title="SentinelWatch API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],  # Vite dev server
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type"],
)
app.include_router(alerts.router)
app.include_router(cases.router)
app.include_router(events.router)


@app.get("/health")
def health():
    return {"status": "ok"}
