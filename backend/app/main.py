from fastapi import FastAPI

from app.routers import alerts, cases, events

app = FastAPI(title="SentinelWatch API", version="0.2.0")
app.include_router(alerts.router)
app.include_router(cases.router)
app.include_router(events.router)


@app.get("/health")
def health():
    return {"status": "ok"}
