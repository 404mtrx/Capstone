from fastapi import FastAPI

from app.routers import alerts

app = FastAPI(title="SentinelWatch API", version="0.2.0")
app.include_router(alerts.router)


@app.get("/health")
def health():
    return {"status": "ok"}
