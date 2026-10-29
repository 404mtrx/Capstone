from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from opensearchpy.exceptions import OpenSearchException

from app.event_schemas import EventIn
from app.event_store import get_event_store

router = APIRouter(prefix="/events", tags=["events"])


@router.post("", status_code=201)
def ingest_events(events: list[EventIn], store=Depends(get_event_store)):
    docs = [e.model_dump(mode="json", exclude_none=True) for e in events]
    try:
        indexed = store.index_events(docs)
    except OpenSearchException as exc:
        raise HTTPException(503, f"OpenSearch unavailable: {exc}")
    return {"indexed": indexed}


@router.get("")
def search_events(
    username: Optional[str] = None,
    source_ip: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    size: int = Query(50, ge=1, le=500),
    store=Depends(get_event_store),
):
    filters = {
        k: v
        for k, v in {
            "username": username,
            "source_ip": source_ip,
            "event_type": event_type,
            "severity": severity,
        }.items()
        if v is not None
    }
    try:
        return store.search(filters, size)
    except OpenSearchException as exc:
        raise HTTPException(503, f"OpenSearch unavailable: {exc}")
