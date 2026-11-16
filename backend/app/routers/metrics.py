from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from app.auth import as_lead
from app.database import get_session
from app.models import ALERT_STATUSES, SEVERITIES, Alert, Case

router = APIRouter(prefix="/metrics", tags=["metrics"], dependencies=[Depends(as_lead)])


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _mean_seconds(pairs) -> Optional[float]:
    seconds = [(_aware(end) - _aware(start)).total_seconds() for start, end in pairs]
    return round(sum(seconds) / len(seconds), 1) if seconds else None


@router.get("/summary")
def summary(
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    session: Session = Depends(get_session),
):
    """Alert volume and response times for alerts created between start and end."""
    stmt = select(Alert)
    if start:
        stmt = stmt.where(Alert.created_at >= start)
    if end:
        stmt = stmt.where(Alert.created_at <= end)
    alerts = session.exec(stmt).all()
    open_cases = session.exec(select(Case).where(Case.status != "closed")).all()
    return {
        "start": start,
        "end": end,
        "total_alerts": len(alerts),
        "by_severity": {s: sum(a.severity == s for a in alerts) for s in SEVERITIES},
        "by_status": {s: sum(a.status == s for a in alerts) for s in ALERT_STATUSES},
        "mean_time_to_acknowledge_seconds": _mean_seconds(
            (a.created_at, a.acknowledged_at) for a in alerts if a.acknowledged_at
        ),
        "mean_time_to_close_seconds": _mean_seconds(
            (a.created_at, a.closed_at) for a in alerts if a.closed_at
        ),
        "open_cases": len(open_cases),
    }
