from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select

from app import audit
from app.auth import ADMIN_ONLY, ANALYST_UP, as_analyst, service_or_role
from app.database import get_session
from app.models import Alert, User
from app.schemas import AlertCreate, AlertStatus, AlertUpdate, Severity

router = APIRouter(prefix="/alerts", tags=["alerts"])

# Which status changes are allowed (new -> investigating -> escalated/closed).
ALLOWED_TRANSITIONS = {
    "new": {"investigating", "closed"},
    "investigating": {"escalated", "closed"},
    "escalated": {"investigating", "closed"},
    "closed": {"investigating"},  # reopen
}


@router.post(
    "",
    response_model=Alert,
    status_code=201,
    dependencies=[Depends(service_or_role(*ADMIN_ONLY))],  # detection engine (API key) or admin
)
def create_alert(payload: AlertCreate, session: Session = Depends(get_session)):
    alert = Alert(**payload.model_dump(exclude={"timestamp"}))
    if payload.timestamp:
        alert.created_at = payload.timestamp
    session.add(alert)
    session.commit()
    session.refresh(alert)
    return alert


@router.get(
    "", response_model=list[Alert], dependencies=[Depends(service_or_role(*ANALYST_UP))]
)
def list_alerts(
    severity: Optional[Severity] = None,
    status: Optional[AlertStatus] = None,
    source_ip: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
):
    stmt = select(Alert).order_by(Alert.created_at.desc())
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if status:
        stmt = stmt.where(Alert.status == status)
    if source_ip:
        stmt = stmt.where(Alert.source_ip == source_ip)
    return session.exec(stmt.offset(offset).limit(limit)).all()


@router.get(
    "/{alert_id}", response_model=Alert, dependencies=[Depends(as_analyst)]
)
def get_alert(alert_id: int, session: Session = Depends(get_session)):
    alert = session.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=Alert)
def update_alert(
    alert_id: int,
    payload: AlertUpdate,
    session: Session = Depends(get_session),
    user: Optional[User] = Depends(as_analyst),
):
    alert = session.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")

    if payload.status is not None and payload.status != alert.status:
        if payload.status not in ALLOWED_TRANSITIONS[alert.status]:
            raise HTTPException(
                409, f"Cannot move alert from '{alert.status}' to '{payload.status}'"
            )
        audit.record(
            session, user, "alert_status_change", "alert", alert.id,
            {"from": alert.status, "to": payload.status},
        )
        alert.status = payload.status

    if "assigned_to" in payload.model_fields_set:
        if payload.assigned_to is not None and not session.get(User, payload.assigned_to):
            raise HTTPException(400, "assigned_to user does not exist")
        audit.record(
            session, user, "alert_assign", "alert", alert.id, {"assigned_to": payload.assigned_to}
        )
        alert.assigned_to = payload.assigned_to

    session.add(alert)
    session.commit()
    session.refresh(alert)
    return alert
