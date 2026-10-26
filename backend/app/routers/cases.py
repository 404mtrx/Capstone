from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select

from app.database import get_session
from app.models import Alert, Case, User, utcnow
from app.schemas import CaseCreate, CaseStatus, CaseUpdate

router = APIRouter(prefix="/cases", tags=["cases"])


def _check_owner(session: Session, owner_id: Optional[int]):
    if owner_id is not None and not session.get(User, owner_id):
        raise HTTPException(400, "owner_id user does not exist")


@router.post("", response_model=Case, status_code=201)
def create_case(payload: CaseCreate, session: Session = Depends(get_session)):
    alert = session.get(Alert, payload.alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    _check_owner(session, payload.owner_id)

    existing = session.exec(
        select(Case).where(Case.alert_id == alert.id, Case.status != "closed")
    ).first()
    if existing:
        raise HTTPException(409, f"Alert already has an open case (id {existing.id})")

    case = Case(**payload.model_dump())
    # Opening a case means someone is working the alert.
    if alert.status == "new":
        alert.status = "investigating"
        session.add(alert)
    session.add(case)
    session.commit()
    session.refresh(case)
    return case


@router.get("", response_model=list[Case])
def list_cases(
    status: Optional[CaseStatus] = None,
    owner_id: Optional[int] = None,
    alert_id: Optional[int] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
):
    stmt = select(Case).order_by(Case.opened_at.desc())
    if status:
        stmt = stmt.where(Case.status == status)
    if owner_id is not None:
        stmt = stmt.where(Case.owner_id == owner_id)
    if alert_id is not None:
        stmt = stmt.where(Case.alert_id == alert_id)
    return session.exec(stmt.offset(offset).limit(limit)).all()


@router.get("/{case_id}", response_model=Case)
def get_case(case_id: int, session: Session = Depends(get_session)):
    case = session.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    return case


@router.patch("/{case_id}", response_model=Case)
def update_case(
    case_id: int, payload: CaseUpdate, session: Session = Depends(get_session)
):
    case = session.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")

    changes = payload.model_dump(exclude_unset=True)
    if "owner_id" in changes:
        _check_owner(session, changes["owner_id"])
    for required in ("title", "status"):  # these can't be set to null
        if changes.get(required, "") is None:
            changes.pop(required)

    for field, value in changes.items():
        setattr(case, field, value)

    if "status" in changes:
        case.closed_at = utcnow() if case.status == "closed" else None

    session.add(case)
    session.commit()
    session.refresh(case)
    return case
