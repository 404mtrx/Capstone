from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlmodel import Session, select

from app.auth import as_admin
from app.database import get_session
from app.models import AuditLog

router = APIRouter(prefix="/audit", tags=["audit"], dependencies=[Depends(as_admin)])


@router.get("", response_model=list[AuditLog])
def list_audit(
    action: Optional[str] = None,
    username: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
):
    stmt = select(AuditLog).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if username:
        stmt = stmt.where(AuditLog.username == username)
    return session.exec(stmt.offset(offset).limit(limit)).all()
