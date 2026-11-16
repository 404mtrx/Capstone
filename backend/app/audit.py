"""Record security-relevant actions in the audit_log table."""
from typing import Optional

from sqlmodel import Session

from app.models import AuditLog, User


def record(
    session: Session,
    user: Optional[User],
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[int] = None,
    detail: Optional[dict] = None,
    username: Optional[str] = None,
) -> None:
    """Add an audit row to the current transaction (the caller commits).
    Never put passwords, tokens or hashes in `detail`."""
    session.add(
        AuditLog(
            user_id=user.id if user else None,
            username=(user.username if user else (username or "system"))[:150],
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail=detail,
        )
    )
