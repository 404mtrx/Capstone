from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# Stored as plain strings in the DB (easier to change than Postgres enums);
# validate against these in the API layer.
ROLES = ("analyst", "lead", "admin")


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    password_hash: str
    role: str = Field(default="analyst")
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utcnow)


SEVERITIES = ("low", "medium", "high", "critical")
ALERT_STATUSES = ("new", "investigating", "escalated", "closed")


class Alert(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    rule_name: str = Field(index=True)
    severity: str = Field(default="medium", index=True)
    status: str = Field(default="new", index=True)
    source: Optional[str] = None
    source_ip: Optional[str] = Field(default=None, index=True)
    username: Optional[str] = None
    reason: str  # why the rule fired
    evidence: Optional[dict] = Field(default=None, sa_column=Column(JSON))
    assigned_to: Optional[int] = Field(default=None, foreign_key="user.id")
    created_at: datetime = Field(default_factory=utcnow, index=True)


class AuditLog(SQLModel, table=True):
    """Who did what, and when. Rows are only ever added."""

    __tablename__ = "audit_log"

    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=utcnow, index=True)
    user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    username: str = Field(index=True)  # "system" when no user (auth off or API key)
    action: str = Field(index=True)
    target_type: Optional[str] = None
    target_id: Optional[int] = None
    detail: Optional[dict] = Field(default=None, sa_column=Column(JSON))


CASE_STATUSES = ("open", "investigating", "contained", "closed")


class Case(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    alert_id: int = Field(foreign_key="alert.id", index=True)
    title: str
    status: str = Field(default="open", index=True)
    notes: Optional[str] = None
    owner_id: Optional[int] = Field(default=None, foreign_key="user.id")
    opened_at: datetime = Field(default_factory=utcnow)
    closed_at: Optional[datetime] = None
