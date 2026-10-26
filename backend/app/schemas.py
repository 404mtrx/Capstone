from datetime import datetime
from typing import Literal, Optional

from pydantic import AliasChoices, BaseModel, Field

Severity = Literal["low", "medium", "high", "critical"]
AlertStatus = Literal["new", "investigating", "escalated", "closed"]


class AlertCreate(BaseModel):
    """Accepts the dict our detection engine produces (it sends `message`)."""

    rule_name: str
    severity: Severity = "medium"
    reason: str = Field(validation_alias=AliasChoices("reason", "message"))
    source: Optional[str] = None
    source_ip: Optional[str] = None
    username: Optional[str] = None
    evidence: Optional[dict] = None
    timestamp: Optional[datetime] = None  # stored as created_at


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    assigned_to: Optional[int] = None  # send null to unassign


CaseStatus = Literal["open", "investigating", "contained", "closed"]


class CaseCreate(BaseModel):
    alert_id: int
    title: str
    notes: Optional[str] = None
    owner_id: Optional[int] = None


class CaseUpdate(BaseModel):
    title: Optional[str] = None
    status: Optional[CaseStatus] = None
    notes: Optional[str] = None
    owner_id: Optional[int] = None  # send null to remove the owner
