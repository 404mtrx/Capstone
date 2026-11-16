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


Role = Literal["analyst", "lead", "admin"]


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=12, max_length=128)
    role: Role = "analyst"


class UserUpdate(BaseModel):
    role: Optional[Role] = None
    is_active: Optional[bool] = None


class LoginRequest(BaseModel):
    username: str
    password: str


class UserRead(BaseModel):
    id: int
    username: str
    role: str
    is_active: bool


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserRead
