from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Optional, Union

from pydantic import BaseModel

from app.schemas import Severity


class EventIn(BaseModel):
    """The common event schema from the Sprint 1 design document."""

    timestamp: datetime
    source: str
    event_type: str
    username: Optional[str] = None
    source_ip: Optional[Union[IPv4Address, IPv6Address]] = None
    destination_ip: Optional[Union[IPv4Address, IPv6Address]] = None
    action: str
    severity: Severity
    message: str
    destination_port: Optional[int] = None
    hostname: Optional[str] = None
    protocol: Optional[str] = None
    event_id: Optional[str] = None
    process_name: Optional[str] = None
