"""Login tokens and access checks (who is calling, and are they allowed)."""
import hmac
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, Header, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel import Session

from app.config import settings
from app.database import get_session
from app.models import User

ALGORITHM = "HS256"
bearer = HTTPBearer(auto_error=False)

ANALYST_UP = ("analyst", "lead", "admin")
LEAD_UP = ("lead", "admin")
ADMIN_ONLY = ("admin",)


def create_access_token(user: User) -> str:
    expires = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_minutes)
    payload = {"sub": str(user.id), "role": user.role, "exp": expires}
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def _unauthorized(detail="Not authenticated"):
    return HTTPException(401, detail, headers={"WWW-Authenticate": "Bearer"})


def _user_from_token(token: str, session: Session) -> User:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise _unauthorized("Invalid or expired token")
    user = session.get(User, user_id)
    if not user or not user.is_active:
        raise _unauthorized("Invalid or expired token")
    return user


def current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    session: Session = Depends(get_session),
) -> Optional[User]:
    """The signed-in user. Returns None only when AUTH_REQUIRED is false."""
    if not settings.auth_required:
        return None
    if creds is None:
        raise _unauthorized()
    return _user_from_token(creds.credentials, session)


def require_role(*roles: str):
    """Dependency: the caller must be signed in with one of `roles` (401 / 403)."""

    def check(user: Optional[User] = Depends(current_user)) -> Optional[User]:
        if not settings.auth_required:
            return None
        if user.role not in roles:
            raise HTTPException(403, "You do not have permission to do this")
        return user

    return check


as_analyst = require_role(*ANALYST_UP)
as_lead = require_role(*LEAD_UP)
as_admin = require_role(*ADMIN_ONLY)


def _key_ok(x_api_key: Optional[str]) -> bool:
    return bool(settings.api_key) and bool(x_api_key) and hmac.compare_digest(
        x_api_key.encode(), settings.api_key.encode()
    )


def service_or_role(*roles: str):
    """Dependency for the collector and detection engine: a valid X-API-Key header,
    or a signed-in user with one of `roles`."""

    def check(
        x_api_key: Optional[str] = Header(default=None),
        creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
        session: Session = Depends(get_session),
    ) -> Optional[User]:
        if not settings.auth_required or _key_ok(x_api_key):
            return None
        if creds is None:
            raise _unauthorized()
        user = _user_from_token(creds.credentials, session)
        if user.role not in roles:
            raise HTTPException(403, "You do not have permission to do this")
        return user

    return check
