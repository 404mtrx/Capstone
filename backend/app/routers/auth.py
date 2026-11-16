from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app import audit
from app.auth import create_access_token, current_user
from app.database import get_session
from app.models import User
from app.schemas import LoginRequest, LoginResponse, UserRead
from app.security import hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])

# Checked when the username does not exist, so a wrong username and a wrong password
# take about the same time.
_DUMMY_HASH = hash_password("not-a-real-password")


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == payload.username)).first()
    ok = verify_password(payload.password, user.password_hash if user else _DUMMY_HASH)
    # Same message for a wrong username, a wrong password and an inactive account.
    if not user or not ok or not user.is_active:
        audit.record(session, None, "login_failure", username=payload.username)
        session.commit()
        raise HTTPException(401, "Incorrect username or password")
    audit.record(session, user, "login_success")
    session.commit()
    return LoginResponse(
        access_token=create_access_token(user),
        user=UserRead(id=user.id, username=user.username, role=user.role, is_active=user.is_active),
    )


@router.get("/me", response_model=UserRead)
def me(user: Optional[User] = Depends(current_user)):
    if user is None:  # AUTH_REQUIRED=false
        raise HTTPException(401, "Authentication is turned off")
    return UserRead(id=user.id, username=user.username, role=user.role, is_active=user.is_active)
