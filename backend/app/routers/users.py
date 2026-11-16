from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app import audit
from app.auth import as_admin
from app.database import get_session
from app.models import User
from app.schemas import UserCreate, UserRead, UserUpdate
from app.security import hash_password

router = APIRouter(prefix="/users", tags=["users"], dependencies=[Depends(as_admin)])


def _read(user: User) -> UserRead:
    return UserRead(id=user.id, username=user.username, role=user.role, is_active=user.is_active)


@router.get("", response_model=list[UserRead])
def list_users(session: Session = Depends(get_session)):
    return [_read(u) for u in session.exec(select(User).order_by(User.id)).all()]


@router.post("", response_model=UserRead, status_code=201)
def create_user(
    payload: UserCreate,
    session: Session = Depends(get_session),
    admin: Optional[User] = Depends(as_admin),
):
    if session.exec(select(User).where(User.username == payload.username)).first():
        raise HTTPException(409, "That username is already taken")
    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=payload.role,
    )
    session.add(user)
    session.flush()
    audit.record(
        session, admin, "user_create", "user", user.id,
        {"username": user.username, "role": user.role},
    )
    session.commit()
    session.refresh(user)
    return _read(user)


@router.patch("/{user_id}", response_model=UserRead)
def update_user(
    user_id: int,
    payload: UserUpdate,
    session: Session = Depends(get_session),
    admin: Optional[User] = Depends(as_admin),
):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    changes = payload.model_dump(exclude_unset=True, exclude_none=True)

    # Never leave the system without an active administrator.
    leaving_admin = user.role == "admin" and user.is_active and (
        changes.get("role", "admin") != "admin" or changes.get("is_active", True) is False
    )
    if leaving_admin:
        other = session.exec(
            select(User).where(User.role == "admin", User.is_active == True, User.id != user.id)  # noqa: E712
        ).first()
        if not other:
            raise HTTPException(409, "There must be at least one active administrator")

    for field, value in changes.items():
        setattr(user, field, value)
    audit.record(session, admin, "user_update", "user", user.id, {"changes": changes})
    session.add(user)
    session.commit()
    session.refresh(user)
    return _read(user)
