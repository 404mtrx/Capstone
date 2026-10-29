from sqlmodel import Session, select

from app import create_user
from app.models import User
from app.security import verify_password


def test_create_user_cli(engine, monkeypatch):
    monkeypatch.setattr(create_user, "engine", engine)
    monkeypatch.setattr("sys.argv", ["create_user", "aayan", "--role", "admin"])
    monkeypatch.setattr(create_user.getpass, "getpass", lambda prompt: "correct-horse-battery")
    create_user.main()
    with Session(engine) as session:
        user = session.exec(select(User).where(User.username == "aayan")).one()
    assert user.role == "admin"
    assert user.password_hash != "correct-horse-battery"
    assert verify_password("correct-horse-battery", user.password_hash)
