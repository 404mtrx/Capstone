from datetime import datetime, timedelta, timezone

import jwt

from app.config import settings


def test_login_returns_token_and_user(client, auth_on, make_login_user):
    make_login_user("amy", "lead")
    r = client.post("/auth/login", json={"username": "amy", "password": "correct-horse-battery"})
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["user"]["username"] == "amy" and body["user"]["role"] == "lead"
    assert "password" not in str(body) and "argon2" not in str(body)


def test_wrong_password_and_unknown_user_look_the_same(client, auth_on, make_login_user):
    make_login_user("amy")
    bad_pw = client.post("/auth/login", json={"username": "amy", "password": "wrong-password-123"})
    bad_user = client.post("/auth/login", json={"username": "nobody", "password": "wrong-password-123"})
    assert bad_pw.status_code == bad_user.status_code == 401
    assert bad_pw.json() == bad_user.json()


def test_inactive_user_cannot_log_in(client, auth_on, make_login_user):
    make_login_user("old", active=False)
    r = client.post("/auth/login", json={"username": "old", "password": "correct-horse-battery"})
    assert r.status_code == 401


def test_me_needs_a_token(client, auth_on, make_login_user, login):
    make_login_user("amy")
    assert client.get("/auth/me").status_code == 401
    r = client.get("/auth/me", headers=login("amy"))
    assert r.status_code == 200 and r.json()["username"] == "amy"


def test_expired_token_is_rejected(client, auth_on, make_login_user):
    uid = make_login_user("amy")
    old = datetime.now(timezone.utc) - timedelta(minutes=5)
    token = jwt.encode({"sub": str(uid), "role": "analyst", "exp": old}, settings.secret_key, algorithm="HS256")
    r = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_tampered_or_wrong_key_token_is_rejected(client, auth_on, make_login_user):
    uid = make_login_user("amy")
    exp = datetime.now(timezone.utc) + timedelta(minutes=5)
    forged = jwt.encode({"sub": str(uid), "role": "admin", "exp": exp}, "some-other-secret-key-0123456789abcd", algorithm="HS256")
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    assert client.get("/auth/me", headers={"Authorization": "Bearer not.a.token"}).status_code == 401


def test_deactivated_user_token_stops_working(client, auth_on, make_login_user, login, engine):
    from sqlmodel import Session
    from app.models import User

    uid = make_login_user("amy")
    headers = login("amy")
    with Session(engine) as session:
        user = session.get(User, uid)
        user.is_active = False
        session.add(user)
        session.commit()
    assert client.get("/auth/me", headers=headers).status_code == 401


def test_token_does_not_trust_role_in_payload(client, auth_on, make_login_user):
    """The role comes from the database, so a user cannot promote themselves."""
    uid = make_login_user("amy", "analyst")
    exp = datetime.now(timezone.utc) + timedelta(minutes=5)
    token = jwt.encode({"sub": str(uid), "role": "admin", "exp": exp}, settings.secret_key, algorithm="HS256")
    r = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.json()["role"] == "analyst"
