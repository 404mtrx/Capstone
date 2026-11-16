from sqlmodel import Session, select

from app.models import User
from app.security import verify_password

NEW = {"username": "newuser", "password": "a-long-enough-pass", "role": "lead"}


def admin_headers(make_login_user, login, name="ad"):
    make_login_user(name, "admin")
    return login(name)


def test_admin_creates_user_with_hashed_password(client, auth_on, make_login_user, login, engine):
    h = admin_headers(make_login_user, login)
    r = client.post("/users", json=NEW, headers=h)
    assert r.status_code == 201
    assert r.json()["role"] == "lead" and "password" not in str(r.json())
    with Session(engine) as session:
        user = session.exec(select(User).where(User.username == "newuser")).one()
    assert user.password_hash != NEW["password"] and verify_password(NEW["password"], user.password_hash)
    assert client.post("/auth/login", json={"username": "newuser", "password": NEW["password"]}).status_code == 200


def test_create_user_validation(client, auth_on, make_login_user, login):
    h = admin_headers(make_login_user, login)
    assert client.post("/users", json={**NEW, "password": "short"}, headers=h).status_code == 422
    assert client.post("/users", json={**NEW, "role": "root"}, headers=h).status_code == 422
    assert client.post("/users", json={**NEW, "username": "ab"}, headers=h).status_code == 422
    assert client.post("/users", json=NEW, headers=h).status_code == 201
    assert client.post("/users", json=NEW, headers=h).status_code == 409  # duplicate name


def test_user_list_never_shows_hashes(client, auth_on, make_login_user, login):
    h = admin_headers(make_login_user, login)
    text = client.get("/users", headers=h).text
    assert "argon2" not in text and "password" not in text


def test_non_admins_cannot_manage_users(client, auth_on, make_login_user, login):
    make_login_user("an", "analyst"); make_login_user("ld", "lead")
    for name in ("an", "ld"):
        h = login(name)
        assert client.get("/users", headers=h).status_code == 403
        assert client.post("/users", json=NEW, headers=h).status_code == 403
        assert client.patch("/users/1", json={"role": "admin"}, headers=h).status_code == 403
    assert client.get("/users").status_code == 401


def test_change_role_and_deactivate(client, auth_on, make_login_user, login):
    h = admin_headers(make_login_user, login)
    uid = client.post("/users", json=NEW, headers=h).json()["id"]
    assert client.patch(f"/users/{uid}", json={"role": "analyst"}, headers=h).json()["role"] == "analyst"
    r = client.patch(f"/users/{uid}", json={"is_active": False}, headers=h)
    assert r.json()["is_active"] is False
    assert client.post("/auth/login", json={"username": "newuser", "password": NEW["password"]}).status_code == 401
    assert client.patch("/users/9999", json={"role": "lead"}, headers=h).status_code == 404


def test_last_active_admin_cannot_be_removed(client, auth_on, make_login_user, login):
    h = admin_headers(make_login_user, login)
    assert client.patch("/users/1", json={"is_active": False}, headers=h).status_code == 409
    assert client.patch("/users/1", json={"role": "analyst"}, headers=h).status_code == 409
    other = client.post("/users", json={**NEW, "role": "admin"}, headers=h).json()["id"]
    assert client.patch(f"/users/{other}", json={"is_active": False}, headers=h).status_code == 200


def test_user_changes_are_audited(client, auth_on, make_login_user, login):
    h = admin_headers(make_login_user, login)
    uid = client.post("/users", json=NEW, headers=h).json()["id"]
    client.patch(f"/users/{uid}", json={"role": "analyst"}, headers=h)
    actions = [row["action"] for row in client.get("/audit", headers=h).json()]
    assert "user_create" in actions and "user_update" in actions
    assert NEW["password"] not in client.get("/audit", headers=h).text
