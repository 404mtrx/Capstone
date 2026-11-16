from sqlmodel import Session, select

from app.models import AuditLog

ALERT = {"rule_name": "Failed Login Detected", "severity": "medium", "message": "m"}
KEY = {"X-API-Key": "test-service-key"}


def rows(engine, action=None):
    with Session(engine) as session:
        stmt = select(AuditLog)
        if action:
            stmt = stmt.where(AuditLog.action == action)
        return session.exec(stmt.order_by(AuditLog.id)).all()


def test_login_success_and_failure_are_recorded(client, auth_on, make_login_user, engine):
    make_login_user("amy")
    client.post("/auth/login", json={"username": "amy", "password": "wrong-password-123"})
    client.post("/auth/login", json={"username": "amy", "password": "correct-horse-battery"})
    fail, ok = rows(engine, "login_failure")[0], rows(engine, "login_success")[0]
    assert fail.username == "amy" and ok.username == "amy"
    assert "password" not in str(fail.detail) + str(ok.detail)


def test_status_change_and_assignment_are_recorded(client, auth_on, make_login_user, login, engine):
    uid = make_login_user("amy")
    h = login("amy")
    alert_id = client.post("/alerts", json=ALERT, headers=KEY).json()["id"]
    client.patch(f"/alerts/{alert_id}", json={"status": "investigating", "assigned_to": uid}, headers=h)
    change = rows(engine, "alert_status_change")[0]
    assert change.username == "amy" and change.target_id == alert_id
    assert change.detail == {"from": "new", "to": "investigating"}
    assert rows(engine, "alert_assign")[0].detail == {"assigned_to": uid}


def test_refused_status_change_is_not_recorded(client, auth_on, make_login_user, login, engine):
    make_login_user("amy")
    alert_id = client.post("/alerts", json=ALERT, headers=KEY).json()["id"]
    r = client.patch(f"/alerts/{alert_id}", json={"status": "escalated"}, headers=login("amy"))
    assert r.status_code == 409
    assert rows(engine, "alert_status_change") == []


def test_case_open_and_update_are_recorded(client, auth_on, make_login_user, login, engine):
    make_login_user("amy")
    h = login("amy")
    alert_id = client.post("/alerts", json=ALERT, headers=KEY).json()["id"]
    case_id = client.post("/cases", json={"alert_id": alert_id, "title": "t"}, headers=h).json()["id"]
    client.patch(f"/cases/{case_id}", json={"status": "closed", "notes": "secret note text"}, headers=h)
    assert rows(engine, "case_open")[0].detail == {"alert_id": alert_id, "title": "t"}
    upd = rows(engine, "case_update")[0]
    assert upd.detail == {"fields": ["notes", "status"], "status": "closed"}
    assert "secret note text" not in str(upd.detail)  # content is not copied into the log


def test_create_user_command_is_recorded(engine, monkeypatch):
    from app import create_user
    monkeypatch.setattr(create_user, "engine", engine)
    monkeypatch.setattr("sys.argv", ["create_user", "bob", "--role", "lead"])
    monkeypatch.setattr(create_user.getpass, "getpass", lambda prompt: "correct-horse-battery")
    create_user.main()
    row = rows(engine, "user_create")[0]
    assert row.username == "cli" and row.detail == {"username": "bob", "role": "lead"}


def test_only_admin_can_read_the_audit_log(client, auth_on, make_login_user, login):
    make_login_user("an", "analyst"); make_login_user("ld", "lead"); make_login_user("ad", "admin")
    assert client.get("/audit").status_code == 401
    assert client.get("/audit", headers=login("an")).status_code == 403
    assert client.get("/audit", headers=login("ld")).status_code == 403
    assert client.get("/audit", headers=login("ad")).status_code == 200
    assert client.get("/audit", headers=KEY).status_code == 401  # the API key is not enough


def test_audit_filters_and_newest_first(client, auth_on, make_login_user, login):
    make_login_user("ad", "admin")
    client.post("/auth/login", json={"username": "ghost", "password": "x" * 12})
    h = login("ad")
    body = client.get("/audit", headers=h).json()
    assert body[0]["action"] == "login_success" and body[-1]["action"] == "login_failure"
    only = client.get("/audit?action=login_failure&username=ghost", headers=h).json()
    assert len(only) == 1 and only[0]["username"] == "ghost"
    assert client.get("/audit?limit=0", headers=h).status_code == 422


def test_audit_log_has_no_update_or_delete_endpoint(client, auth_on, make_login_user, login):
    make_login_user("ad", "admin")
    h = login("ad")
    assert client.delete("/audit/1", headers=h).status_code in (404, 405)
    assert client.patch("/audit/1", json={}, headers=h).status_code in (404, 405)
