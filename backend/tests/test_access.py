"""Who may call which endpoint (401 = not signed in, 403 = wrong role)."""
import pytest

ALERT = {"rule_name": "Failed Login Detected", "severity": "medium", "message": "m"}
EVENT = {
    "timestamp": "2026-10-08T14:30:00Z", "source": "linux", "event_type": "failed_login",
    "action": "failure", "severity": "medium", "message": "m", "source_ip": "10.0.0.9",
}
KEY = {"X-API-Key": "test-service-key"}


def make_alert(client):
    return client.post("/alerts", json=ALERT, headers=KEY).json()["id"]


PROTECTED = [
    ("get", "/alerts"), ("get", "/alerts/1"), ("patch", "/alerts/1"),
    ("get", "/cases"), ("post", "/cases"), ("get", "/cases/1"), ("patch", "/cases/1"),
    ("get", "/events"), ("post", "/alerts"), ("post", "/events"),
]


def test_health_and_login_are_public(client, auth_on):
    assert client.get("/health").status_code == 200
    assert client.post("/auth/login", json={"username": "x", "password": "y"}).status_code == 401


@pytest.mark.parametrize("method,path", PROTECTED)
def test_no_token_is_401(client, auth_on, method, path):
    r = getattr(client, method)(path, json={}) if method in ("post", "patch") else getattr(client, method)(path)
    assert r.status_code == 401


@pytest.mark.parametrize("method,path", PROTECTED)
def test_garbage_token_is_401(client, auth_on, method, path):
    h = {"Authorization": "Bearer garbage"}
    r = getattr(client, method)(path, json={}, headers=h) if method in ("post", "patch") else getattr(client, method)(path, headers=h)
    assert r.status_code == 401


def test_api_key_lets_the_engine_and_collector_in(client, auth_on):
    assert client.post("/alerts", json=ALERT, headers=KEY).status_code == 201
    assert client.get("/alerts", headers=KEY).status_code == 200
    assert client.post("/events", json=[EVENT], headers=KEY).status_code == 201
    assert client.get("/events", headers=KEY).status_code == 200


def test_wrong_api_key_is_401(client, auth_on):
    assert client.post("/alerts", json=ALERT, headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/alerts", headers={"X-API-Key": ""}).status_code == 401


def test_api_key_does_not_open_triage_or_cases(client, auth_on):
    alert_id = make_alert(client)
    assert client.patch(f"/alerts/{alert_id}", json={"status": "closed"}, headers=KEY).status_code == 401
    assert client.get("/cases", headers=KEY).status_code == 401
    assert client.post("/cases", json={"alert_id": alert_id, "title": "t"}, headers=KEY).status_code == 401


def test_no_api_key_configured_means_the_key_never_matches(client, auth_on, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "api_key", "")
    assert client.post("/alerts", json=ALERT, headers={"X-API-Key": ""}).status_code == 401


@pytest.mark.parametrize("role", ["analyst", "lead", "admin"])
def test_every_role_can_triage(client, auth_on, make_login_user, login, role):
    make_login_user("u1", role)
    h = login("u1")
    alert_id = make_alert(client)
    assert client.get("/alerts", headers=h).status_code == 200
    assert client.patch(f"/alerts/{alert_id}", json={"status": "investigating"}, headers=h).status_code == 200
    r = client.post("/cases", json={"alert_id": alert_id, "title": "t"}, headers=h)
    assert r.status_code == 201
    assert client.get("/cases", headers=h).status_code == 200
    assert client.get("/events", headers=h).status_code == 200


def test_only_admin_can_create_alerts_and_events_by_hand(client, auth_on, make_login_user, login):
    make_login_user("an", "analyst"); make_login_user("ld", "lead"); make_login_user("ad", "admin")
    for name, expected in (("an", 403), ("ld", 403), ("ad", 201)):
        assert client.post("/alerts", json=ALERT, headers=login(name)).status_code == expected
    assert client.post("/events", json=[EVENT], headers=login("an")).status_code == 403
    assert client.post("/events", json=[EVENT], headers=login("ad")).status_code == 201


def test_auth_off_lets_everything_through(client):  # AUTH_REQUIRED=false (the default in tests)
    assert client.post("/alerts", json=ALERT).status_code == 201
    assert client.get("/cases").status_code == 200
