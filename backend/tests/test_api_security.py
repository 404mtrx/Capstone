"""Hostile-input checks on the API (the password hashing tests are in test_security.py)."""
import pytest

KEY = {"X-API-Key": "test-service-key"}
ALERT = {"rule_name": "Failed Login Detected", "severity": "medium", "message": "m"}


@pytest.mark.parametrize("bad", ["' OR '1'='1", "1; DROP TABLE alert;--", "\" OR 1=1 --", "%27%20OR%201=1"])
def test_sql_looking_filters_return_no_rows_not_errors(client, auth_on, make_login_user, login, bad):
    make_login_user("an")
    client.post("/alerts", json=ALERT, headers=KEY)
    h = login("an")
    r = client.get("/alerts", params={"source_ip": bad}, headers=h)
    assert r.status_code == 200 and r.json() == []
    assert len(client.get("/alerts", headers=h).json()) == 1  # table still there


@pytest.mark.parametrize("bad", ["' OR 1=1 --", "x' UNION SELECT 1 --"])
def test_sql_looking_login_is_just_a_wrong_password(client, auth_on, make_login_user, bad):
    make_login_user("amy")
    assert client.post("/auth/login", json={"username": bad, "password": bad + "xxxx"}).status_code == 401
    assert client.post("/auth/login", json={"username": "amy", "password": bad}).status_code == 401


def test_oversized_and_negative_paging_values_are_rejected(client, auth_on, make_login_user, login):
    make_login_user("an")
    h = login("an")
    for query in ("limit=1000", "limit=0", "limit=-1", "offset=-5"):
        assert client.get(f"/alerts?{query}", headers=h).status_code == 422
    assert client.get("/events?size=100000", headers=h).status_code == 422


def test_unknown_severity_status_and_ip_inputs_are_422(client, auth_on, make_login_user, login):
    make_login_user("an")
    h = login("an")
    assert client.get("/alerts?severity=urgent", headers=h).status_code == 422
    assert client.get("/alerts?status=done", headers=h).status_code == 422
    assert client.post("/alerts", json={**ALERT, "severity": "urgent"}, headers=KEY).status_code == 422
    bad_event = {"timestamp": "2026-10-08T14:30:00Z", "source": "linux", "event_type": "x",
                 "action": "failure", "severity": "low", "message": "m", "source_ip": "999.1.1.1"}
    assert client.post("/events", json=[bad_event], headers=KEY).status_code == 422


def test_login_with_missing_fields_or_wrong_types_is_422(client, auth_on):
    assert client.post("/auth/login", json={}).status_code == 422
    assert client.post("/auth/login", json={"username": 1, "password": ["x"]}).status_code == 422


def test_no_secret_ever_appears_in_responses(client, auth_on, make_login_user, login):
    make_login_user("ad", "admin")
    h = login("ad")
    everything = "".join(client.get(p, headers=h).text for p in ("/auth/me", "/users", "/audit", "/alerts"))
    for secret in ("argon2", "test-secret-key", "test-service-key", "correct-horse-battery"):
        assert secret not in everything


def test_error_responses_do_not_leak_internals(client, auth_on):
    r = client.get("/alerts", headers={"Authorization": "Bearer abc"})
    assert r.status_code == 401 and "Traceback" not in r.text and "jwt" not in r.text.lower()


def test_cors_allows_authorization_header_only_from_dashboard(client):
    ok = client.options("/alerts", headers={
        "Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization",
    })
    assert ok.status_code == 200 and "authorization" in ok.headers["access-control-allow-headers"].lower()
    bad = client.options("/alerts", headers={
        "Origin": "http://evil.example", "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization",
    })
    assert "access-control-allow-origin" not in bad.headers
