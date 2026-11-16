from datetime import datetime, timedelta, timezone

from sqlmodel import Session

from app.models import Alert

KEY = {"X-API-Key": "test-service-key"}


def seed(engine, severity, created, ack=None, closed=None, status="new"):
    with Session(engine) as session:
        session.add(Alert(rule_name="r", severity=severity, status=status, reason="x",
                          created_at=created, acknowledged_at=ack, closed_at=closed))
        session.commit()


def test_summary_counts_and_mean_times(client, auth_on, make_login_user, login, engine):
    make_login_user("ld", "lead")
    t0 = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
    seed(engine, "high", t0, ack=t0 + timedelta(seconds=60), closed=t0 + timedelta(seconds=600), status="closed")
    seed(engine, "high", t0, ack=t0 + timedelta(seconds=120), status="investigating")
    seed(engine, "low", t0)
    body = client.get("/metrics/summary", headers=login("ld")).json()
    assert body["total_alerts"] == 3
    assert body["by_severity"] == {"low": 1, "medium": 0, "high": 2, "critical": 0}
    assert body["by_status"]["closed"] == 1 and body["by_status"]["new"] == 1
    assert body["mean_time_to_acknowledge_seconds"] == 90.0
    assert body["mean_time_to_close_seconds"] == 600.0


def test_summary_date_range(client, auth_on, make_login_user, login, engine):
    make_login_user("ld", "lead")
    seed(engine, "low", datetime(2026, 10, 1, tzinfo=timezone.utc))
    seed(engine, "low", datetime(2026, 11, 5, tzinfo=timezone.utc))
    body = client.get("/metrics/summary?start=2026-11-01T00:00:00Z", headers=login("ld")).json()
    assert body["total_alerts"] == 1
    assert body["mean_time_to_acknowledge_seconds"] is None  # nothing acknowledged: no divide by zero


def test_summary_needs_lead_or_admin(client, auth_on, make_login_user, login):
    make_login_user("an", "analyst"); make_login_user("ad", "admin")
    assert client.get("/metrics/summary").status_code == 401
    assert client.get("/metrics/summary", headers=KEY).status_code == 401
    assert client.get("/metrics/summary", headers=login("an")).status_code == 403
    assert client.get("/metrics/summary", headers=login("ad")).status_code == 200


def test_triage_sets_acknowledged_and_closed_times(client, auth_on, make_login_user, login):
    make_login_user("an", "analyst")
    h = login("an")
    alert = {"rule_name": "r", "message": "m"}
    a = client.post("/alerts", json=alert, headers=KEY).json()["id"]
    assert client.get(f"/alerts/{a}", headers=h).json()["acknowledged_at"] is None
    got = client.patch(f"/alerts/{a}", json={"status": "investigating"}, headers=h).json()
    assert got["acknowledged_at"] is not None and got["closed_at"] is None
    got = client.patch(f"/alerts/{a}", json={"status": "closed"}, headers=h).json()
    assert got["closed_at"] is not None
    got = client.patch(f"/alerts/{a}", json={"status": "investigating"}, headers=h).json()
    assert got["closed_at"] is None and got["acknowledged_at"] is not None  # reopen keeps the first time


def test_opening_a_case_counts_as_acknowledging(client, auth_on, make_login_user, login):
    make_login_user("an", "analyst")
    a = client.post("/alerts", json={"rule_name": "r", "message": "m"}, headers=KEY).json()["id"]
    h = login("an")
    client.post("/cases", json={"alert_id": a, "title": "t"}, headers=h)
    assert client.get(f"/alerts/{a}", headers=h).json()["acknowledged_at"] is not None
