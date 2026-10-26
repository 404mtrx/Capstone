# This is exactly what detection/rules.py produces today.
SATYA_ALERT = {
    "rule_name": "Failed Login Detected",
    "severity": "medium",
    "message": "Failed login detected for user admin",
    "source_ip": "192.168.1.25",
    "timestamp": "2026-10-08T14:30:00Z",
}


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_create_alert_from_detection_engine_output(client):
    r = client.post("/alerts", json=SATYA_ALERT)
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "new"
    assert body["reason"] == "Failed login detected for user admin"
    assert body["created_at"].startswith("2026-10-08T14:30:00")


def test_create_alert_rejects_bad_severity(client):
    r = client.post("/alerts", json={**SATYA_ALERT, "severity": "apocalyptic"})
    assert r.status_code == 422


def test_list_and_filter_alerts(client):
    client.post("/alerts", json=SATYA_ALERT)
    client.post("/alerts", json={**SATYA_ALERT, "severity": "high", "source_ip": "10.0.0.9"})
    assert len(client.get("/alerts").json()) == 2
    high = client.get("/alerts", params={"severity": "high"}).json()
    assert len(high) == 1 and high[0]["source_ip"] == "10.0.0.9"
    assert client.get("/alerts", params={"severity": "bogus"}).status_code == 422


def test_get_missing_alert_is_404(client):
    assert client.get("/alerts/999").status_code == 404


def test_status_lifecycle(client):
    alert_id = client.post("/alerts", json=SATYA_ALERT).json()["id"]
    ok = client.patch(f"/alerts/{alert_id}", json={"status": "investigating"})
    assert ok.status_code == 200 and ok.json()["status"] == "investigating"
    # new -> escalated is not allowed
    other = client.post("/alerts", json=SATYA_ALERT).json()["id"]
    bad = client.patch(f"/alerts/{other}", json={"status": "escalated"})
    assert bad.status_code == 409


def test_assign_alert(client, make_user):
    alert_id = client.post("/alerts", json=SATYA_ALERT).json()["id"]
    user_id = make_user()
    r = client.patch(f"/alerts/{alert_id}", json={"assigned_to": user_id})
    assert r.json()["assigned_to"] == user_id
    assert client.patch(f"/alerts/{alert_id}", json={"assigned_to": 999}).status_code == 400
    r = client.patch(f"/alerts/{alert_id}", json={"assigned_to": None})
    assert r.json()["assigned_to"] is None
