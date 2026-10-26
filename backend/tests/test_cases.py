ALERT = {"rule_name": "Failed Login Detected", "severity": "medium", "message": "m"}


def _alert(client):
    return client.post("/alerts", json=ALERT).json()["id"]


def test_create_case_moves_alert_to_investigating(client):
    alert_id = _alert(client)
    r = client.post("/cases", json={"alert_id": alert_id, "title": "Brute force on admin"})
    assert r.status_code == 201
    assert r.json()["status"] == "open"
    assert client.get(f"/alerts/{alert_id}").json()["status"] == "investigating"


def test_case_for_missing_alert_is_404(client):
    assert client.post("/cases", json={"alert_id": 42, "title": "x"}).status_code == 404


def test_only_one_open_case_per_alert(client):
    alert_id = _alert(client)
    first = client.post("/cases", json={"alert_id": alert_id, "title": "a"}).json()["id"]
    assert client.post("/cases", json={"alert_id": alert_id, "title": "b"}).status_code == 409
    client.patch(f"/cases/{first}", json={"status": "closed"})
    assert client.post("/cases", json={"alert_id": alert_id, "title": "b"}).status_code == 201


def test_close_and_reopen_sets_closed_at(client):
    alert_id = _alert(client)
    case_id = client.post("/cases", json={"alert_id": alert_id, "title": "t"}).json()["id"]
    closed = client.patch(f"/cases/{case_id}", json={"status": "closed", "notes": "false positive"})
    assert closed.json()["closed_at"] is not None
    assert closed.json()["notes"] == "false positive"
    reopened = client.patch(f"/cases/{case_id}", json={"status": "investigating"})
    assert reopened.json()["closed_at"] is None


def test_owner_must_exist(client, make_user):
    alert_id = _alert(client)
    assert client.post(
        "/cases", json={"alert_id": alert_id, "title": "t", "owner_id": 77}
    ).status_code == 400
    owner = make_user()
    r = client.post("/cases", json={"alert_id": alert_id, "title": "t", "owner_id": owner})
    assert r.json()["owner_id"] == owner


def test_list_cases_filters(client):
    a1, a2 = _alert(client), _alert(client)
    c1 = client.post("/cases", json={"alert_id": a1, "title": "one"}).json()["id"]
    client.post("/cases", json={"alert_id": a2, "title": "two"})
    client.patch(f"/cases/{c1}", json={"status": "closed"})
    assert len(client.get("/cases").json()) == 2
    assert len(client.get("/cases", params={"status": "closed"}).json()) == 1
