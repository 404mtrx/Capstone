EVENTS = [
    {
        "timestamp": "2026-10-08T14:30:00Z",
        "source": "linux",
        "event_type": "failed_login",
        "username": "admin",
        "source_ip": "192.168.1.25",
        "destination_ip": None,
        "action": "failure",
        "severity": "medium",
        "message": "Failed password for admin from 192.168.1.25",
    },
    {
        "timestamp": "2026-10-08T14:32:00Z",
        "source": "linux",
        "event_type": "authentication_success",
        "username": "student",
        "source_ip": "192.168.1.40",
        "destination_ip": None,
        "action": "success",
        "severity": "low",
        "message": "Accepted password for student from 192.168.1.40",
    },
]


def test_ingest_collector_output(client, store):
    r = client.post("/events", json=EVENTS)
    assert r.status_code == 201
    assert r.json() == {"indexed": 2}
    assert len(store.docs) == 2


def test_resending_same_events_does_not_duplicate(client, store):
    client.post("/events", json=EVENTS)
    client.post("/events", json=EVENTS)
    assert len(store.docs) == 2


def test_bad_event_is_rejected(client):
    assert client.post("/events", json=[{**EVENTS[0], "source_ip": "not-an-ip"}]).status_code == 422
    assert client.post("/events", json=[{**EVENTS[0], "severity": "meh"}]).status_code == 422


def test_search_filters(client):
    client.post("/events", json=EVENTS)
    r = client.get("/events", params={"event_type": "failed_login"})
    assert r.status_code == 200
    assert [e["username"] for e in r.json()] == ["admin"]
    assert len(client.get("/events").json()) == 2
