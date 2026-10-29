def test_dashboard_origin_is_allowed(client):
    r = client.options(
        "/alerts",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"},
    )
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_other_origin_is_not_allowed(client):
    r = client.options(
        "/alerts",
        headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in r.headers
