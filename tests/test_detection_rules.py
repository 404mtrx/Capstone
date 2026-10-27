from detection.rules import (
    detect_failed_login,
    detect_multiple_failed_logins,
    detect_failed_then_success,
    detect_password_spraying,
)


def make_event(timestamp, event_type, username, source_ip):
    return {
        "timestamp": timestamp,
        "source": "linux",
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "destination_ip": None,
        "action": (
            "success"
            if event_type == "authentication_success"
            else "failure"
        ),
        "severity": "medium",
        "message": f"Test event for {username}",
    }


def test_failed_login_rule():
    event = make_event(
        "2026-10-27T12:00:00Z",
        "failed_login",
        "admin",
        "192.168.1.10",
    )

    alert = detect_failed_login(event)

    assert alert is not None
    assert alert["rule_name"] == "Failed Login Detected"
    assert alert["username"] == "admin"
    assert alert["source_ip"] == "192.168.1.10"
    assert "evidence" in alert


def test_multiple_failed_logins_rule():
    events = [
        make_event(
            "2026-10-27T12:00:00Z",
            "failed_login",
            "admin",
            "192.168.1.20",
        ),
        make_event(
            "2026-10-27T12:01:00Z",
            "failed_login",
            "admin",
            "192.168.1.20",
        ),
        make_event(
            "2026-10-27T12:02:00Z",
            "failed_login",
            "admin",
            "192.168.1.20",
        ),
    ]

    alert = detect_multiple_failed_logins(events)

    assert alert is not None
    assert alert["rule_name"] == "Multiple Failed Logins"
    assert alert["severity"] == "high"
    assert alert["source_ip"] == "192.168.1.20"


def test_failed_then_success_rule():
    events = [
        make_event(
            "2026-10-27T12:00:00Z",
            "failed_login",
            "admin",
            "192.168.1.30",
        ),
        make_event(
            "2026-10-27T12:01:00Z",
            "failed_login",
            "admin",
            "192.168.1.30",
        ),
        make_event(
            "2026-10-27T12:02:00Z",
            "failed_login",
            "admin",
            "192.168.1.30",
        ),
        make_event(
            "2026-10-27T12:03:00Z",
            "authentication_success",
            "admin",
            "192.168.1.30",
        ),
    ]

    alert = detect_failed_then_success(events)

    assert alert is not None
    assert (
        alert["rule_name"]
        == "Successful Login After Multiple Failures"
    )
    assert alert["severity"] == "critical"
    assert alert["username"] == "admin"
    assert alert["source_ip"] == "192.168.1.30"


def test_password_spraying_rule():
    events = [
        make_event(
            "2026-10-27T12:00:00Z",
            "failed_login",
            "admin",
            "192.168.1.40",
        ),
        make_event(
            "2026-10-27T12:01:00Z",
            "failed_login",
            "root",
            "192.168.1.40",
        ),
        make_event(
            "2026-10-27T12:02:00Z",
            "failed_login",
            "student",
            "192.168.1.40",
        ),
    ]

    alert = detect_password_spraying(events)

    assert alert is not None
    assert alert["rule_name"] == "Password Spraying Detected"
    assert alert["severity"] == "high"
    assert alert["source_ip"] == "192.168.1.40"
