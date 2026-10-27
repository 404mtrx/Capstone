from detection.rules import (
    detect_failed_login,
    detect_multiple_failed_logins,
    detect_failed_then_success,
    detect_password_spraying,
    detect_port_scan,
    detect_repeated_blocked_connections,
    detect_high_severity_event,
    detect_account_lockout,
    detect_privilege_change,
    detect_suspicious_remote_login,

)

# Helper Function: Create Test Event
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

# Rule 1: Failed Login Detection
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


# Rule 2: Multiple Failed Logins
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


# Rule 3: Failed Login Followed by Successful Login
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


# Rule 4: Password Spraying Detection
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


# Rule 5: Port Scan Detection
def test_port_scan_rule():
    events = [
        {
            "timestamp": "2026-10-27T12:00:00Z",
            "source": "firewall",
            "event_type": "connection_attempt",
            "username": None,
            "source_ip": "192.168.1.50",
            "destination_ip": "10.0.0.10",
            "destination_port": 22,
            "action": "blocked",
            "severity": "medium",
            "message": "Connection attempt to port 22",
        },
        {
            "timestamp": "2026-10-27T12:00:30Z",
            "source": "firewall",
            "event_type": "connection_attempt",
            "username": None,
            "source_ip": "192.168.1.50",
            "destination_ip": "10.0.0.10",
            "destination_port": 23,
            "action": "blocked",
            "severity": "medium",
            "message": "Connection attempt to port 23",
        },
        {
            "timestamp": "2026-10-27T12:01:00Z",
            "source": "firewall",
            "event_type": "connection_attempt",
            "username": None,
            "source_ip": "192.168.1.50",
            "destination_ip": "10.0.0.10",
            "destination_port": 80,
            "action": "blocked",
            "severity": "medium",
            "message": "Connection attempt to port 80",
        },
        {
            "timestamp": "2026-10-27T12:01:30Z",
            "source": "firewall",
            "event_type": "connection_attempt",
            "username": None,
            "source_ip": "192.168.1.50",
            "destination_ip": "10.0.0.10",
            "destination_port": 443,
            "action": "blocked",
            "severity": "medium",
            "message": "Connection attempt to port 443",
        },
        {
            "timestamp": "2026-10-27T12:02:00Z",
            "source": "firewall",
            "event_type": "connection_attempt",
            "username": None,
            "source_ip": "192.168.1.50",
            "destination_ip": "10.0.0.10",
            "destination_port": 3389,
            "action": "blocked",
            "severity": "medium",
            "message": "Connection attempt to port 3389",
        },
    ]

    alert = detect_port_scan(events)

    assert alert is not None
    assert alert["rule_name"] == "Port Scan Detected"
    assert alert["severity"] == "high"
    assert alert["source_ip"] == "192.168.1.50"


# Rule 6: Repeated Blocked Connections
def test_repeated_blocked_connections_rule():
    events = [
        {
            "timestamp": "2026-10-27T13:00:00Z",
            "source": "firewall",
            "event_type": "connection_attempt",
            "username": None,
            "source_ip": "192.168.1.60",
            "destination_ip": "10.0.0.20",
            "destination_port": 22,
            "action": "blocked",
            "severity": "medium",
            "message": "Blocked connection",
        },
        {
            "timestamp": "2026-10-27T13:00:30Z",
            "source": "firewall",
            "event_type": "connection_attempt",
            "username": None,
            "source_ip": "192.168.1.60",
            "destination_ip": "10.0.0.20",
            "destination_port": 23,
            "action": "blocked",
            "severity": "medium",
            "message": "Blocked connection",
        },
        {
            "timestamp": "2026-10-27T13:01:00Z",
            "source": "firewall",
            "event_type": "connection_attempt",
            "username": None,
            "source_ip": "192.168.1.60",
            "destination_ip": "10.0.0.20",
            "destination_port": 80,
            "action": "blocked",
            "severity": "medium",
            "message": "Blocked connection",
        },
        {
            "timestamp": "2026-10-27T13:01:30Z",
            "source": "firewall",
            "event_type": "connection_attempt",
            "username": None,
            "source_ip": "192.168.1.60",
            "destination_ip": "10.0.0.20",
            "destination_port": 443,
            "action": "blocked",
            "severity": "medium",
            "message": "Blocked connection",
        },
        {
            "timestamp": "2026-10-27T13:02:00Z",
            "source": "firewall",
            "event_type": "connection_attempt",
            "username": None,
            "source_ip": "192.168.1.60",
            "destination_ip": "10.0.0.20",
            "destination_port": 3389,
            "action": "blocked",
            "severity": "medium",
            "message": "Blocked connection",
        },
    ]

    alert = detect_repeated_blocked_connections(events)

    assert alert is not None
    assert alert["rule_name"] == "Repeated Blocked Connections"
    assert alert["severity"] == "high"
    assert alert["source_ip"] == "192.168.1.60"


# Rule 7: High-Severity Event Detection
def test_high_severity_event_rule():
    event = {
        "timestamp": "2026-10-27T14:00:00Z",
        "source": "linux",
        "event_type": "privilege_change",
        "username": "admin",
        "source_ip": "192.168.1.70",
        "destination_ip": None,
        "action": "success",
        "severity": "critical",
        "message": "User added to administrator group",
    }

    alert = detect_high_severity_event(event)

    assert alert is not None
    assert alert["rule_name"] == "High Severity Event"
    assert alert["severity"] == "critical"
    assert alert["username"] == "admin"
    assert alert["source_ip"] == "192.168.1.70"


# Rule 8: Account Lockout Detection
def test_account_lockout_rule():
    event = {
        "timestamp": "2026-10-27T15:00:00Z",
        "source": "linux",
        "event_type": "account_lockout",
        "username": "admin",
        "source_ip": "192.168.1.80",
        "destination_ip": None,
        "action": "blocked",
        "severity": "high",
        "message": "Account locked after repeated failed logins",
    }

    alert = detect_account_lockout(event)

    assert alert is not None
    assert alert["rule_name"] == "Account Lockout Detected"
    assert alert["severity"] == "high"
    assert alert["username"] == "admin"
    assert alert["source_ip"] == "192.168.1.80"


# Rule 9: Privilege Change Detection
def test_privilege_change_rule():
    event = {
        "timestamp": "2026-10-27T15:30:00Z",
        "source": "linux",
        "event_type": "privilege_change",
        "username": "student",
        "source_ip": "192.168.1.90",
        "destination_ip": None,
        "action": "success",
        "severity": "high",
        "message": "User added to sudo group",
    }

    alert = detect_privilege_change(event)

    assert alert is not None
    assert alert["rule_name"] == "Privilege Change Detected"
    assert alert["severity"] == "high"
    assert alert["username"] == "student"
    assert alert["source_ip"] == "192.168.1.90"


# Rule 10: Suspicious Remote Login Detection
def test_suspicious_remote_login_rule():
    event = {
        "timestamp": "2026-10-27T16:00:00Z",
        "source": "linux",
        "event_type": "remote_login",
        "username": "admin",
        "source_ip": "203.0.113.25",
        "destination_ip": "10.0.0.50",
        "action": "success",
        "severity": "high",
        "message": "Successful remote login from unusual source",
    }

    alert = detect_suspicious_remote_login(event)

    assert alert is not None
    assert alert["rule_name"] == "Suspicious Remote Login Detected"
    assert alert["severity"] == "high"
    assert alert["username"] == "admin"
    assert alert["source_ip"] == "203.0.113.25"
