import json
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from .rules import (
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

except ImportError:
    from rules import (
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


BASE_DIR = Path(__file__).resolve().parent.parent
EVENT_FILE = BASE_DIR / "normalized_events.json"
API_BASE_URL = "http://localhost:8000"


def analyze_event(event):
    single_event_detectors = [
        detect_failed_login,
        detect_high_severity_event,
        detect_account_lockout,
        detect_privilege_change,
        detect_suspicious_remote_login,
    ]

    for detector in single_event_detectors:
        alert = detector(event)

        if alert:
            return alert

    return None


def analyze_events(events):
    alerts = []

    # Single-event detection rules
    single_event_detectors = [
        detect_failed_login,
        detect_high_severity_event,
        detect_account_lockout,
        detect_privilege_change,
        detect_suspicious_remote_login,
    ]

    for event in events:
        for detector in single_event_detectors:
            alert = detector(event)

            if alert:
                alerts.append(alert)

    # Multi-event and correlation detection rules
    multi_event_detectors = [
        detect_multiple_failed_logins,
        detect_failed_then_success,
        detect_password_spraying,
        detect_port_scan,
        detect_repeated_blocked_connections,
    ]

    for detector in multi_event_detectors:
        alert = detector(events)

        if alert:
            alerts.append(alert)

    return alerts


# Load normalized events from the local JSON file.
def load_events():
    with EVENT_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


# Convert timestamps into a consistent ISO-8601 format.
def normalize_timestamp(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        ).isoformat()
    except (ValueError, AttributeError):
        return value


# Build a unique key used to identify duplicate alerts.
def alert_key(alert):
    timestamp = alert.get("timestamp") or alert.get("created_at")

    return (
        alert.get("rule_name"),
        alert.get("source_ip"),
        alert.get("username"),
        normalize_timestamp(timestamp),
    )


# Retrieve existing alerts from the SentinelWatch backend API.
def get_existing_alerts():
    request = Request(
        f"{API_BASE_URL}/alerts?limit=200",
        method="GET",
    )

    with urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


# Send a newly generated alert to the backend API.
def post_alert(alert):
    data = json.dumps(alert).encode("utf-8")

    request = Request(
        f"{API_BASE_URL}/alerts",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


# Submit alerts while preventing duplicates from being stored.
def submit_alerts(alerts):
    try:
        existing_alerts = get_existing_alerts()
    except (HTTPError, URLError, TimeoutError) as error:
        print(f"Could not read existing alerts: {error}")
        return

    existing_keys = {
        alert_key(alert)
        for alert in existing_alerts
    }

    for alert in alerts:
        key = alert_key(alert)

        if key in existing_keys:
            print(
                "DUPLICATE SKIPPED:",
                alert["rule_name"],
                alert.get("source_ip"),
            )
            continue

        try:
            saved_alert = post_alert(alert)
            existing_keys.add(key)
            print(
                "ALERT POSTED:",
                saved_alert.get("id"),
                saved_alert.get("rule_name"),
            )
        except (HTTPError, URLError, TimeoutError) as error:
            print(
                f"Could not post alert "
                f"{alert['rule_name']}: {error}"
            )


# Run the detection engine when this file is executed directly.
if __name__ == "__main__":
    events = load_events()
    alerts = analyze_events(events)

    if alerts:
        for alert in alerts:
            print("ALERT:", alert)

        submit_alerts(alerts)
    else:
        print("NO ALERTS DETECTED")
