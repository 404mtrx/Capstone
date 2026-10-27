import json
from pathlib import Path

try:
    from .rules import (
        detect_failed_login,
        detect_multiple_failed_logins,
        detect_failed_then_success,
        detect_password_spraying,
    )
except ImportError:
    from rules import (
        detect_failed_login,
        detect_multiple_failed_logins,
        detect_failed_then_success,
        detect_password_spraying,
    )


BASE_DIR = Path(__file__).resolve().parent.parent
EVENT_FILE = BASE_DIR / "normalized_events.json"


def analyze_event(event):
    return detect_failed_login(event)


def analyze_events(events):
    alerts = []

    # Existing single-event detection
    for event in events:
        alert = detect_failed_login(event)
        if alert:
            alerts.append(alert)

    # Multi-event / correlation detections
    detectors = [
        detect_multiple_failed_logins,
        detect_failed_then_success,
        detect_password_spraying,
    ]

    for detector in detectors:
        alert = detector(events)
        if alert:
            alerts.append(alert)

    return alerts


def load_events():
    with EVENT_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


if __name__ == "__main__":
    events = load_events()
    alerts = analyze_events(events)

    if alerts:
        for alert in alerts:
            print("ALERT:", alert)
    else:
        print("NO ALERTS DETECTED")
