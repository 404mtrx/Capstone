import json
import os
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
API_BASE_URL = os.environ.get("SENTINEL_API_URL", "http://localhost:8000")  # set to the public site + /api when deployed


# The backend asks for an API key (X-API-Key). Set it in the environment: export SENTINEL_API_KEY=...
def api_headers(extra=None):
    headers = dict(extra or {})
    key = os.environ.get("SENTINEL_API_KEY")
    if key:
        headers["X-API-Key"] = key
    return headers


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
    request = Request(
        f"{API_BASE_URL}/events",
        headers=api_headers(),
        method="GET",
    )

    with urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))

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
        headers=api_headers(),
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
        headers=api_headers({"Content-Type": "application/json"}),
        method="POST",
    )

    with urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


# Submit alerts while preventing duplicates from being stored.
def submit_alerts(alerts, quiet=False):
    posted = 0
    try:
        existing_alerts = get_existing_alerts()
    except (HTTPError, URLError, TimeoutError) as error:
        print(f"Could not read existing alerts: {error}")
        return posted

    existing_keys = {
        alert_key(alert)
        for alert in existing_alerts
    }

    for alert in alerts:
        key = alert_key(alert)

        if key in existing_keys:
            if not quiet:
                print(
                    "DUPLICATE SKIPPED:",
                    alert["rule_name"],
                    alert.get("source_ip"),
                )
            continue

        try:
            saved_alert = post_alert(alert)
            existing_keys.add(key)
            posted += 1
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

    return posted


# One detection pass: read events, run the rules, post any new alerts.
# quiet=True (watch mode) prints only when something new is posted.
def run_once(quiet=False):
    events = load_events()
    alerts = analyze_events(events)

    if alerts:
        if not quiet:
            for alert in alerts:
                print("ALERT:", alert)

        posted = submit_alerts(alerts, quiet=quiet)
        if quiet and posted:
            print(f"{posted} new alert(s) posted.")
    elif not quiet:
        print("NO ALERTS DETECTED")


# Run the detection engine when this file is executed directly.
#   python3 detection/engine.py              one pass, then stop
#   python3 detection/engine.py --watch 5    repeat every 5 seconds (live demo); Ctrl+C stops
if __name__ == "__main__":
    import argparse
    import time

    parser = argparse.ArgumentParser(description="SentinelWatch detection engine")
    parser.add_argument(
        "--watch",
        type=float,
        metavar="SECONDS",
        help="keep running and check for new events every SECONDS seconds",
    )
    args = parser.parse_args()

    if not args.watch:
        run_once()
    else:
        print(f"Watching for new events every {args.watch:g} seconds. Ctrl+C to stop.")
        print("Only NEW alerts are printed; no output means nothing new.")
        try:
            while True:
                try:
                    run_once(quiet=True)
                except (HTTPError, URLError, TimeoutError) as error:
                    print(f"API not reachable, will retry: {error}")
                time.sleep(args.watch)
        except KeyboardInterrupt:
            print("Stopped.")
