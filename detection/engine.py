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
        f"{API_BASE_URL}/events?size=500",
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
# cooldown (watch mode): after an alert is posted, the same rule + source IP stays quiet for
# `cooldown` seconds of event time, so one attacker gives one alert instead of one per attempt.
# last_posted remembers the event time of the last alert per (rule, source IP).
def alert_time(alert):
    value = normalize_timestamp(alert.get("timestamp") or alert.get("created_at"))
    try:
        return datetime.fromisoformat(value) if value else None
    except (ValueError, TypeError):
        return None


def in_cooldown(alert, last_posted, cooldown):
    when = alert_time(alert)
    last = last_posted.get((alert.get("rule_name"), alert.get("source_ip")))
    if not cooldown or when is None or last is None:
        return False
    try:
        return abs((when - last).total_seconds()) < cooldown
    except TypeError:  # one timestamp has a timezone and the other does not
        return False


def submit_alerts(alerts, quiet=False, seen=None, last_posted=None, cooldown=0):
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

    # In watch mode, also remember every alert handled so far. The API only returns the
    # newest 200 alerts, so without this a busy server would re-post older ones.
    if seen is not None:
        existing_keys |= seen

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

        if last_posted is not None and in_cooldown(alert, last_posted, cooldown):
            existing_keys.add(key)
            continue

        try:
            saved_alert = post_alert(alert)
            existing_keys.add(key)
            when = alert_time(alert)
            if last_posted is not None and when is not None:
                last_posted[(alert.get("rule_name"), alert.get("source_ip"))] = when
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

    if seen is not None:
        seen |= existing_keys

    return posted


# One detection pass: read events, run the rules, post any new alerts.
# quiet=True (watch mode) prints only when something new is posted.
def run_once(quiet=False, seen=None, last_posted=None, cooldown=0):
    events = load_events()
    alerts = analyze_events(events)

    if alerts:
        if not quiet:
            for alert in alerts:
                print("ALERT:", alert)

        posted = submit_alerts(alerts, quiet=quiet, seen=seen, last_posted=last_posted, cooldown=cooldown)
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
    parser.add_argument(
        "--cooldown",
        type=float,
        default=600,
        metavar="SECONDS",
        help="watch mode: one alert per rule and source IP per SECONDS (default 600; 0 = alert on everything)",
    )
    args = parser.parse_args()

    if not args.watch:
        run_once()
    else:
        print(f"Watching for new events every {args.watch:g} seconds. Ctrl+C to stop.")
        print("Only NEW alerts are printed; no output means nothing new.")
        seen = set()
        last_posted = {}
        try:
            while True:
                try:
                    run_once(quiet=True, seen=seen, last_posted=last_posted, cooldown=args.cooldown)
                except (HTTPError, URLError, TimeoutError) as error:
                    print(f"API not reachable, will retry: {error}")
                time.sleep(args.watch)
        except KeyboardInterrupt:
            print("Stopped.")
