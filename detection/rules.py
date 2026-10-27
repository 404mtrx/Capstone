from collections import defaultdict
from datetime import datetime, timedelta


def build_alert(rule_name, severity, message, event, evidence):
    return {
        "rule_name": rule_name,
        "severity": severity,
        "message": message,
        "source_ip": event.get("source_ip"),
        "timestamp": event.get("timestamp"),
        "username": event.get("username"),
        "evidence": evidence,
    }


def detect_failed_login(event):
    if event.get("event_type") == "failed_login":
        return build_alert(
            "Failed Login Detected",
            "medium",
            f"Failed login detected for user {event.get('username')}",
            event,
            {"event": event},
        )

    return None


def detect_multiple_failed_logins(events, threshold=3, window_minutes=5):
    grouped = defaultdict(list)

    for event in events:
        if event.get("event_type") != "failed_login":
            continue

        source_ip = event.get("source_ip")
        if source_ip:
            grouped[source_ip].append(event)

    for source_ip, failed_events in grouped.items():
        failed_events.sort(key=lambda event: event.get("timestamp", ""))

        for index, start_event in enumerate(failed_events):
            try:
                start_time = datetime.fromisoformat(
                    start_event["timestamp"].replace("Z", "+00:00")
                )
            except (KeyError, ValueError, TypeError):
                continue

            matching_events = []

            for event in failed_events[index:]:
                try:
                    event_time = datetime.fromisoformat(
                        event["timestamp"].replace("Z", "+00:00")
                    )
                except (KeyError, ValueError, TypeError):
                    continue

                if event_time - start_time <= timedelta(minutes=window_minutes):
                    matching_events.append(event)

            if len(matching_events) >= threshold:
                last_event = matching_events[-1]

                return build_alert(
                    "Multiple Failed Logins",
                    "high",
                    (
                        f"{len(matching_events)} failed logins detected from "
                        f"{source_ip} within {window_minutes} minutes"
                    ),
                    last_event,
                    {"events": matching_events},
                )

    return None


def detect_failed_then_success(events, threshold=3, window_minutes=10):
    for success_event in events:
        if success_event.get("event_type") != "authentication_success":
            continue

        source_ip = success_event.get("source_ip")

        try:
            success_time = datetime.fromisoformat(
                success_event["timestamp"].replace("Z", "+00:00")
            )
        except (KeyError, ValueError, TypeError):
            continue

        matching_failures = []

        for event in events:
            if (
                event.get("event_type") != "failed_login"
                or event.get("source_ip") != source_ip
            ):
                continue

            try:
                failure_time = datetime.fromisoformat(
                    event["timestamp"].replace("Z", "+00:00")
                )
            except (KeyError, ValueError, TypeError):
                continue

            difference = success_time - failure_time

            if timedelta(0) <= difference <= timedelta(minutes=window_minutes):
                matching_failures.append(event)

        if len(matching_failures) >= threshold:
            evidence = matching_failures + [success_event]

            return build_alert(
                "Successful Login After Multiple Failures",
                "critical",
                (
                    f"Successful login detected from {source_ip} after "
                    f"{len(matching_failures)} failed login attempts"
                ),
                success_event,
                {"events": evidence},
            )

    return None


def detect_password_spraying(events, threshold=3, window_minutes=5):
    grouped = defaultdict(list)

    for event in events:
        if event.get("event_type") != "failed_login":
            continue

        source_ip = event.get("source_ip")
        if source_ip:
            grouped[source_ip].append(event)

    for source_ip, failed_events in grouped.items():
        failed_events.sort(key=lambda event: event.get("timestamp", ""))

        for index, start_event in enumerate(failed_events):
            try:
                start_time = datetime.fromisoformat(
                    start_event["timestamp"].replace("Z", "+00:00")
                )
            except (KeyError, ValueError, TypeError):
                continue

            matching_events = []

            for event in failed_events[index:]:
                try:
                    event_time = datetime.fromisoformat(
                        event["timestamp"].replace("Z", "+00:00")
                    )
                except (KeyError, ValueError, TypeError):
                    continue

                if event_time - start_time <= timedelta(minutes=window_minutes):
                    matching_events.append(event)

            usernames = {
                event.get("username")
                for event in matching_events
                if event.get("username")
            }

            if len(usernames) >= threshold:
                last_event = matching_events[-1]

                return build_alert(
                    "Password Spraying Detected",
                    "high",
                    (
                        f"Password spraying detected from {source_ip} "
                        f"against {len(usernames)} usernames"
                    ),
                    last_event,
                    {"events": matching_events},
                )

    return None
