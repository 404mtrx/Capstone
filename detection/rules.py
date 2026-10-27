from collections import defaultdict
from datetime import datetime, timedelta


# Helper Function: Build Standard Alert
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


# Rule 1: Failed Login Detection
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


# Rule 2: Multiple Failed Logins
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


# Rule 3: Failed Login Followed by Successful Login
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


# Rule 4: Password Spraying Detection
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


# Rule 5: Port Scan Detection
def detect_port_scan(events, threshold=5, window_minutes=5):
    grouped = defaultdict(list)

    for event in events:
        source_ip = event.get("source_ip")
        destination_ip = event.get("destination_ip")
        destination_port = event.get("destination_port")

        if not source_ip or not destination_ip or destination_port is None:
            continue

        grouped[(source_ip, destination_ip)].append(event)

    for (source_ip, destination_ip), source_events in grouped.items():
        source_events.sort(key=lambda event: event.get("timestamp", ""))

        for index, start_event in enumerate(source_events):
            try:
                start_time = datetime.fromisoformat(
                    start_event["timestamp"].replace("Z", "+00:00")
                )
            except (KeyError, ValueError, TypeError):
                continue

            matching_events = []

            for event in source_events[index:]:
                try:
                    event_time = datetime.fromisoformat(
                        event["timestamp"].replace("Z", "+00:00")
                    )
                except (KeyError, ValueError, TypeError):
                    continue

                if event_time - start_time <= timedelta(minutes=window_minutes):
                    matching_events.append(event)

            ports = {
                event.get("destination_port")
                for event in matching_events
                if event.get("destination_port") is not None
            }

            if len(ports) >= threshold:
                last_event = matching_events[-1]

                return build_alert(
                    "Port Scan Detected",
                    "high",
                    (
                        f"Possible port scan from {source_ip} "
                        f"against {destination_ip} across {len(ports)} ports"
                    ),
                    last_event,
                    {"events": matching_events},
                )

    return None


# Rule 6: Repeated Blocked Connections
def detect_repeated_blocked_connections(events, threshold=5, window_minutes=5):
    grouped = defaultdict(list)

    for event in events:
        if event.get("action") != "blocked":
            continue

        source_ip = event.get("source_ip")

        if source_ip:
            grouped[source_ip].append(event)

    for source_ip, blocked_events in grouped.items():
        blocked_events.sort(key=lambda event: event.get("timestamp", ""))

        for index, start_event in enumerate(blocked_events):
            try:
                start_time = datetime.fromisoformat(
                    start_event["timestamp"].replace("Z", "+00:00")
                )
            except (KeyError, ValueError, TypeError):
                continue

            matching_events = []

            for event in blocked_events[index:]:
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
                    "Repeated Blocked Connections",
                    "high",
                    (
                        f"{len(matching_events)} blocked connections detected "
                        f"from {source_ip} within {window_minutes} minutes"
                    ),
                    last_event,
                    {"events": matching_events},
                )

    return None



# Rule 7: High-Severity Event Detection
def detect_high_severity_event(event):
    if event.get("severity") in {"high", "critical"}:
        return build_alert(
            "High Severity Event",
            event.get("severity"),
            f"High severity security event detected: {event.get('message')}",
            event,
            {"event": event},
        )

    return None


# Rule 8: Account Lockout Detection
def detect_account_lockout(event):
    if event.get("event_type") == "account_lockout":
        return build_alert(
            "Account Lockout Detected",
            "high",
            f"Account lockout detected for user {event.get('username')}",
            event,
            {"event": event},
        )

    return None


# Rule 9: Privilege Change Detection
def detect_privilege_change(event):
    if event.get("event_type") == "privilege_change":
        return build_alert(
            "Privilege Change Detected",
            "high",
            f"Privilege change detected for user {event.get('username')}",
            event,
            {"event": event},
        )

    return None


# Rule 10: Suspicious Remote Login Detection
def detect_suspicious_remote_login(event):
    if (
        event.get("event_type") == "remote_login"
        and event.get("action") == "success"
        and event.get("severity") in {"high", "critical"}
    ):
        return build_alert(
            "Suspicious Remote Login Detected",
            event.get("severity"),
            f"Suspicious remote login detected for user {event.get('username')}",
            event,
            {"event": event},
        )

    return None
