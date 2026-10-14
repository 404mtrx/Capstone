def detect_failed_login(event):
    if event.get("event_type") == "failed_login":
        return {
            "rule_name": "Failed Login Detected",
            "severity": "medium",
            "message": f"Failed login detected for user {event.get('username')}",
            "source_ip": event.get("source_ip"),
            "timestamp": event.get("timestamp")
        }

    return None
