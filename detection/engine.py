from rules import detect_failed_login


def analyze_event(event):
    alert = detect_failed_login(event)

    if alert:
        return alert

    return None


if __name__ == "__main__":
    test_event = {
        "timestamp": "2026-10-02T20:10:01Z",
        "source": "test_auth",
        "event_type": "failed_login",
        "username": "admin",
        "source_ip": "192.168.1.25",
        "destination_ip": None,
        "action": "failure",
        "severity": "medium",
        "message": "FAILED_LOGIN user=admin src_ip=192.168.1.25"
    }

    result = analyze_event(test_event)
    print(result)
