
import json
import re
from datetime import datetime, timezone
from collect_logs import collect_logs

def normalize_log(log):
    pattern = (
        r"^(\w+)\s+(\d+)\s+(\d+:\d+:\d+)\s+"
        r"(\S+)\s+sshd\[\d+\]: "
        r"(Failed|Accepted) password for (\S+) from "
        r"(\d+\.\d+\.\d+\.\d+)"
    )

    match = re.search(pattern, log)

    if not match:
        return None

    month, day, time, hostname, status, username, ip = match.groups()

    # Our synthetic logs use the year 2026 and UTC.
    timestamp = datetime.strptime(
        f"2026 {month} {day} {time}",
        "%Y %b %d %H:%M:%S"
    ).replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")

    failed = status == "Failed"

    return {
        "timestamp": timestamp,
        "source": "linux",
        "event_type": "authentication_failure" if failed else "authentication_success",
        "username": username,
        "source_ip": ip,
        "destination_ip": None,
        "action": "failure" if failed else "success",
        "severity": "medium" if failed else "low",
        "message": log
    }


if __name__ == "__main__":
    raw_logs = collect_logs()
    normalized_events = []

    for log in raw_logs:
        event = normalize_log(log)

        if event is not None:
            normalized_events.append(event)

    print("SentinelWatch Log Normalizer")
    print(f"Total normalized events: {len(normalized_events)}")
    print(json.dumps(normalized_events, indent=4))
    with open("normalized_events.json", "w") as file:
        json.dump(normalized_events, file, indent=4)

    print("Normalized events saved to normalized_events.json")
