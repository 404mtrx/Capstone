import json
from rules import detect_failed_login


def analyze_event(event):
    alert = detect_failed_login(event)

    if alert:
        return alert

    return None


if __name__ == "__main__":
    with open("normalized_events.json", "r") as file:
        events = json.load(file)

    for event in events:
        result = analyze_event(event)

        if result:
            print("ALERT:", result)
        else:
            print("NO ALERT:", event["event_type"])