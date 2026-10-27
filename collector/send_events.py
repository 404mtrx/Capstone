"""Send normalized events to the SentinelWatch API (POST /events).

Usage:
    python collector/send_events.py normalized_events.json [more.json ...]
    python collector/send_events.py normalized_events.json --url http://127.0.0.1:8000/events
"""
import argparse
import json
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8000/events"


def send_events(events, url=DEFAULT_URL):
    body = json.dumps(events).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST", headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.status, json.loads(response.read() or b"null")


def main():
    parser = argparse.ArgumentParser(description="Send normalized events to SentinelWatch")
    parser.add_argument("files", nargs="+", help="JSON files written by normalize_logs.py")
    parser.add_argument("--url", default=DEFAULT_URL)
    args = parser.parse_args()

    events = []
    for path in args.files:
        with open(path, "r") as file:
            events.extend(json.load(file))

    print(f"Sending {len(events)} events to {args.url}")
    try:
        status, result = send_events(events, args.url)
    except urllib.error.HTTPError as error:
        print(f"Failed: HTTP {error.code} {error.read().decode('utf-8', 'replace')}")
        return 1
    except urllib.error.URLError as error:
        print(f"Failed: cannot reach the API ({error.reason}). Is the backend running?")
        return 1

    print(f"OK: HTTP {status} {result}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
