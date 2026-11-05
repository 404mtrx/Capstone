"""Send normalized events to the SentinelWatch API (POST /events).

Usage:
    python collector/send_events.py normalized_events.json [more.json ...]
    python collector/send_events.py normalized_events.json --url http://127.0.0.1:8000/events

Large files are sent in batches (500 events by default). Sending the same
events again is safe: the API stores each event once.
"""
import argparse
import json
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8000/events"
DEFAULT_BATCH_SIZE = 500


def post_batch(events, url=DEFAULT_URL):
    """POST one list of events. Returns (HTTP status, parsed JSON body)."""
    body = json.dumps(events).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST", headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.status, json.loads(response.read() or b"null")


def send_events(events, url=DEFAULT_URL, batch_size=DEFAULT_BATCH_SIZE, post=post_batch):
    """Send events in batches. Returns (last HTTP status, {"indexed": total}).

    Raises urllib.error.HTTPError / URLError on the first failed batch.
    """
    status, indexed = 201, 0
    for start in range(0, len(events), batch_size):
        status, result = post(events[start:start + batch_size], url)
        indexed += (result or {}).get("indexed", 0)
    return status, {"indexed": indexed}


def main():
    parser = argparse.ArgumentParser(description="Send normalized events to SentinelWatch")
    parser.add_argument("files", nargs="+", help="JSON files written by normalize_logs.py")
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    args = parser.parse_args()

    events = []
    for path in args.files:
        with open(path, "r") as file:
            events.extend(json.load(file))

    print(f"Sending {len(events)} events to {args.url}")
    try:
        status, result = send_events(events, args.url, args.batch_size)
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
