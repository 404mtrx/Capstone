"""Read CSE-CIC-IDS2018 flow CSV files into SentinelWatch events.

The Canadian Institute for Cybersecurity's CSE-CIC-IDS2018 dataset publishes,
for each attack day, a CSV of network flows (one row per connection) made with
CICFlowMeter, each row labeled "Benign" or with the attack name. This module
turns those rows into events in the common event schema so they can be stored,
searched and used to evaluate detection against known attacks.

Usage (from the repository root):
    python3 collector/cic_flows.py Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv -o cic_events.json
    python3 collector/cic_flows.py day.csv --labels SSH-Bruteforce,Benign --every 10 --limit 5000 -o sample.json
    python3 collector/cic_flows.py day.csv --summary-only

Notes:
  * These CSVs have no source or destination IP columns, so events carry
    destination_port and protocol but no IPs.
  * The label is kept in the event as "label" and in the message. The backend
    API stores the message; "label" is used for offline evaluation.
  * CSV timestamps have no time zone; they are treated as UTC.

Dataset: CSE-CIC-IDS2018, Communications Security Establishment (CSE) and
Canadian Institute for Cybersecurity (CIC), https://www.unb.ca/cic/datasets/ids-2018.html
(data on AWS: s3://cse-cic-ids2018/). Cite it when you use or redistribute it.
"""
import argparse
import csv
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROTOCOLS = {"6": "tcp", "17": "udp", "1": "icmp", "0": "other"}
TIME_FORMATS = ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M")


def parse_time(text):
    for fmt in TIME_FORMATS:
        try:
            stamp = datetime.strptime(text.strip(), fmt).replace(tzinfo=timezone.utc)
            return stamp.isoformat().replace("+00:00", "Z")
        except ValueError:
            continue
    return None


def _int(value):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def flow_to_event(row, flow_id=None):
    """Convert one CSV row (a dict keyed by column name) to an event, or None."""
    timestamp = parse_time(row.get("Timestamp", ""))
    port = _int(row.get("Dst Port"))
    label = (row.get("Label") or "").strip()
    if timestamp is None or port is None or not label:
        return None

    protocol = PROTOCOLS.get(str(_int(row.get("Protocol"))), str(row.get("Protocol")))
    duration = _int(row.get("Flow Duration"))
    fwd = _int(row.get("Tot Fwd Pkts"))
    bwd = _int(row.get("Tot Bwd Pkts"))
    attack = label.lower() != "benign"

    event = {
        "timestamp": timestamp,
        "source": "network",
        "event_type": "network_flow",
        "username": None,
        "source_ip": None,
        "destination_ip": None,
        "action": "observed",
        "severity": "medium" if attack else "low",
        "message": (f"CIC-IDS2018 flow dst_port={port} proto={protocol} "
                    f"duration_us={duration} fwd_pkts={fwd} bwd_pkts={bwd} label={label}"),
        "destination_port": port,
        "protocol": protocol,
        "label": label,
    }
    if flow_id is not None:
        event["event_id"] = flow_id
    return event


def read_flows(path, labels=None, every=1, limit=None):
    """Yield events from a CICFlowMeter CSV, streaming (the files are hundreds of MB).

    labels: set of labels to keep (None keeps all). every: keep every Nth matching
    row. limit: stop after this many events. Repeated header rows and malformed
    rows are skipped.
    """
    path = Path(path)
    kept = matched = 0
    with open(path, newline="", encoding="utf-8", errors="replace") as file:
        reader = csv.DictReader(file)
        for number, row in enumerate(reader, start=2):
            if row.get("Label") == "Label":  # header repeated inside the file
                continue
            event = flow_to_event(row, flow_id=f"cic2018-{path.stem}-{number}")
            if event is None:
                continue
            if labels and event["label"] not in labels:
                continue
            matched += 1
            if (matched - 1) % every:
                continue
            yield event
            kept += 1
            if limit and kept >= limit:
                return


def summarize(events):
    by_label = Counter(e["label"] for e in events)
    ports = {}
    for e in events:
        ports.setdefault(e["label"], Counter())[e["destination_port"]] += 1
    return by_label, ports


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read CSE-CIC-IDS2018 flow CSVs into SentinelWatch events")
    parser.add_argument("files", nargs="+", help="CICFlowMeter CSV files")
    parser.add_argument("-o", "--out", default="cic_events.json")
    parser.add_argument("--labels", help="comma-separated labels to keep, e.g. SSH-Bruteforce,Benign")
    parser.add_argument("--every", type=int, default=1, help="keep every Nth matching flow (sampling)")
    parser.add_argument("--limit", type=int, help="maximum number of events per file")
    parser.add_argument("--summary-only", action="store_true", help="count labels, write no file")
    args = parser.parse_args(argv)

    labels = set(args.labels.split(",")) if args.labels else None
    events = []
    for path in args.files:
        events.extend(read_flows(path, labels, max(args.every, 1), args.limit))

    by_label, ports = summarize(events)
    print("SentinelWatch CIC-IDS2018 Flow Reader")
    print(f"Events: {len(events)}")
    for label, count in by_label.most_common():
        top = ", ".join(f"{p} ({n})" for p, n in ports[label].most_common(3))
        print(f"  {label}: {count}   top destination ports: {top}")

    if not args.summary_only:
        with open(args.out, "w") as file:
            json.dump(events, file, indent=1)
        print(f"Saved to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
