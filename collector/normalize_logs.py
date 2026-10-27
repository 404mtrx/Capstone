import argparse
import json
import re
from datetime import datetime, timedelta, timezone

from collect_logs import collect_logs

# Event type names shared with the detection engine. Agree on any change with Satya.
FAILED_LOGIN = "failed_login"
LOGIN_SUCCESS = "authentication_success"
FIREWALL_BLOCK = "firewall_block"
FIREWALL_ALLOW = "firewall_allow"

# Syslog prefix: "Oct  8 14:30:00 ubuntu ..."
SYSLOG_PREFIX = r"^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+"

# sshd login result, including "for invalid user" and public-key logins.
SSH_PATTERN = re.compile(
    SYSLOG_PREFIX
    + r"sshd\[\d+\]: (Failed|Accepted) (password|publickey) for "
    r"(?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3})"
)

# UFW firewall line written by the kernel.
UFW_PATTERN = re.compile(
    SYSLOG_PREFIX
    + r"kernel:.*\[UFW (BLOCK|ALLOW)\].*?SRC=(\S+) DST=(\S+).*?PROTO=(\w+)"
    r"(?:.*?DPT=(\d+))?"
)


def syslog_timestamp(month, day, time, now=None):
    """Convert a syslog date (which has no year) to ISO-8601 UTC.

    Uses the current year. If that would put the event more than a day in
    the future (for example a December log read in January), uses the
    previous year. Our logs are written in UTC.
    """
    now = now or datetime.now(timezone.utc)
    stamp = datetime.strptime(
        f"{now.year} {month} {day} {time}", "%Y %b %d %H:%M:%S"
    ).replace(tzinfo=timezone.utc)

    if stamp > now + timedelta(days=1):
        stamp = stamp.replace(year=now.year - 1)

    return stamp.isoformat().replace("+00:00", "Z")


def normalize_ssh(log, now=None):
    match = SSH_PATTERN.search(log)
    if not match:
        return None

    month, day, time, hostname, status, method, username, ip = match.groups()
    failed = status == "Failed"

    return {
        "timestamp": syslog_timestamp(month, day, time, now),
        "source": "linux",
        "event_type": FAILED_LOGIN if failed else LOGIN_SUCCESS,
        "username": username,
        "source_ip": ip,
        "destination_ip": None,
        "action": "failure" if failed else "success",
        "severity": "medium" if failed else "low",
        "message": log,
        # Optional fields
        "hostname": hostname,
        "process_name": "sshd",
    }


def normalize_ufw(log, now=None):
    match = UFW_PATTERN.search(log)
    if not match:
        return None

    month, day, time, hostname, verdict, src, dst, protocol, dst_port = match.groups()
    blocked = verdict == "BLOCK"

    return {
        "timestamp": syslog_timestamp(month, day, time, now),
        "source": "firewall",
        "event_type": FIREWALL_BLOCK if blocked else FIREWALL_ALLOW,
        "username": None,
        "source_ip": src,
        "destination_ip": dst,
        "action": "blocked" if blocked else "allowed",
        "severity": "low",
        "message": log,
        # Optional fields
        "hostname": hostname,
        "destination_port": int(dst_port) if dst_port else None,
        "protocol": protocol.lower(),
    }


def normalize_log(log, now=None):
    """Return one normalized event, or None if the line is not recognized."""
    return normalize_ssh(log, now) or normalize_ufw(log, now)


def normalize_logs(logs, now=None):
    events = []
    for log in logs:
        event = normalize_log(log, now)
        if event is not None:  # unrecognized lines are skipped, not fatal
            events.append(event)
    return events


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelWatch Log Normalizer")
    parser.add_argument("files", nargs="*", help="log files (default: sample_auth.log)")
    parser.add_argument("-o", "--out", default="normalized_events.json")
    args = parser.parse_args()

    raw_logs = collect_logs(args.files)
    normalized_events = normalize_logs(raw_logs)

    print("SentinelWatch Log Normalizer")
    print(f"Lines read: {len(raw_logs)}")
    print(f"Total normalized events: {len(normalized_events)}")
    print(f"Lines skipped: {len(raw_logs) - len(normalized_events)}")
    print(json.dumps(normalized_events, indent=4))

    with open(args.out, "w") as file:
        json.dump(normalized_events, file, indent=4)

    print(f"Normalized events saved to {args.out}")
