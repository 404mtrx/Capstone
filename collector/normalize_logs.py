"""SentinelWatch log normalizer.

Turns raw log lines into events in the common event schema (see collector/README.md).

Supported sources:
  linux     - /var/log/auth.log lines from sshd, sudo, useradd, usermod,
              gpasswd and pam_faillock / pam_tally2
  firewall  - UFW lines written by the kernel (/var/log/ufw.log)
  web       - nginx / Apache access logs in the "combined" format

Syslog lines may start with the classic "Oct  8 14:30:00" date or the
RFC 3339 date that newer systems write ("2026-10-27T20:15:02.123456+00:00").
"""
import argparse
import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from collect_logs import collect_logs

# Event type names shared with the detection engine. Agree on any change with Satya.
FAILED_LOGIN = "failed_login"
LOGIN_SUCCESS = "authentication_success"
FIREWALL_BLOCK = "firewall_block"
FIREWALL_ALLOW = "firewall_allow"
SUDO_FAILURE = "sudo_failure"
SUDO_COMMAND = "sudo_command"
USER_ADDED = "user_added"
PRIVILEGE_CHANGE = "privilege_change"
GROUP_CHANGE = "group_change"
ACCOUNT_LOCKOUT = "account_lockout"
HTTP_REQUEST = "http_request"
HTTP_ERROR = "http_error"
WEB_ATTACK = "web_attack"

# Groups that give administrator rights on Linux.
ADMIN_GROUPS = {"sudo", "wheel", "admin", "root", "adm"}

IP = r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:]+)"

# Syslog header with the classic date: "Oct  8 14:30:00 ubuntu sshd[1234]: ..."
BSD_HEADER = re.compile(
    r"^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\s\[:]+)(?:\[\d+\])?:\s?(.*)$"
)
# Syslog header with an RFC 3339 date: "2026-10-27T20:15:02.123456+00:00 parrot sshd[1]: ..."
ISO_HEADER = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+"
    r"(\S+)\s+([^\s\[:]+)(?:\[\d+\])?:\s?(.*)$"
)

SSH_LOGIN = re.compile(
    r"(Failed|Accepted) (password|publickey|keyboard-interactive/pam) for "
    r"(?:invalid user )?(\S+) from " + IP
)
SUDO_INCORRECT = re.compile(r"^\s*(\S+) : (\d+) incorrect password attempts?")
SUDO_RUN = re.compile(r"^\s*(\S+) : TTY=.*?USER=(\S+) ; COMMAND=(.*)$")
USERADD = re.compile(r"new user: name=([^,\s]+)")
USERMOD_GROUP = re.compile(r"^add '([^']+)' to group '([^']+)'")
GPASSWD_GROUP = re.compile(r"^user (\S+) added by \S+ to group (\S+)")
FAILLOCK = re.compile(r"Consecutive login failures for user (\S+) account temporarily locked")
TALLY = re.compile(r"user (\S+) \(\d+\) tally \d+, deny \d+")
UFW = re.compile(r"\[UFW (BLOCK|ALLOW)\].*?SRC=(\S+) DST=(\S+).*?PROTO=(\w+)(?:.*?DPT=(\d+))?")

# nginx / Apache "combined" access log.
ACCESS_LOG = re.compile(
    r"^" + IP + r' \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+)(?: [^"]*)?" (\d{3}) \S+'
)
# Request paths that are attack attempts rather than normal browsing.
WEB_ATTACK_PATTERNS = re.compile(
    r"(\.\./|%2e%2e%2f|union(\s|\+|%20)+select|'\s*or\s*'?1'?\s*=\s*'?1|"
    r"%27(\s|\+|%20)*or|<script|%3cscript|/etc/passwd|cmd\.exe|"
    r"\bsleep\(|benchmark\()",
    re.IGNORECASE,
)


def to_utc_z(stamp):
    """Format a timezone-aware datetime as ISO-8601 UTC ending in Z."""
    return stamp.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def syslog_timestamp(month, day, time, now=None):
    """Convert a syslog date (which has no year) to ISO-8601 UTC.

    Uses the current year. If that would put the event more than a day in
    the future (for example a December log read in January), uses the
    previous year. Classic syslog dates carry no time zone; we treat them as UTC.
    """
    now = now or datetime.now(timezone.utc)
    stamp = datetime.strptime(
        f"{now.year} {month} {day} {time}", "%Y %b %d %H:%M:%S"
    ).replace(tzinfo=timezone.utc)

    if stamp > now + timedelta(days=1):
        stamp = stamp.replace(year=now.year - 1)

    return stamp.isoformat().replace("+00:00", "Z")


def iso_timestamp(text):
    """Convert an RFC 3339 date (any offset) to ISO-8601 UTC."""
    if re.search(r"[+-]\d{4}$", text):  # +0000 -> +00:00
        text = text[:-2] + ":" + text[-2:]
    return to_utc_z(datetime.fromisoformat(text.replace("Z", "+00:00")))


def parse_syslog_header(log, now=None):
    """Split a syslog line into (timestamp, hostname, program, message), or None."""
    match = BSD_HEADER.match(log)
    if match:
        month, day, time, host, program, message = match.groups()
        try:
            return syslog_timestamp(month, day, time, now), host, program, message
        except ValueError:
            return None

    match = ISO_HEADER.match(log)
    if match:
        stamp, host, program, message = match.groups()
        try:
            return iso_timestamp(stamp), host, program, message
        except ValueError:
            return None

    return None


def make_event(timestamp, source, event_type, action, severity, log, *,
               username=None, source_ip=None, destination_ip=None, **optional):
    """Build an event with the 9 core fields plus any optional fields that have a value."""
    event = {
        "timestamp": timestamp,
        "source": source,
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "action": action,
        "severity": severity,
        "message": log,
    }
    event.update({key: value for key, value in optional.items() if value is not None})
    return event


def normalize_ssh(timestamp, host, message, log):
    match = SSH_LOGIN.search(message)
    if not match:
        # Other sshd lines (including the pre-login "Invalid user" notice) are
        # skipped so brute-force rules do not count one attempt twice.
        return None

    status, _method, username, ip = match.groups()
    failed = status == "Failed"
    return make_event(
        timestamp, "linux",
        FAILED_LOGIN if failed else LOGIN_SUCCESS,
        "failure" if failed else "success",
        "medium" if failed else "low",
        log, username=username, source_ip=ip, hostname=host, process_name="sshd",
    )


def normalize_sudo(timestamp, host, message, log):
    match = SUDO_INCORRECT.search(message)
    if match:
        return make_event(timestamp, "linux", SUDO_FAILURE, "failure", "medium", log,
                          username=match.group(1), hostname=host, process_name="sudo")

    match = SUDO_RUN.search(message)
    if match:
        return make_event(timestamp, "linux", SUDO_COMMAND, "success", "low", log,
                          username=match.group(1), hostname=host, process_name="sudo")
    return None


def normalize_account(program, timestamp, host, message, log):
    """useradd, usermod and gpasswd lines."""
    match = USERADD.search(message)
    if program == "useradd" and match:
        return make_event(timestamp, "linux", USER_ADDED, "success", "medium", log,
                          username=match.group(1), hostname=host, process_name=program)

    # usermod writes "add 'bob' to group 'sudo'" and a second "shadow group" line
    # for the same change; only the first is used.
    match = USERMOD_GROUP.search(message) or GPASSWD_GROUP.search(message)
    if program in ("usermod", "gpasswd") and match:
        username, group = match.groups()
        admin = group in ADMIN_GROUPS
        return make_event(timestamp, "linux",
                          PRIVILEGE_CHANGE if admin else GROUP_CHANGE,
                          "success", "medium" if admin else "low", log,
                          username=username, hostname=host, process_name=program)
    return None


def normalize_lockout(program, timestamp, host, message, log):
    match = FAILLOCK.search(message) or TALLY.search(message)
    if not match:
        return None
    return make_event(timestamp, "linux", ACCOUNT_LOCKOUT, "blocked", "medium", log,
                      username=match.group(1), hostname=host, process_name=program)


def normalize_ufw(timestamp, host, message, log):
    match = UFW.search(message)
    if not match:
        return None

    verdict, src, dst, protocol, dst_port = match.groups()
    blocked = verdict == "BLOCK"
    return make_event(
        timestamp, "firewall",
        FIREWALL_BLOCK if blocked else FIREWALL_ALLOW,
        "blocked" if blocked else "allowed",
        "low", log, source_ip=src, destination_ip=dst, hostname=host,
        destination_port=int(dst_port) if dst_port else None,
        protocol=protocol.lower(),
    )


def normalize_syslog(log, now=None):
    header = parse_syslog_header(log, now)
    if header is None:
        return None
    timestamp, host, program, message = header

    # Lockout lines are written under the program that was logging in (sshd, login, su),
    # so they are checked before the per-program parsers.
    if "pam_faillock" in message or "pam_tally" in message:
        return normalize_lockout(program, timestamp, host, message, log)
    if program == "sshd":
        return normalize_ssh(timestamp, host, message, log)
    if program == "sudo":
        return normalize_sudo(timestamp, host, message, log)
    if program in ("useradd", "usermod", "gpasswd"):
        return normalize_account(program, timestamp, host, message, log)
    if program == "kernel":
        return normalize_ufw(timestamp, host, message, log)
    return None


def normalize_access(log, now=None):
    """nginx / Apache combined access log line."""
    match = ACCESS_LOG.match(log)
    if not match:
        return None

    ip, user, stamp, method, path, status = match.groups()
    try:
        timestamp = to_utc_z(datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z"))
    except ValueError:
        return None

    status = int(status)
    if WEB_ATTACK_PATTERNS.search(path):
        event_type, severity = WEB_ATTACK, "high"
    elif status >= 400:
        event_type, severity = HTTP_ERROR, "low"
    else:
        event_type, severity = HTTP_REQUEST, "low"

    return make_event(
        timestamp, "web", event_type,
        "success" if status < 400 else "failure", severity, log,
        username=None if user == "-" else user, source_ip=ip,
        protocol="http", process_name="webserver",
    )


def normalize_log(log, now=None):
    """Return one normalized event, or None if the line is not recognized."""
    return normalize_syslog(log, now) or normalize_access(log, now)


def normalize_logs(logs, now=None):
    events = []
    for log in logs:
        event = normalize_log(log, now)
        if event is not None:  # unrecognized lines are skipped, not fatal
            events.append(event)
    return events


def print_summary(raw_logs, events):
    print("SentinelWatch Log Normalizer")
    print(f"Lines read: {len(raw_logs)}")
    print(f"Total normalized events: {len(events)}")
    print(f"Lines skipped: {len(raw_logs) - len(events)}")
    for event_type, count in sorted(Counter(e["event_type"] for e in events).items()):
        print(f"  {event_type}: {count}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelWatch Log Normalizer")
    parser.add_argument("files", nargs="*", help="log files (default: sample_auth.log)")
    parser.add_argument("-o", "--out", default="normalized_events.json")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="print only the summary, not every event")
    args = parser.parse_args()

    raw_logs = collect_logs(args.files)
    normalized_events = normalize_logs(raw_logs)

    print_summary(raw_logs, normalized_events)
    if not args.quiet:
        print(json.dumps(normalized_events, indent=4))

    with open(args.out, "w") as file:
        json.dump(normalized_events, file, indent=4)

    print(f"Normalized events saved to {args.out}")
