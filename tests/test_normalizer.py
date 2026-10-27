from datetime import datetime, timezone
from pathlib import Path

from collect_logs import collect_logs
from normalize_logs import normalize_log, normalize_logs

COLLECTOR = Path(__file__).resolve().parent.parent / "collector"
NOW = datetime(2026, 10, 27, tzinfo=timezone.utc)  # fixed "today" for repeatable tests
CORE_FIELDS = {
    "timestamp", "source", "event_type", "username", "source_ip",
    "destination_ip", "action", "severity", "message",
}

FAILED = "Oct  8 14:30:00 ubuntu sshd[1234]: Failed password for admin from 192.168.1.25 port 52341 ssh2"
ACCEPTED = "Oct  8 14:32:00 ubuntu sshd[1236]: Accepted password for student from 192.168.1.40 port 52343 ssh2"
UFW_BLOCK = ("Oct  8 14:40:01 ubuntu kernel: [12001.1] [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.50 "
             "DST=192.168.1.10 LEN=44 PROTO=TCP SPT=41000 DPT=21 WINDOW=1024 SYN URGP=0")
UFW_ALLOW = ("Oct  8 14:45:10 ubuntu kernel: [12310.2] [UFW ALLOW] IN=eth0 OUT= SRC=192.168.1.40 "
             "DST=192.168.1.10 LEN=60 PROTO=TCP SPT=52343 DPT=22 WINDOW=64240 SYN URGP=0")


# TC-LOG-02
def test_failed_password():
    e = normalize_log(FAILED, NOW)
    assert e["event_type"] == "failed_login"
    assert e["username"] == "admin"
    assert e["source_ip"] == "192.168.1.25"
    assert e["action"] == "failure"
    assert e["severity"] == "medium"


# TC-LOG-03
def test_accepted_password():
    e = normalize_log(ACCEPTED, NOW)
    assert e["event_type"] == "authentication_success"
    assert e["username"] == "student"
    assert e["action"] == "success"
    assert e["severity"] == "low"


# TC-LOG-04
def test_timestamp_is_iso_utc():
    assert normalize_log(FAILED, NOW)["timestamp"] == "2026-10-08T14:30:00Z"


# TC-LOG-05
def test_single_digit_day_and_hour():
    line = "Oct  8 09:05:00 ubuntu sshd[1]: Failed password for root from 10.0.0.9 port 22 ssh2"
    assert normalize_log(line, NOW)["timestamp"] == "2026-10-08T09:05:00Z"


# TC-LOG-06
def test_unrecognized_line_returns_none():
    assert normalize_log("hello world", NOW) is None


# TC-LOG-08 (KI-05)
def test_failed_password_for_invalid_user():
    line = "Oct  8 14:33:00 ubuntu sshd[1240]: Failed password for invalid user bob from 10.0.0.5 port 40022 ssh2"
    e = normalize_log(line, NOW)
    assert e["event_type"] == "failed_login"
    assert e["username"] == "bob"
    assert e["source_ip"] == "10.0.0.5"


# TC-LOG-09 (KI-05)
def test_accepted_publickey():
    line = "Oct  8 14:34:00 ubuntu sshd[1241]: Accepted publickey for alice from 10.0.0.6 port 40023 ssh2: RSA SHA256:abc"
    e = normalize_log(line, NOW)
    assert e["event_type"] == "authentication_success"
    assert e["username"] == "alice"


def test_invalid_user_notice_is_not_double_counted():
    # sshd also writes this line before "Failed password for invalid user".
    # Counting it too would double the failures seen by the brute-force rules.
    line = "Oct  8 14:33:00 ubuntu sshd[1240]: Invalid user bob from 10.0.0.5 port 40022"
    assert normalize_log(line, NOW) is None


# KI-06: the year comes from the current date, not a fixed 2026
def test_year_comes_from_current_date():
    jan_2027 = datetime(2027, 1, 5, tzinfo=timezone.utc)
    line = "Jan  4 10:00:00 ubuntu sshd[1]: Failed password for root from 10.0.0.9 port 22 ssh2"
    assert normalize_log(line, jan_2027)["timestamp"] == "2027-01-04T10:00:00Z"


def test_december_log_read_in_january_uses_previous_year():
    jan_2027 = datetime(2027, 1, 5, tzinfo=timezone.utc)
    line = "Dec 31 23:59:00 ubuntu sshd[1]: Failed password for root from 10.0.0.9 port 22 ssh2"
    assert normalize_log(line, jan_2027)["timestamp"] == "2026-12-31T23:59:00Z"


# TC-LOG-10: second log source (UFW firewall)
def test_ufw_block():
    e = normalize_log(UFW_BLOCK, NOW)
    assert e["source"] == "firewall"
    assert e["event_type"] == "firewall_block"
    assert e["source_ip"] == "192.168.1.50"
    assert e["destination_ip"] == "192.168.1.10"
    assert e["destination_port"] == 21
    assert e["protocol"] == "tcp"
    assert e["action"] == "blocked"


def test_ufw_allow():
    e = normalize_log(UFW_ALLOW, NOW)
    assert e["event_type"] == "firewall_allow"
    assert e["action"] == "allowed"
    assert e["destination_port"] == 22


# TC-LOG-10: every source produces all nine core fields
def test_all_core_fields_present():
    for line in (FAILED, ACCEPTED, UFW_BLOCK, UFW_ALLOW):
        assert CORE_FIELDS <= normalize_log(line, NOW).keys()


# TC-LOG-01 / TC-LOG-07: no loss or duplication on the sample files
def test_auth_sample_three_lines_three_events():
    logs = collect_logs([COLLECTOR / "sample_auth.log"])
    assert len(logs) == 3
    assert len(normalize_logs(logs, NOW)) == 3


def test_ufw_sample_every_line_normalized():
    logs = collect_logs([COLLECTOR / "sample_ufw.log"])
    events = normalize_logs(logs, NOW)
    assert len(logs) == 12
    assert len(events) == 12
    assert sum(e["event_type"] == "firewall_block" for e in events) == 10
