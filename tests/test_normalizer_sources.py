"""Tests for the log types added in Sprint 3: more auth.log events,
RFC 3339 syslog dates and the web-server access log (third source)."""
from datetime import datetime, timezone

from normalize_logs import normalize_log

NOW = datetime(2026, 11, 5, 18, tzinfo=timezone.utc)
CORE_FIELDS = {
    "timestamp", "source", "event_type", "username", "source_ip",
    "destination_ip", "action", "severity", "message",
}


# TC-LOG-14: RFC 3339 dates (Ubuntu 24.04 / journalctl -o short-iso)
def test_iso_syslog_date_with_offset_is_converted_to_utc():
    line = "2026-10-27T15:15:02.123456-05:00 parrot sshd[901]: Failed password for root from 192.168.64.1 port 50000 ssh2"
    e = normalize_log(line, NOW)
    assert e["timestamp"] == "2026-10-27T20:15:02Z"
    assert e["event_type"] == "failed_login"
    assert e["hostname"] == "parrot"


def test_iso_syslog_date_without_colon_in_offset():
    line = "2026-10-27T20:15:02+0000 parrot sshd[901]: Accepted password for user from 192.168.64.1 port 50000 ssh2"
    assert normalize_log(line, NOW)["timestamp"] == "2026-10-27T20:15:02Z"


def test_iso_ufw_line():
    line = ("2026-10-27T20:20:01.5+00:00 parrot kernel: [UFW BLOCK] IN=enp0s1 OUT= "
            "SRC=192.168.64.1 DST=192.168.64.2 LEN=64 PROTO=TCP SPT=50001 DPT=23 SYN URGP=0")
    e = normalize_log(line, NOW)
    assert e["event_type"] == "firewall_block"
    assert e["destination_port"] == 23


# TC-LOG-15: privilege change, new account, group change
def test_usermod_add_to_sudo_is_privilege_change():
    e = normalize_log("Nov  5 13:23:05 web01 usermod[5131]: add 'backup2' to group 'sudo'", NOW)
    assert e["event_type"] == "privilege_change"
    assert e["username"] == "backup2"
    assert e["process_name"] == "usermod"


def test_usermod_shadow_group_line_is_not_double_counted():
    assert normalize_log("Nov  5 13:23:05 web01 usermod[5131]: add 'backup2' to shadow group 'sudo'", NOW) is None


def test_gpasswd_add_to_wheel_is_privilege_change():
    e = normalize_log("Nov  5 13:30:00 web01 gpasswd[5200]: user eve added by root to group wheel", NOW)
    assert e["event_type"] == "privilege_change"
    assert e["username"] == "eve"


def test_non_admin_group_is_group_change():
    e = normalize_log("Nov  5 08:12:44 web01 usermod[1302]: add 'student' to group 'docker'", NOW)
    assert e["event_type"] == "group_change"
    assert e["severity"] == "low"


def test_useradd_new_user():
    line = "Nov  5 13:22:40 web01 useradd[5120]: new user: name=backup2, UID=1005, GID=1005, home=/home/backup2, shell=/bin/bash"
    e = normalize_log(line, NOW)
    assert e["event_type"] == "user_added"
    assert e["username"] == "backup2"


def test_useradd_new_group_line_is_skipped():
    assert normalize_log("Nov  5 13:22:40 web01 useradd[5120]: new group: name=backup2, GID=1005", NOW) is None


# TC-LOG-16: sudo and account lockout
def test_sudo_incorrect_password_attempts():
    line = "Nov  5 13:20:04 web01 sudo:  student : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/student ; USER=root ; COMMAND=/usr/bin/su"
    e = normalize_log(line, NOW)
    assert e["event_type"] == "sudo_failure"
    assert e["username"] == "student"
    assert e["action"] == "failure"


def test_sudo_command():
    line = "Nov  5 08:06:02 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"
    e = normalize_log(line, NOW)
    assert e["event_type"] == "sudo_command"
    assert e["username"] == "alice"


def test_pam_faillock_lockout_under_sshd():
    line = ("Nov  5 14:02:27 web01 sshd[6201]: pam_faillock(sshd:auth): "
            "Consecutive login failures for user maria account temporarily locked")
    e = normalize_log(line, NOW)
    assert e["event_type"] == "account_lockout"
    assert e["username"] == "maria"
    assert e["process_name"] == "sshd"


def test_pam_tally2_lockout():
    e = normalize_log("Nov  5 14:05:00 web01 login[700]: pam_tally2(login:auth): user bob (1002) tally 4, deny 3", NOW)
    assert e["event_type"] == "account_lockout"
    assert e["username"] == "bob"


# TC-LOG-17: web-server access log (third source)
def test_web_normal_request():
    e = normalize_log('10.0.0.40 - - [05/Nov/2026:08:10:01 +0000] "GET / HTTP/1.1" 200 4210 "-" "Mozilla/5.0"', NOW)
    assert e["source"] == "web"
    assert e["event_type"] == "http_request"
    assert e["action"] == "success"
    assert e["source_ip"] == "10.0.0.40"
    assert e["timestamp"] == "2026-11-05T08:10:01Z"


def test_web_not_found_is_http_error():
    e = normalize_log('198.51.100.200 - - [05/Nov/2026:15:10:02 +0000] "GET /admin HTTP/1.1" 404 153 "-" "x"', NOW)
    assert e["event_type"] == "http_error"
    assert e["action"] == "failure"


def test_web_sql_injection_is_attack():
    line = '198.51.100.200 - - [05/Nov/2026:15:10:06 +0000] "GET /p?id=1+UNION+SELECT+password+FROM+users HTTP/1.1" 500 98 "-" "sqlmap"'
    e = normalize_log(line, NOW)
    assert e["event_type"] == "web_attack"
    assert e["severity"] == "high"


def test_web_path_traversal_is_attack():
    line = '198.51.100.200 - - [05/Nov/2026:15:10:08 +0000] "GET /download?file=../../etc/passwd HTTP/1.1" 403 153 "-" "curl"'
    assert normalize_log(line, NOW)["event_type"] == "web_attack"


def test_web_time_zone_offset_converted_to_utc():
    line = '10.0.0.40 - alice [05/Nov/2026:09:00:00 -0600] "POST /login HTTP/1.1" 302 0 "-" "x"'
    e = normalize_log(line, NOW)
    assert e["timestamp"] == "2026-11-05T15:00:00Z"
    assert e["username"] == "alice"


def test_web_ipv6_client():
    e = normalize_log('2001:db8::7 - - [05/Nov/2026:08:00:00 +0000] "GET / HTTP/2.0" 200 10 "-" "x"', NOW)
    assert e["source_ip"] == "2001:db8::7"


def test_every_new_event_type_has_core_fields():
    lines = [
        "Nov  5 13:23:05 web01 usermod[5131]: add 'backup2' to group 'sudo'",
        "Nov  5 13:22:40 web01 useradd[5120]: new user: name=backup2, UID=1005",
        "Nov  5 13:20:04 web01 sudo:  student : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
        "Nov  5 14:02:27 web01 sshd[6201]: pam_faillock(sshd:auth): Consecutive login failures for user maria account temporarily locked",
        '10.0.0.40 - - [05/Nov/2026:08:10:01 +0000] "GET / HTTP/1.1" 200 4210 "-" "Mozilla/5.0"',
    ]
    for line in lines:
        assert CORE_FIELDS <= normalize_log(line, NOW).keys()


def test_severity_values_are_accepted_by_the_api():
    # The API only accepts low, medium, high and critical.
    lines = [
        "Nov  5 13:23:05 web01 usermod[5131]: add 'backup2' to group 'sudo'",
        '198.51.100.200 - - [05/Nov/2026:15:10:08 +0000] "GET /../etc/passwd HTTP/1.1" 403 1 "-" "x"',
    ]
    for line in lines:
        assert normalize_log(line, NOW)["severity"] in {"low", "medium", "high", "critical"}


def test_garbage_lines_are_skipped():
    for line in ["", "hello world", "Nov  5 garbage", '1.2.3.4 - - [bad date] "GET / HTTP/1.1" 200 1']:
        assert normalize_log(line, NOW) is None
