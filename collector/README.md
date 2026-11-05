# SentinelWatch Collector

Owner: Kritika Thapa Magar

The collector reads security logs, converts every recognized line into the
common event schema, and sends the events to the backend (`POST /events`).
Lines it does not recognize are skipped and counted, never fatal.

```
log files ──► collect_logs.py ──► normalize_logs.py ──► send_events.py ──► POST /events ──► OpenSearch
                         └──────── follow_logs.py (live: watch + normalize + send) ────────┘
```

## Supported log sources

| Source | File | Recognized lines | `event_type` values |
| --- | --- | --- | --- |
| `linux` | `/var/log/auth.log` | sshd logins (password, publickey, keyboard-interactive, invalid users) | `failed_login`, `authentication_success` |
| | | sudo | `sudo_failure`, `sudo_command` |
| | | useradd | `user_added` |
| | | usermod / gpasswd group changes | `privilege_change` (sudo, wheel, admin, root, adm), `group_change` (other groups) |
| | | pam_faillock / pam_tally2 | `account_lockout` |
| `firewall` | `/var/log/ufw.log` | UFW kernel lines | `firewall_block`, `firewall_allow` |
| `web` | nginx / Apache access log (combined format) | every request | `http_request` (< 400), `http_error` (≥ 400), `web_attack` (SQL injection, path traversal, script injection) |

Syslog dates can be the classic `Oct  8 14:30:00` (no year: the current year is
used, or last year for a December log read in January) or RFC 3339
`2026-10-27T20:15:02.123456+00:00` (Ubuntu 24.04, `journalctl -o short-iso`).
All timestamps are stored in UTC (`...Z`). Classic syslog dates have no time
zone and are treated as UTC.

## Event fields

Core (always present): `timestamp`, `source`, `event_type`, `username`,
`source_ip`, `destination_ip`, `action`, `severity`, `message` (the original line).

Optional (added when known): `hostname`, `process_name`, `destination_port`, `protocol`.

`action` values: `success` / `failure` (logins, sudo, web), `blocked` / `allowed`
(firewall), `blocked` (account lockout).

`severity` set by the collector: `low`, `medium` or `high` (only `web_attack` is
`high`). Alerts get their own severity from the detection rules.

## Commands (run from the repository root)

```bash
# Normalize files to JSON (default input: collector/sample_auth.log)
python3 collector/normalize_logs.py collector/sample_auth.log collector/sample_ufw.log collector/sample_access.log -o events.json
python3 collector/normalize_logs.py big.log -q -o events.json      # summary only

# Send a JSON file to the API (batches of 500; resending is safe)
python3 collector/send_events.py events.json

# Live: watch files and send new lines every 5 seconds (Ctrl+C to stop)
python3 collector/follow_logs.py /var/log/auth.log /var/log/ufw.log
python3 collector/follow_logs.py collector/scenarios/port_scan.log --from-start --once --dry-run
```

`follow_logs.py` options: `--interval N`, `--from-start`, `--once`, `--dry-run`,
`--url URL`, `--state FILE` (default `.collector_state.json`).

Follow mode handles log rotation and truncation, waits for half-written lines,
keeps events queued and retries when the API is down (5xx or no connection),
drops events the API rejects (4xx) with a message, and saves read positions only
after a successful send, so a restart never loses events.

## Demonstration scenarios

`collector/scenarios/` holds one synthetic log per demonstration scenario, and
`labels.json` lists the alerts each must raise. `tests/test_scenarios.py` runs
them through the collector and the detection engine.

| Log | Expected alerts |
| --- | --- |
| `brute_force.log` | Multiple Failed Logins |
| `account_compromise.log` | Multiple Failed Logins, Successful Login After Multiple Failures |
| `password_spraying.log` | Password Spraying Detected |
| `port_scan.log` | Port Scan Detected, Repeated Blocked Connections |
| `privilege_escalation.log` | Privilege Change Detected |
| `account_lockout.log` | Account Lockout Detected |
| `web_attack.log` | High Severity Event |
| `benign.log` | none |

All IP addresses in the samples are from documentation ranges or private
networks. No real credentials or personal data are used.

## Real log data

For testing with real attack traffic, the public Loghub OpenSSH log
(https://github.com/logpai/loghub, Zhu et al., ISSRE 2023) normalizes without
changes: 2,000 lines → 520 events (519 failed logins, 1 success). It is not
committed to this repository.

## Tests

```bash
python -m pytest tests -v
```

| File | Covers |
| --- | --- |
| `tests/test_normalizer.py` | SSH and UFW parsing, timestamps, skipped lines (Sprint 2) |
| `tests/test_normalizer_sources.py` | RFC 3339 dates, sudo, useradd, group changes, lockouts, web log |
| `tests/test_follow_logs.py` | follow mode, rotation, retries, saved positions, batching |
| `tests/test_scenarios.py` | scenario logs → detection engine → expected alerts |

## Known limitations

- Classic syslog dates are assumed to be UTC.
- `message repeated N times: [...]` lines count as one event, not N.
- The web parser keeps the URL and status code only in `message`; the backend
  event schema has no fields for them yet.
- Windows Event Logs are not supported (out of MVP scope).
