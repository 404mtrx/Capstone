# CSCE 4907 Cybersecurity Capstone
# Team - Netrunners

## SentinelWatch: A Lightweight SIEM/SOC Platform

## Team members

| Member | Area |
| --- | --- |
| Satya Pun Magar | Detection and correlation engine |
| Kritika Thapa Magar | Log collection and normalization |
| Matrika Timilsaina | SOC dashboard (frontend) |
| Aayan Nisar Zafar | Backend API, database, authentication and security |

## Description

Small organizations such as schools, nonprofits and small businesses generate
security logs but rarely centralize them, because commercial SIEM products are
priced and staffed for enterprises. Signs of an attack (repeated failed logins,
a port scan, a new administrator account) go unnoticed until it is too late.

SentinelWatch is a lightweight, self-hosted security platform that combines
three core blue-team capabilities into one product:

1. **Collects and normalizes security logs** from Linux authentication logs,
   UFW firewall logs and nginx/Apache web-server logs into one common event
   format, and stores them in OpenSearch for search and analysis.
2. **Applies rule-based detection and correlation** to the events to identify
   suspicious activity and generate alerts with severity and supporting evidence.
3. **Presents security activity and alerts** through a SOC dashboard where
   analysts log in, review alerts, change their status and open cases.

## Architecture

```
Log files (auth.log, ufw.log, web access log)
   │
   ▼
collector/  ── normalize ──► POST /events ──► OpenSearch (events)
                                                   │
detection/  ◄── GET /events ───────────────────────┘
   │
   └── rules ──► POST /alerts ──► PostgreSQL (alerts, cases, users, audit log)
                                        │
frontend/ (React dashboard) ◄── login, GET /alerts, PATCH /alerts, /cases
```

| Folder | What it contains |
| --- | --- |
| `collector/` | Log collector, normalizer, live follow mode, sample, scenario and real lab logs ([collector/README.md](collector/README.md)) |
| `detection/` | Detection engine and rules ([detection/README.md](detection/README.md)) |
| `backend/` | FastAPI service, PostgreSQL models and Alembic migrations, login and roles ([docs/backend-setup.md](docs/backend-setup.md)) |
| `frontend/sentinelwatch-ui/` | React + TypeScript SOC dashboard |
| `tests/` | Collector, detection, scenario and real-log tests |
| `backend/tests/` | API, authentication, access-control, audit and OpenSearch tests |
| `scripts/` | OpenSearch user setup and recorded test scripts |
| `docs/test-evidence/` | Saved test runs and evidence |

**Technologies:** Python 3, FastAPI, PostgreSQL 16, SQLModel/Alembic,
OpenSearch 2.17 (HTTPS with login), React + TypeScript (Vite), Docker Compose, pytest.

## SentinelWatch Common Security Event Schema

All log sources are converted into one flat event format, so detection rules
and storage do not depend on the original log format.

```json
{
  "timestamp": "2026-10-08T14:30:00Z",
  "source": "linux",
  "event_type": "failed_login",
  "username": "admin",
  "source_ip": "192.168.1.25",
  "destination_ip": null,
  "action": "failure",
  "severity": "medium",
  "message": "<original log line>"
}
```

These 9 core fields are always present. Optional fields are added when a log
source has them: `destination_port`, `hostname`, `protocol`, `event_id`,
`process_name`. Timestamps are ISO-8601 in UTC.

| Source | Event types |
| --- | --- |
| `linux` (auth.log) | `failed_login`, `authentication_success`, `sudo_failure`, `sudo_command`, `user_added`, `privilege_change`, `group_change`, `account_lockout` |
| `firewall` (UFW) | `firewall_block`, `firewall_allow` |
| `web` (nginx/Apache) | `http_request`, `http_error`, `web_attack` |

## Detection Rules

SentinelWatch targets 10–15 rule-based detections.

| # | Rule | Status |
| --- | --- | --- |
| 1 | Failed Login | Implemented |
| 2 | Multiple Failed Logins | Implemented |
| 3 | Successful Login After Multiple Failures (correlation) | Implemented |
| 4 | Password Spraying | Implemented |
| 5 | Port Scan | Implemented |
| 6 | Repeated Blocked Connections | Implemented |
| 7 | High-Severity Event | Implemented |
| 8 | Account Lockout | Implemented |
| 9 | Privilege Change | Implemented |
| 10 | Suspicious Remote Login | Implemented |
| 11 | Repeated Access to Sensitive Ports | Planned |
| 12 | Suspicious Activity From Same Source IP | Planned |
| 13 | Repeated Authentication Across Hosts | Planned |

## Quick start

Requirements: Docker Desktop (at least 4 GB of memory), Python 3.11+, Node.js.
If PostgreSQL is installed directly on your machine, stop it first so it does
not take port 5432 (for example `brew services stop postgresql@14`).

```bash
# 1. Services (PostgreSQL and OpenSearch)
docker compose up -d
docker compose ps                      # wait until both are healthy

# 2. Backend
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env                   # set SECRET_KEY and API_KEY
cd .. && bash scripts/opensearch_setup_user.sh && cd backend
alembic upgrade head
python -m app.create_user <name> --role admin
uvicorn app.main:app --reload          # http://127.0.0.1:8000/docs

# 3. Collector and detection (second terminal, repository root)
export SENTINEL_API_KEY=<API_KEY from backend/.env>
python3 collector/normalize_logs.py collector/sample_auth.log collector/sample_ufw.log collector/sample_access.log -o events.json
python3 collector/send_events.py events.json
python3 detection/engine.py            # one pass; add --watch 5 to keep checking every 5 s (live demo)

# 4. Dashboard (third terminal)
cd frontend/sentinelwatch-ui && npm install && npm run dev   # http://localhost:5173
```

Live collection: `python3 collector/follow_logs.py /var/log/auth.log /var/log/ufw.log`
watches log files and sends new events every few seconds.

## Testing

```bash
source backend/.venv/bin/activate
python -m pytest tests -v                  # collector, detection, scenarios, real logs
cd backend && pytest                       # API, auth, access control, audit, OpenSearch
```

`collector/scenarios/` holds a labeled log for each demonstration scenario
(brute force, account compromise, password spraying, port scan, privilege
escalation, account lockout, web attack) and a benign baseline; the tests check
that each raises its expected alerts and the baseline raises none.
`collector/real_logs/` holds real logs captured from a lab virtual machine.
Test results are saved in `docs/test-evidence/`.

All test data is synthetic or captured in an isolated lab. No real credentials
or personal data are used.

## Project management

- GitHub: feature branches and reviewed pull requests into `main`
- Trello: Netrunners – CAPSTONE board, updated at every merge
