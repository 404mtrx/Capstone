"""Real logs captured from the lab VM (collector/real_logs/) are normalized
correctly and raise the expected alerts (TC-LOG-25, TC-INT-07)."""
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from collect_logs import collect_logs
from normalize_logs import normalize_logs
from detection.engine import analyze_events

REAL = Path(__file__).resolve().parent.parent / "collector" / "real_logs"
NOW = datetime(2026, 11, 6, tzinfo=timezone.utc)


def events_for(name):
    return normalize_logs(collect_logs([REAL / name]), NOW)


def test_real_auth_log_events():
    events = events_for("parrot_auth.log")
    assert Counter(e["event_type"] for e in events) == {
        "sudo_command": 5, "user_added": 1, "privilege_change": 1,
    }
    change = next(e for e in events if e["event_type"] == "privilege_change")
    assert change["username"] == "labtest"
    assert change["timestamp"] == "2026-11-05T20:05:52Z"
    assert change["hostname"] == "parrot"


def test_real_ufw_log_events():
    events = events_for("parrot_ufw.log")
    assert len(events) == 10
    assert {e["event_type"] for e in events} == {"firewall_block"}
    assert {e["source_ip"] for e in events} == {"192.168.64.1"}
    assert {e["destination_port"] for e in events} == {21, 23, 25, 80, 110}


def test_real_logs_raise_expected_alerts():
    auth_alerts = {a["rule_name"] for a in analyze_events(events_for("parrot_auth.log"))}
    ufw_alerts = {a["rule_name"] for a in analyze_events(events_for("parrot_ufw.log"))}
    assert "Privilege Change Detected" in auth_alerts
    assert {"Port Scan Detected", "Repeated Blocked Connections"} <= ufw_alerts
