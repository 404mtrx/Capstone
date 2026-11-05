"""Integration test: every demonstration scenario log, run through the collector
and the detection engine, raises exactly the alerts listed in labels.json,
and the benign baseline raises none (TC-INT-06, supports TC-EVAL-01/02)."""
import json
from datetime import datetime, timezone
from pathlib import Path

from collect_logs import collect_logs
from normalize_logs import normalize_logs
from detection.engine import analyze_events

SCENARIOS = Path(__file__).resolve().parent.parent / "collector" / "scenarios"
NOW = datetime(2026, 11, 5, 18, tzinfo=timezone.utc)


def labels():
    data = json.loads((SCENARIOS / "labels.json").read_text())
    return {name: label for name, label in data.items() if not name.startswith("_")}


def alerts_for(name):
    events = normalize_logs(collect_logs([SCENARIOS / name]), NOW)
    return {alert["rule_name"] for alert in analyze_events(events)}


def test_every_scenario_file_has_a_label():
    logs = {path.name for path in SCENARIOS.glob("*.log")}
    assert logs == set(labels())


def test_attack_scenarios_raise_their_expected_alerts():
    for name, label in labels().items():
        if label["attack"]:
            missing = set(label["expected_alerts"]) - alerts_for(name)
            assert not missing, f"{name}: missing {missing}"


def test_benign_baseline_raises_no_alerts():
    for name, label in labels().items():
        if not label["attack"]:
            assert alerts_for(name) == set(), name
