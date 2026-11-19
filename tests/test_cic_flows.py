"""Tests for the CSE-CIC-IDS2018 flow reader (collector/cic_flows.py), TC-LOG-26."""
import json
from pathlib import Path

from cic_flows import flow_to_event, main, parse_time, read_flows

SAMPLE = Path(__file__).resolve().parent.parent / "collector" / "cic_sample" / "sample_flows.csv"
CORE_FIELDS = {
    "timestamp", "source", "event_type", "username", "source_ip",
    "destination_ip", "action", "severity", "message",
}


def test_timestamp_day_first_to_utc():
    assert parse_time("14/02/2018 08:31:01") == "2018-02-14T08:31:01Z"
    assert parse_time("02/03/2018 10:05:00") == "2018-03-02T10:05:00Z"  # 2 March, not Feb 3
    assert parse_time("garbage") is None


def test_flow_row_becomes_event():
    row = {"Dst Port": "22", "Protocol": "6", "Timestamp": "14/02/2018 14:01:00",
           "Flow Duration": "380000", "Tot Fwd Pkts": "21", "Tot Bwd Pkts": "33",
           "Label": "SSH-Bruteforce"}
    e = flow_to_event(row, flow_id="x-1")
    assert CORE_FIELDS <= e.keys()
    assert e["source"] == "network"
    assert e["event_type"] == "network_flow"
    assert e["destination_port"] == 22
    assert e["protocol"] == "tcp"
    assert e["label"] == "SSH-Bruteforce"
    assert e["severity"] == "medium"
    assert "label=SSH-Bruteforce" in e["message"]
    assert e["event_id"] == "x-1"


def test_benign_flow_is_low_severity_and_udp_mapped():
    e = flow_to_event({"Dst Port": "53", "Protocol": "17", "Timestamp": "14/02/2018 09:12:45",
                       "Label": "Benign"})
    assert e["severity"] == "low"
    assert e["protocol"] == "udp"


def test_sample_file_counts_and_skips_bad_rows():
    events = list(read_flows(SAMPLE))
    labels = [e["label"] for e in events]
    assert labels.count("Benign") == 3
    assert labels.count("FTP-BruteForce") == 5
    assert labels.count("SSH-Bruteforce") == 6
    assert len(events) == 14  # repeated header, bad date and empty label skipped


def test_label_filter_sampling_and_limit():
    assert {e["label"] for e in read_flows(SAMPLE, labels={"SSH-Bruteforce"})} == {"SSH-Bruteforce"}
    assert len(list(read_flows(SAMPLE, labels={"SSH-Bruteforce"}, every=2))) == 3
    assert len(list(read_flows(SAMPLE, limit=4))) == 4


def test_event_ids_are_unique():
    ids = [e["event_id"] for e in read_flows(SAMPLE)]
    assert len(ids) == len(set(ids))


def test_cli_writes_json(tmp_path):
    out = tmp_path / "cic.json"
    assert main([str(SAMPLE), "-o", str(out), "--labels", "FTP-BruteForce"]) == 0
    events = json.loads(out.read_text())
    assert len(events) == 5
    assert {e["destination_port"] for e in events} == {21}
