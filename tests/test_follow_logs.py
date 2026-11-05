"""Tests for follow mode (collector/follow_logs.py) and batched sending."""
import json
import os
import urllib.error

from follow_logs import Collector, FileFollower, load_state, main, save_state
from send_events import send_events

FAILED = "Nov  5 09:00:01 web01 sshd[2101]: Failed password for root from 203.0.113.10 port 50122 ssh2\n"
ACCEPTED = "Nov  5 09:01:00 web01 sshd[2102]: Accepted password for admin from 10.0.0.2 port 50123 ssh2\n"


class FakeSender:
    def __init__(self, fail_times=0, error=None):
        self.batches = []
        self.fail_times = fail_times
        self.error = error or urllib.error.URLError("connection refused")

    def __call__(self, events):
        if self.fail_times:
            self.fail_times -= 1
            raise self.error
        self.batches.append(list(events))


def write(path, text, mode="a"):
    with open(path, mode) as file:
        file.write(text)


# TC-LOG-18: only new lines are read, in order
def test_follower_returns_only_new_lines(tmp_path):
    log = tmp_path / "auth.log"
    write(log, FAILED)
    follower = FileFollower(log)
    assert len(follower.read_new_lines()) == 1
    assert follower.read_new_lines() == []
    write(log, ACCEPTED)
    assert follower.read_new_lines() == [ACCEPTED.strip()]


def test_partial_line_waits_until_complete(tmp_path):
    log = tmp_path / "auth.log"
    write(log, FAILED[:30])
    follower = FileFollower(log)
    assert follower.read_new_lines() == []
    write(log, FAILED[30:])
    assert follower.read_new_lines() == [FAILED.strip()]


# TC-LOG-19: rotation and truncation
def test_rotated_file_is_read_from_the_start(tmp_path):
    log = tmp_path / "auth.log"
    write(log, FAILED * 3)
    follower = FileFollower(log)
    follower.read_new_lines()
    os.rename(log, tmp_path / "auth.log.1")  # what logrotate does
    write(log, ACCEPTED)
    assert follower.read_new_lines() == [ACCEPTED.strip()]


def test_truncated_file_is_read_from_the_start(tmp_path):
    log = tmp_path / "auth.log"
    write(log, FAILED * 3)
    follower = FileFollower(log)
    follower.read_new_lines()
    write(log, ACCEPTED, mode="w")
    assert follower.read_new_lines() == [ACCEPTED.strip()]


def test_missing_file_does_not_crash(tmp_path):
    assert FileFollower(tmp_path / "nope.log").read_new_lines() == []


# TC-LOG-20: by default only lines written after start-up are sent
def test_collector_starts_at_end_of_file_by_default(tmp_path):
    log = tmp_path / "auth.log"
    write(log, FAILED * 5)
    sender = FakeSender()
    collector = Collector([log], sender)
    assert collector.tick() == 0
    write(log, ACCEPTED)
    assert collector.tick() == 1
    assert sender.batches[0][0]["event_type"] == "authentication_success"


def test_collector_from_start_sends_existing_lines(tmp_path):
    log = tmp_path / "auth.log"
    write(log, FAILED * 2 + "not a log line\n")
    sender = FakeSender()
    assert Collector([log], sender, from_start=True).tick() == 2


# TC-LOG-21: API down -> events are kept and retried, not lost
def test_events_are_retried_when_api_is_down(tmp_path):
    log = tmp_path / "auth.log"
    write(log, FAILED * 2)
    messages = []
    sender = FakeSender(fail_times=2)
    collector = Collector([log], sender, from_start=True, log=messages.append)
    assert collector.tick() == 0
    write(log, ACCEPTED)
    assert collector.tick() == 0
    assert len(collector.queue) == 3
    assert collector.tick() == 3
    assert collector.queue == []
    assert len(sender.batches) == 1
    assert "queued for retry" in messages[0]


def test_rejected_events_are_dropped_not_retried_forever(tmp_path):
    log = tmp_path / "auth.log"
    write(log, FAILED)
    error = urllib.error.HTTPError("http://x", 422, "Unprocessable", None, None)
    messages = []
    collector = Collector([log], FakeSender(fail_times=1, error=error), from_start=True, log=messages.append)
    collector.tick()
    assert collector.queue == []
    assert "rejected" in messages[0]


def test_server_error_is_retried(tmp_path):
    log = tmp_path / "auth.log"
    write(log, FAILED)
    error = urllib.error.HTTPError("http://x", 503, "Unavailable", None, None)
    collector = Collector([log], FakeSender(fail_times=1, error=error), from_start=True, log=lambda m: None)
    collector.tick()
    assert len(collector.queue) == 1
    assert collector.tick() == 1


# TC-LOG-22: saved positions survive a restart
def test_state_resumes_after_restart(tmp_path):
    log = tmp_path / "auth.log"
    state_file = tmp_path / "state.json"
    write(log, FAILED * 2)
    first = Collector([log], FakeSender(), from_start=True)
    first.tick()
    save_state(state_file, first.positions())

    write(log, ACCEPTED)  # written while the collector was stopped
    sender = FakeSender()
    second = Collector([log], sender, state=load_state(state_file))
    assert second.tick() == 1
    assert sender.batches[0][0]["event_type"] == "authentication_success"


def test_load_state_with_missing_or_broken_file(tmp_path):
    assert load_state(tmp_path / "none.json") == {}
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    assert load_state(broken) == {}


def test_dry_run_once_prints_events(tmp_path):
    log = tmp_path / "auth.log"
    write(log, FAILED)
    assert main([str(log), "--from-start", "--once", "--dry-run"]) == 0


# TC-LOG-23: large files are sent in batches
def test_send_events_uses_batches():
    calls = []

    def fake_post(batch, url):
        calls.append(len(batch))
        return 201, {"indexed": len(batch)}

    status, result = send_events([{"n": i} for i in range(1201)], batch_size=500, post=fake_post)
    assert calls == [500, 500, 201]
    assert result == {"indexed": 1201}
    assert status == 201


def test_send_events_with_no_events_sends_nothing():
    calls = []
    assert send_events([], post=lambda b, u: calls.append(b)) == (201, {"indexed": 0})
    assert calls == []
