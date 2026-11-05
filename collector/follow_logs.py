"""SentinelWatch live collector (follow mode).

Watches log files like `tail -f`, normalizes each new line, and sends the
events to the SentinelWatch API every few seconds.

Usage:
    python3 collector/follow_logs.py /var/log/auth.log /var/log/ufw.log
    python3 collector/follow_logs.py collector/sample_auth.log --from-start --once --dry-run

Options:
    --interval N    seconds between checks (default 5)
    --from-start    read files from the beginning instead of only new lines
    --once          read and send once, then exit
    --dry-run       print events instead of sending them
    --state FILE    where read positions are saved (default .collector_state.json)

Reliability:
  * A file that is rotated (replaced) or truncated is read again from the start.
  * A line that is still being written (no newline yet) waits for the next check.
  * If the API is down, events stay queued and are retried on the next check.
  * Read positions are saved only after a successful send, so a restart never
    loses events. A restart may resend a few, which is safe: the API stores
    each event once.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
from pathlib import Path

from normalize_logs import normalize_log
from send_events import DEFAULT_URL, send_events

MAX_QUEUED = 50_000  # cap on unsent events kept in memory while the API is down


class FileFollower:
    """Returns the complete new lines added to one file since the last call."""

    def __init__(self, path, offset=0, inode=None):
        self.path = str(path)
        self.offset = offset
        self.inode = inode
        self._partial = b""

    def read_new_lines(self):
        try:
            info = os.stat(self.path)
        except FileNotFoundError:
            return []  # file may be mid-rotation; try again next time

        if self.inode is not None and info.st_ino != self.inode:
            self.offset, self._partial = 0, b""  # rotated: new file at this path
        elif info.st_size < self.offset:
            self.offset, self._partial = 0, b""  # truncated
        self.inode = info.st_ino

        with open(self.path, "rb") as file:
            file.seek(self.offset)
            data = file.read()
        self.offset += len(data)

        data = self._partial + data
        lines = data.split(b"\n")
        self._partial = lines.pop()  # incomplete last line (empty if data ended in \n)
        return [line.decode("utf-8", "replace").strip() for line in lines if line.strip()]

    def position(self):
        """Offset of the last complete line read (the partial line is re-read later)."""
        return {"offset": self.offset - len(self._partial), "inode": self.inode}


class Collector:
    def __init__(self, paths, sender, from_start=False, state=None, log=print):
        self.sender = sender
        self.log = log
        self.queue = []
        self.followers = []
        state = state or {}
        for path in paths:
            saved = state.get(str(path))
            if saved:
                follower = FileFollower(path, saved["offset"], saved["inode"])
            else:
                follower = FileFollower(path)
                if not from_start and os.path.exists(path):
                    info = os.stat(path)  # only lines written from now on
                    follower.offset, follower.inode = info.st_size, info.st_ino
            self.followers.append(follower)

    def positions(self):
        return {f.path: f.position() for f in self.followers}

    def tick(self):
        """Read new lines, queue their events, try to send. Returns events sent."""
        for follower in self.followers:
            for line in follower.read_new_lines():
                event = normalize_log(line)
                if event is not None:
                    self.queue.append(event)

        if len(self.queue) > MAX_QUEUED:
            dropped = len(self.queue) - MAX_QUEUED
            self.queue = self.queue[dropped:]
            self.log(f"Warning: API unavailable too long, dropped {dropped} oldest events")

        if not self.queue:
            return 0
        try:
            self.sender(self.queue)
        except urllib.error.HTTPError as error:
            if 400 <= error.code < 500:
                # The API rejected the events (for example 422 invalid). Retrying the
                # same events would fail forever, so drop them and keep going.
                self.log(f"API rejected {len(self.queue)} events (HTTP {error.code}); dropped")
                self.queue = []
                return 0
            self.log(f"Send failed (HTTP {error.code}); {len(self.queue)} events queued for retry")
            return 0
        except (urllib.error.URLError, OSError) as error:
            reason = getattr(error, "reason", error)
            self.log(f"Send failed ({reason}); {len(self.queue)} events queued for retry")
            return 0

        sent = len(self.queue)
        self.queue = []
        return sent


def load_state(path):
    try:
        return json.loads(Path(path).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(path, positions):
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(json.dumps(positions, indent=2))
    tmp.replace(path)


def main(argv=None):
    parser = argparse.ArgumentParser(description="SentinelWatch live collector")
    parser.add_argument("files", nargs="+", help="log files to watch")
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--from-start", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--state", default=".collector_state.json")
    args = parser.parse_args(argv)

    if args.dry_run:
        def sender(events):
            for event in events:
                print(json.dumps(event))
    else:
        def sender(events):
            send_events(events, args.url)

    state = {} if args.dry_run else load_state(args.state)
    collector = Collector(args.files, sender, args.from_start, state)
    print(f"Watching {len(args.files)} file(s); sending to "
          f"{'stdout (dry run)' if args.dry_run else args.url}. Press Ctrl+C to stop.")

    try:
        while True:
            sent = collector.tick()
            if sent:
                print(f"Sent {sent} events")
            if not args.dry_run and not collector.queue:
                save_state(args.state, collector.positions())
            if args.once:
                return 0 if not collector.queue else 1
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
