import sys
from pathlib import Path

# Location of our sample security logs
COLLECTOR_DIR = Path(__file__).parent
DEFAULT_LOG_FILE = COLLECTOR_DIR / "sample_auth.log"


def collect_logs(paths=None):
    """Return every non-empty line from the given log files, in order.

    With no paths, reads the Linux SSH sample (sample_auth.log).
    """
    logs = []

    for path in paths or [DEFAULT_LOG_FILE]:
        with open(path, "r") as file:
            for line in file:
                if line.strip():
                    logs.append(line.strip())

    return logs


if __name__ == "__main__":
    # Usage: python collector/collect_logs.py [log_file ...]
    collected_logs = collect_logs(sys.argv[1:])

    print("SentinelWatch Log Collector")
    print(f"Total logs collected: {len(collected_logs)}")

    for log in collected_logs:
        print(log)
