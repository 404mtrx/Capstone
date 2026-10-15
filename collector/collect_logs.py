
from pathlib import Path

# Location of our sample security logs
log_file = Path(__file__).parent / "sample_auth.log"

def collect_logs():
    logs = []

    with open(log_file, "r") as file:
        for line in file:
            if line.strip():
                logs.append(line.strip())

    return logs

if __name__ == "__main__":
    collected_logs = collect_logs()

    print("SentinelWatch Log Collector")
    print(f"Total logs collected: {len(collected_logs)}")

    for log in collected_logs:
        print(log)
