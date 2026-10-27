import sys
from pathlib import Path

# Let tests import the collector modules (collect_logs, normalize_logs).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "collector"))
