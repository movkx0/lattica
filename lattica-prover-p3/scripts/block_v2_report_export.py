"""Best-effort reporting after a controller has stopped all measured work."""
import os
from pathlib import Path
import subprocess
import sys


DEFER_ENV = "LATTICA_BENCHMARK_REPORT_DEFER"


def export_after_run(evidence):
    if os.environ.get(DEFER_ENV) == "1" or not Path(evidence).exists():
        return
    reporter = Path(__file__).with_name("block-v2-benchmark-report.py")
    try:
        result = subprocess.run(
            [sys.executable, str(reporter), "ingest", "--input", str(Path(evidence).resolve())],
            check=False,
        )
        if result.returncode:
            print("Benchmark report export failed; raw evidence is retained. "
                  f"Retry: {sys.executable} {reporter} ingest --input {evidence}", file=sys.stderr)
    except OSError as error:
        print(f"Benchmark report export unavailable: {error}; raw evidence is retained.", file=sys.stderr)
