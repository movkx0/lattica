#!/usr/bin/env python3
"""Preserve solving measurements and render an offline development report."""
import argparse
import json
from pathlib import Path
import sys

from benchmark_report.model import DEFAULT_ROOT
from benchmark_report.report import check, dataset_lock, import_history, ingest, render


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("import-history", "ingest", "render", "check"))
    p.add_argument("--input", type=Path)
    p.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    output = args.output or args.root / "docs/benchmarks"
    if args.command == "check":
        result = check(output)
    else:
        with dataset_lock(output):
            if args.command == "import-history":
                catalog = import_history(output, args.root)
                result = catalog["coverage"]
            elif args.command == "ingest":
                if not args.input:
                    p.error("ingest requires --input")
                result = ingest(output, args.input, args.root)["coverage"]
            else:
                result = {}
            result["html_bytes"] = render(output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print(f"benchmark report: {error}", file=sys.stderr)
        sys.exit(1)
