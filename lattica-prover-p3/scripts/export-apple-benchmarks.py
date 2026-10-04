#!/usr/bin/env python3
"""Export verified Apple controller evidence and optionally update the offline HTML."""
import argparse
from pathlib import Path
from apple_benchmark_export import export_campaign, export_component
from benchmark_report.model import DEFAULT_ROOT
from benchmark_report.report import dataset_lock, ingest, render, check


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--result", type=Path, required=True)
    p.add_argument("--component-metadata", type=Path)
    p.add_argument("--portable", type=Path, required=True)
    p.add_argument("--report", type=Path)
    p.add_argument("--allow-verified-partial", action="store_true", help="export only fully audited trials from a stopped campaign; keep its failure and incomplete repetition status visible")
    args = p.parse_args()
    paths = (export_component(args.result, args.component_metadata, args.portable) if args.component_metadata
             else export_campaign(args.result, args.portable, allow_verified_partial=args.allow_verified_partial))
    if args.report:
        with dataset_lock(args.report):
            for path in paths: ingest(args.report, path, DEFAULT_ROOT)
            render(args.report)
        check(args.report)
    print(f"Exported {len(paths)} immutable portable run records to {args.portable}")


if __name__ == "__main__":
    main()
