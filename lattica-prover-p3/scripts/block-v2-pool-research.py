#!/usr/bin/env python3
"""Generate isolated research proposals or evaluate five recorded matched pairs."""
import argparse
import json
from pathlib import Path
from block_v2_pool_qualification import compare, research_profile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    profile = sub.add_parser('profile')
    profile.add_argument('--capacity', type=int, required=True)
    profile.add_argument('--cycle-seconds', type=int, required=True)
    profile.add_argument('--issuance-inputs', type=int, required=True)
    pairs = sub.add_parser('compare')
    pairs.add_argument('manifest', type=Path)
    args = parser.parse_args()
    if args.action == 'profile':
        result = research_profile(args.capacity, args.cycle_seconds, args.issuance_inputs)
    else:
        manifest = json.loads(args.manifest.read_text())
        rows = []
        for row in manifest['pairs']:
            rows.append({**row, **{name: json.loads((args.manifest.parent / row[name]).read_text())
                                  for name in ('control', 'candidate')}})
        result = compare(rows)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
