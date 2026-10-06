#!/usr/bin/env python3
"""Persist research arrivals and seal an exact, independently prepared native batch."""

import argparse
import json
import os
from pathlib import Path

import block_v2_host_store as H
import block_v2_native_arrivals as A
import block_v2_native_shared as N


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host-config', type=Path, required=True)
    parser.add_argument('--host-journal', type=Path, required=True)
    parser.add_argument('--store', type=Path, required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('init')
    create.add_argument('--max-arrivals', type=int, required=True)
    create.add_argument('--max-payload-bytes', type=int, required=True)
    create.add_argument('--max-database-bytes', type=int, required=True)
    create.add_argument('--max-events', type=int, required=True)
    submit = commands.add_parser('submit')
    submit.add_argument('--request-id', required=True)
    submit.add_argument('--expected-head', required=True)
    submit.add_argument('--complete-body', type=Path, required=True)
    submit.add_argument('--wallet-proof', type=Path, required=True)
    seal = commands.add_parser('seal')
    seal.add_argument('--fixture', type=Path, required=True)
    seal.add_argument('--request-id', action='append', required=True)
    prepare = commands.add_parser('prepare')
    prepare.add_argument('--registry', type=Path, required=True)
    prepare.add_argument('--cpu-probe', type=Path, required=True)
    prepare.add_argument('--output', type=Path, required=True)
    prepare.add_argument('--request-id', action='append')
    prepare.add_argument('--limit', type=int, default=64)
    prepare.add_argument('--scan-limit', type=int, default=256,
                         help='maximum unclaimed arrivals to screen, including prior heads (up to 4096)')
    prepare.add_argument('--seal', action='store_true')
    prepare.add_argument('--prefix', action='store_true', help='prepare an unsealed prefix for stable subtree proving')
    cancel = commands.add_parser('cancel')
    cancel.add_argument('--selection-id', required=True)
    cancel.add_argument('--reason', choices=['stale_head', 'proving_failed', 'operator_cancelled'], required=True)
    commands.add_parser('inspect')
    args = parser.parse_args()
    if args.command == 'prepare' and args.prefix and args.seal:
        parser.error('--prefix cannot be combined with --seal')
    os.environ.setdefault('RAYON_NUM_THREADS', '1')
    host = N.open_host(args.host_config, args.host_journal)
    if args.command == 'init':
        limits = A.Limits(args.max_arrivals, args.max_payload_bytes, args.max_database_bytes, args.max_events)
        store = A.Store.create(args.store, host, limits)
        result = store.snapshot()
    else:
        store = A.Store(args.store, host)
        if args.command == 'submit':
            result = store.submit(args.request_id, expected_head=args.expected_head,
                body=H.Store._read_file(args.complete_body, H.MAX_BODY_BYTES),
                wallet=H.Store._read_file(args.wallet_proof, H.MAX_PROOF_BYTES))
        elif args.command == 'prepare':
            import block_v2_pending_candidate as B
            candidate = B.prepare(store, args.host_config, args.registry, args.cpu_probe, args.output,
                request_ids=args.request_id, limit=args.limit, scan_limit=args.scan_limit, prefix=args.prefix)
            if args.seal:
                result = store.seal(candidate, N.read(candidate.manifest_path)['request_ids'])
            else:
                result = {'status': 'prepared', 'manifest': candidate.manifest_pin,
                          'native_host_binding': candidate.binding}
        elif args.command == 'seal':
            candidate = N.Candidate(args.host_config, args.host_journal, args.fixture, len(args.request_id))
            result = store.seal(candidate, args.request_id)
        elif args.command == 'cancel':
            result = store.cancel(args.selection_id, args.reason)
        else:
            result = store.snapshot()
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))


if __name__ == '__main__':
    main()
