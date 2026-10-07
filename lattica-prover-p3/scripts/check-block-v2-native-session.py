#!/usr/bin/env python3
"""Compare the incremental native ABI with full verification of retained roots.

Uses read-only inputs from qualify-block-v2-native-delivery.py. This is a
correctness check, not fresh proving or sustained throughput qualification.
"""
import argparse
import json
from pathlib import Path

import block_v2_host_store as H
from block_v2_native_session import NativeSessionVerifier


def check(library, evidence):
    config = json.loads((evidence / 'inputs.json').read_text())
    arguments = (library, Path(config['registry']).read_bytes(),
                 bytes.fromhex(config['profile_id']), bytes.fromhex(config['chain_id']),
                 Path(config['genesis']).read_bytes(),
                 H.IssuancePolicy({int(h): {int(i): v for i, v in row.items()}
                                  for h, row in config['issuance_grants'].items()}))
    replay, session = H.NativeVerifier(*arguments), NativeSessionVerifier(*arguments)
    candidates = []
    checks = []
    try:
        for index, name in enumerate(('first', 'second', 'third')):
            fixture = evidence / (name + '-fixture')
            proof = evidence / (name + '-root/001-typed/root-only/node.6.0')
            candidate = H.Candidate(10 + index, (fixture / 'complete-body.bin').read_bytes(), proof.read_bytes())
            assert replay.preflight(candidates, candidate.body, candidate.height) == session.preflight(candidates, candidate.body, candidate.height)
            candidates.append(candidate)
            assert replay.replay(candidates) == session.replay(candidates)
            assert session.replay(candidates) == replay.replay(candidates)
            checks.append(f'height {candidate.height}: preflight, apply, cached replay')
        assert replay.replay(candidates[:1]) == session.replay(candidates[:1])
        alternative = H.Candidate(11, (evidence / 'alternate-second-fixture/complete-body.bin').read_bytes(),
                                  (evidence / 'alternate-second-root/001-typed/root-only/node.6.0').read_bytes())
        assert replay.replay([candidates[0], alternative]) == session.replay([candidates[0], alternative])
        assert replay.replay(candidates) == session.replay(candidates)
        checks.append('rollback, alternate branch, and restored chain')
        bad = H.Candidate(12, candidates[-1].body, candidates[-1].proof[:-1])
        for verifier in (replay, session):
            try:
                verifier.replay(candidates[:2] + [bad])
            except H.RejectedBlock:
                pass
            else:
                raise AssertionError('altered proof accepted')
        assert replay.replay(candidates) == session.replay(candidates)
        checks.append('altered proof rejected; valid state rebuilt')
        session.close()
        assert replay.replay(candidates) == session.replay(candidates)
        checks.append('explicit session restart')
    finally:
        session.close()
    return {'schema_version': 1, 'status': 'passed', 'checks': checks,
            'fresh_proofs': 0, 'sustained_throughput_qualified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(check(args.library.resolve(strict=True), args.evidence.resolve(strict=True)), indent=2))
