#!/usr/bin/env python3
"""Real verifier ABI and native rejection checks, after building the host bridge.

A retained statement-fixture root must pass the C verifier, but must reject when
paired with newly generated complete bodies. Positive durable complete-body
application still requires a newly proved matching recursive root.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import time

from block_v2_host_store import Candidate, IssuancePolicy, NativeVerifier, RejectedBlock, Store


def pin(path):
    return {'path': str(path.resolve()), 'bytes': path.stat().st_size,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--cpu-probe', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--reference-trial', type=Path, required=True)
    parser.add_argument('--issuance-grant', action='append', default=[], metavar='INDEX:AMOUNT',
                        help='independent host authorization at fixture height 10; never inferred from the body')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    fixture = args.fixture.resolve(strict=True)
    reference = args.reference_trial.resolve(strict=True) / '001-typed/root-only'
    library, cpu = args.library.resolve(strict=True), args.cpu_probe.resolve(strict=True)
    result = {'schema_version': 1, 'status': 'running', 'checks': [], 'library': pin(library),
              'cpu_probe': pin(cpu), 'durable_complete_body_application_qualified': False,
              'delivered_transactions_measured': False, 'production_ready': False}
    started = time.monotonic()

    def check(name, condition):
        if not condition:
            raise ValueError(name)
        result['checks'].append(name)

    try:
        command = [str(cpu), 'export-host-expected', str(reference / 'expected.json'), str(out / 'reference-expected.bin')]
        log = out / 'reference-export.log'
        with log.open('x') as handle:
            exported = subprocess.run(command, stdout=handle, stderr=subprocess.STDOUT)
        result['expected_export'] = {'command': command, 'exit_code': exported.returncode, 'log': pin(log)}
        check('independent reference expectation export', exported.returncode == 0)
        expected = (out / 'reference-expected.bin').read_bytes()
        registry = (fixture / 'host-registry.bin').read_bytes()
        proof = (reference / 'node.6.0').read_bytes()
        native_expected = (fixture / 'native-expected.bin').read_bytes()
        check('registry and chain context remain independently matched', expected[8:72] == native_expected[8:72])
        native = ctypes.CDLL(str(library))
        root = native.lattica_v2_research_root_verify_v1
        root.argtypes = [ctypes.c_void_p, ctypes.c_size_t] * 3
        root.restype = ctypes.c_int32

        def verify(p=proof, e=expected, r=registry):
            buffers = [ctypes.create_string_buffer(value) for value in (p, e, r)]
            return root(buffers[0], len(p), buffers[1], len(e), buffers[2], len(r))

        check('real CPU verifier accepts the retained audited root', verify() == 0)
        for name, offset in (('profile', 8), ('chain', 40), ('root', 72)):
            changed = bytearray(expected)
            changed[offset] ^= 1
            check(f'root verifier rejects altered {name}', verify(e=bytes(changed)) != 0)
        for count in (0, 3, 65):
            changed = expected[:104] + struct.pack('<Q', count)
            check(f'root verifier rejects count {count}', verify(e=changed) != 0)
        check('root verifier rejects truncated expectation', verify(e=expected[:-1]) != 0)
        check('root verifier rejects trailing expectation', verify(e=expected + b'\0') != 0)
        check('root verifier rejects malformed registry', verify(r=b'X' + registry[1:]) != 0)
        check('root verifier rejects truncated proof', verify(p=proof[:-1]) != 0)
        check('root verifier rejects trailing proof', verify(p=proof + b'\0') != 0)
        check('root verifier rejects empty proof', verify(p=b'') != 0)

        body = (fixture / 'complete-body.bin').read_bytes()
        grant_pairs = [tuple(map(int, item.split(':'))) for item in args.issuance_grant]
        if any(len(pair) != 2 for pair in grant_pairs) or len({pair[0] for pair in grant_pairs}) != len(grant_pairs):
            raise ValueError('invalid or duplicated independent issuance grant')
        grants = dict(grant_pairs)
        result['independent_host_grants'] = {'height': 10, 'grants': grants}
        verifier = NativeVerifier(library, registry, native_expected[8:40], native_expected[40:72],
                                  (fixture / 'genesis.bin').read_bytes(), IssuancePolicy({10: grants}))
        states = verifier.replay([])
        check('native genesis replays with supply and note state',
              len(states) == 1 and states[0]['height'] == 9 and states[0]['outputs'] == 128
              and states[0]['nullifiers'] == 0 and states[0]['supply']['issued'] == '64000')
        store = Store.create(out / 'native-empty-store', verifier)
        before = store.read()
        rejected = False
        try:
            store.commit(Candidate(10, body, proof), expected_head=before.token)
        except RejectedBlock:
            rejected = True
        check('valid root cannot authorize different complete ciphertext-bound bodies', rejected)
        check('native rejection preserves durable head and all state', store.read() == before)
        check('native rejection creates no published transaction records',
              not list((out / 'native-empty-store/records').glob('*.json')))
        check('reopened native genesis state matches', Store(out / 'native-empty-store', verifier).read() == before)
        result['reference_root_cpu_verified'] = True
        result['native_genesis_and_rejection_checks_passed'] = True
        result['scope'] = 'Real CPU root ABI acceptance and mutations; native genesis, complete-body mismatch '
        result['scope'] += 'rejection and durable-head preservation. No matching complete-body recursive root was applied.'
        result['sources'] = [pin(reference / 'node.6.0'), pin(reference / 'expected.json'),
                             pin(out / 'reference-expected.bin'), pin(fixture / 'complete-body.bin'),
                             pin(fixture / 'native-expected.bin'), pin(fixture / 'host-registry.bin'),
                             pin(fixture / 'genesis.bin')]
        result['status'] = 'passed'
    except Exception as error:
        result['status'] = 'failed'
        result['failure'] = f'{type(error).__name__}: {error}'
    result['elapsed_seconds'] = time.monotonic() - started
    result['checks_passed'] = len(result['checks'])
    (out / 'summary.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': result['status'], 'checks_passed': result['checks_passed'],
                      'failure': result.get('failure'), 'summary': str(out / 'summary.json')}))
    return int(result['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
