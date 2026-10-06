#!/usr/bin/env python3
"""Check Rust/Zig native mixed roots. This does not qualify recursive proofs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def save(path, value):
    with path.open('x', encoding='utf-8') as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())


def invoke(directory, name, argv, env, success=True):
    started = time.monotonic()
    result = subprocess.run([str(v) for v in argv], env=env, text=True,
                            capture_output=True, timeout=120, check=False)
    record = {'argv': [str(v) for v in argv], 'exit_code': result.returncode,
              'seconds': time.monotonic() - started,
              'stdout': result.stdout, 'stderr': result.stderr}
    save(directory / f'{name}.json', record)
    if (result.returncode == 0) != success:
        raise ValueError(f'{name}: unexpected exit status {result.returncode}')
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--zig', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    rust, zig = args.rust.resolve(strict=True), args.zig.resolve(strict=True)
    directory = args.evidence.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    contract_path = Path(__file__).with_name('block-v2-throughput-contract.json').resolve()
    pins = {str(p): digest(p) for p in [rust, zig, Path(__file__).resolve(), contract_path]}
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(('LATTICA_V2_GPU_', 'LATTICA_V2_QUOTIENT_'))}
    env['RAYON_NUM_THREADS'] = '2'
    env['LATTICA_PROFILE'] = '0'
    env['LATTICA_PROFILE_TIMELINE'] = '0'
    save(directory / 'input.json', {'schema_version': 1, 'pins': pins,
                                  'scope': 'native_commitments_only'})
    invoke(directory, 'fixture-statements',
           [rust, 'fixture-statements', directory / 'body.json'], env)
    body = json.loads((directory / 'body.json').read_text())
    if body['schema_version'] != 1 or len(body['transactions']) != 64:
        raise ValueError('unexpected public fixture')
    profile = bytes([0x33] * 32)
    chain = bytes(body['chain'])
    encoded = []
    for tx in body['transactions']:
        kind = {'joinsplit': 1, 'htlc_redeem': 2, 'htlc_refund': 2, 'issuance': 3}[tx['kind']]
        fields = tx['statement']
        if len(fields) != (31 if kind == 2 else 26) or any(
                type(v) is not int or not 0 <= v < 0xffff_ffff_0000_0001 for v in fields):
            raise ValueError('noncanonical public fixture')
        encoded.append(f'{kind}:' + b''.join(v.to_bytes(8, 'little') for v in fields).hex())
    contract = json.loads(contract_path.read_text())
    results = []
    for count in contract['required_counts']:
        name = f'count-{count:02d}'
        output = invoke(directory, f'{name}-zig',
                        [zig, 'root-mixed', profile.hex(), chain.hex(), *encoded[:count]], env)
        fields = dict(word.split('=', 1) for word in output.split() if '=' in word)
        if fields.get('profile') != profile.hex() or fields.get('chain') != chain.hex() \
                or fields.get('level') != '6' or fields.get('count') != str(count) \
                or fields.get('proof_verified') != 'false':
            raise ValueError('unexpected native Zig statement')
        root = bytes.fromhex(fields['root'])
        if len(root) != 32:
            raise ValueError('unexpected native root size')
        expected = {
            'schema_version': 1, 'profile': list(profile), 'chain': list(chain),
            'root': [int.from_bytes(root[i:i + 8], 'little') for i in range(0, 32, 8)],
            'count': count, 'block_height': 10,
            'authorized_issuance': {str(i): 7 for i, tx in enumerate(body['transactions'][:count])
                                    if tx['kind'] == 'issuance'},
        }
        pinned = directory / f'{name}-expected.json'
        save(pinned, expected)
        planned = json.loads(invoke(directory, f'{name}-rust',
                                    [rust, 'plan', directory, pinned], env))
        if planned['count'] != count or planned['depth'] != 6 \
                or planned['phase_admitted'] or planned['gpu_qualified']:
            raise ValueError('unexpected Rust native plan')
        results.append({'count': count, 'root_hex': root.hex(),
                        'fresh_recursive_proofs_planned': planned['fresh_proofs'],
                        'rust_zig_match': True})
        if count == 4:
            for mutation in ['root', 'height', 'issuance']:
                wrong = json.loads(json.dumps(expected))
                if mutation == 'root':
                    wrong['root'][0] ^= 1
                elif mutation == 'height':
                    wrong['block_height'] += 1
                else:
                    wrong['authorized_issuance']['3'] += 1
                path = directory / f'reject-{mutation}-expected.json'
                save(path, wrong)
                invoke(directory, f'reject-{mutation}', [rust, 'plan', directory, path],
                       env, success=False)
    if any(digest(Path(path)) != pin for path, pin in pins.items()):
        raise ValueError('tool changed during native comparison')
    summary = {'schema_version': 1, 'status': 'NATIVE_INTEROP_PASSED',
               'proof_verified': False, 'mixed_root_qualified': False,
               'durable_host_applied': False, 'production_ready': False,
               'pins': pins, 'body_sha256': digest(directory / 'body.json'),
               'contract_sha256': digest(contract_path), 'counts': results,
               'expected_rejections': ['root', 'height', 'issuance']}
    save(directory / 'summary.json', summary)
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    main()
