#!/usr/bin/env python3
"""Independent integer/Rice oracle. Audits transport, not proof validity.

Only the Python standard library and the preserved v1 format/ledger oracle are
used. Native cryptographic verification is performed separately by the Rust CLI.
"""
import argparse
import hashlib
import json
from pathlib import Path
import statistics

import compact_packet_audit as v1

MIN_PROOF = 13766
MAX_PROOF = 51579
NATIVE_HEAD = 11424
RICE_PREFIX = 11238
SIGNED = v1.PARTS[3:]
require = v1.require


def digits(raw, width):
    require(len(raw) == 32 * width, 'polynomial length')
    number = int.from_bytes(raw, 'little')
    return [(number >> (width * i)) & ((1 << width) - 1) for i in range(256)]


def encode_v2(native):
    require(len(native) == 53600, 'native proof length')
    head, position = bytearray(), 0
    for count, width, base, size in v1.PARTS[:2]:
        for _ in range(count):
            head.extend(v1.polynomial(native[position:position + 32 * width], width, base, size))
            position += 32 * width
    head.extend(native[position:position + 32])
    position += 32
    require(position == NATIVE_HEAD and len(head) == 11232, 'head geometry')
    params, groups, bit_count = [], [], 0
    for count, width, base, _ in SIGNED:
        values = []
        for _ in range(count):
            for digit in digits(native[position:position + 32 * width], width):
                require(digit < base, 'native coefficient domain')
                signed = digit - (base - 1) // 2
                values.append(2 * signed if signed >= 0 else -2 * signed - 1)
            position += 32 * width
        costs = [sum((u >> k) + 1 + k for u in values) for k in range(width)]
        k = min(range(width), key=lambda k: (costs[k], k))
        params.append(k)
        groups.append(values)
        bit_count += costs[k]
    require(position == len(native), 'proof geometry')
    if RICE_PREFIX + (bit_count + 7) // 8 >= MAX_PROOF:
        return b'\0' + v1.proof_encoding(native)
    number, position = 0, 0
    for k, values in zip(params, groups):
        for u in values:
            q, remainder = divmod(u, 1 << k)
            number |= ((1 << q) - 1) << position
            position += q + 1
            number |= remainder << position
            position += k
    require(position == bit_count, 'bit count')
    return b'\1' + bytes(params) + head + number.to_bytes((bit_count + 7) // 8, 'little')


def decode_radix(block, width, base):
    number = int.from_bytes(block, 'little')
    packed = 0
    for i in range(256):
        number, digit = divmod(number, base)
        packed |= digit << (width * i)
    require(number == 0, 'noncanonical radix block')
    return packed.to_bytes(32 * width, 'little')


def decode_v2(encoded):
    require(MIN_PROOF <= len(encoded) <= MAX_PROOF, 'proof length bounds')
    native, position = bytearray(), 1
    if encoded[0] == 0:
        require(len(encoded) == MAX_PROOF, 'fallback length')
        for part in v1.PARTS:
            if part is None:
                native.extend(encoded[position:position + 32]); position += 32
                continue
            count, width, base, size = part
            for _ in range(count):
                native.extend(decode_radix(encoded[position:position + size], width, base))
                position += size
        require(position == len(encoded), 'fallback consumption')
    else:
        require(encoded[0] == 1 and len(encoded) < MAX_PROOF, 'Rice mode')
        params = encoded[1:6]
        require(all(k < part[1] for k, part in zip(params, SIGNED)), 'parameter domain')
        position = 6
        for count, width, base, size in v1.PARTS[:2]:
            for _ in range(count):
                native.extend(decode_radix(encoded[position:position + size], width, base))
                position += size
        native.extend(encoded[position:position + 32]); position += 32
        require(position == RICE_PREFIX, 'Rice prefix')
        payload = encoded[position:]
        number = int.from_bytes(payload, 'little')
        used = 0
        for k, (count, width, base, _) in zip(params, SIGNED):
            for _ in range(count):
                packed = 0
                for i in range(256):
                    q = 0
                    while used < 8 * len(payload) and (number >> used) & 1:
                        q += 1; used += 1
                        require(q <= (base - 1) >> k, 'unary bound')
                    require(used + 1 + k <= 8 * len(payload), 'truncated Rice value')
                    used += 1
                    u = (q << k) | ((number >> used) & ((1 << k) - 1))
                    used += k
                    require(u < base, 'Rice coefficient domain')
                    signed = u // 2 if u % 2 == 0 else -(u + 1) // 2
                    packed |= (signed + (base - 1) // 2) << (width * i)
                native.extend(packed.to_bytes(32 * width, 'little'))
        require((used + 7) // 8 == len(payload), 'trailing bytes')
        require(number >> used == 0, 'nonzero padding')
    native = bytes(native)
    require(encode_v2(native) == encoded, 'noncanonical parameter or mode selection')
    return native


def audit(directory):
    directory = Path(directory)
    report_path = directory / 'report.json'
    require(not report_path.is_symlink() and report_path.stat().st_size <= 262144, 'report storage')
    report = json.loads(report_path.read_text())
    require(report['schema'] == 'ringct-compact-encoding-measurement-v2', 'schema')
    require(report['artifact_digest'] == 'sha3-256', 'digest')
    require(report['gpu_used'] is False and report['production_acceptance_changed'] is False
            and report['recursive_workflow_speedup_measured'] is False, 'scope')
    require(report['proof_parser_bounds'] == {'min': MIN_PROOF, 'max': MAX_PROOF}, 'bounds')
    require(report['fixed_sizes_bytes'] == {'native_proof': 53600, 'v1_proof': 51578,
            'native_packet': 256532, 'v1_standalone': 225004, 'v1_referenced': 67696}, 'fixed census')
    require(len(report['cases']) == 16, '16 fresh cases required')
    checked, seen = [], set()
    for ordinal, case in enumerate(report['cases']):
        require(case['ordinal'] == ordinal and case['ring_index'] == ordinal % 10, 'case identity')
        require(all(case[name] is True for name in ['c_reference_verified', 'rust_verified',
                'exact_native_round_trips', 'proof_mutation_rejected', 'reference_mutation_rejected',
                'duplicate_serial_rejected']), 'verification report')
        require(all(type(x) is int and 0 <= x < 1 << 52 for x in case['input_amounts'] + case['output_amounts'])
                and len(case['input_amounts']) == len(case['output_amounts']) == 2
                and sum(case['input_amounts']) == sum(case['output_amounts']), 'amount profile')
        artifacts = {}
        limits = {'native': (256532, 256532), 'v1_proof': (51578, 51578),
                  'proof': (MIN_PROOF, MAX_PROOF), 'standalone': (173426 + MIN_PROOF, 173426 + MAX_PROOF),
                  'referenced': (16118 + MIN_PROOF, 16118 + MAX_PROOF)}
        for kind, (low, high) in limits.items():
            record = case['artifacts'][kind]
            name = f'case-{ordinal}-{kind}.bin'
            require(record['file'] == name and low <= record['bytes'] <= high, 'artifact identity/length')
            path = directory / name
            require(not path.is_symlink() and path.stat().st_size == record['bytes'], 'artifact storage')
            value = path.read_bytes()
            require(hashlib.sha3_256(value).hexdigest() == record['sha3_256'], 'artifact digest')
            artifacts[kind] = value
        native = artifacts['native']
        seen.add(hashlib.sha3_256(native).hexdigest())
        require(native[:12] == b'LPQMPK01\x01\0\x01\0' and native[12:44] == v1.PROFILE, 'native framing/profile')
        require(native[76:80] == (202848).to_bytes(4, 'little')
                and native[202928:202932] == (53600).to_bytes(4, 'little'), 'native lengths')
        statement, proof = native[80:202928], native[202932:]
        require(native[44:76].hex() == case['context_hex'] and statement[:32].hex() == case['setup_seed_hex'], 'context/setup')
        require(v1.proof_encoding(proof) == artifacts['v1_proof'], 'preserved v1 bytes')
        encoded = encode_v2(proof)
        require(encoded == artifacts['proof'] and decode_v2(encoded) == proof, 'independent proof round trip')
        require(case['proof_mode'] == encoded[0] and case['rice_parameters'] == (list(encoded[1:6]) if encoded[0] == 1 else None), 'mode/parameters')
        header = b'LPQMCP02' + native[8:76]
        require(header + (1).to_bytes(4, 'little') + v1.statement_encoding(statement) + encoded == artifacts['standalone'], 'standalone reproduction')
        accounts = [statement[i:i + 9216] for i in range(32, 32 + 184320, 9216)]
        domain = bytes.fromhex(case['ledger_domain_hex'])
        require(len(domain) == 32 and case['ledger_account_count'] == 20, 'ledger profile')
        root, checkpoint = v1.ledger(domain, statement[:32], accounts)
        require(root.hex() == case['ledger_root_hex'] and checkpoint.hex() == case['ledger_checkpoint_hex'], 'ledger commitments')
        suffix = v1.statement_encoding(statement, omit_ring=True)
        refs = (header + (2).to_bytes(4, 'little') + checkpoint + suffix[:32]
                + b''.join(i.to_bytes(8, 'little') for i in range(20)) + suffix[32:] + encoded)
        require(refs == artifacts['referenced'], 'referenced reproduction')
        checked.append({'ordinal': ordinal, 'native_sha3_256': hashlib.sha3_256(native).hexdigest(),
                        'proof_bytes': len(encoded), 'standalone_bytes': len(artifacts['standalone']),
                        'referenced_bytes': len(refs)})
    require(len(seen) == 16, 'distinct native cases')
    sizes = [case['proof_bytes'] for case in checked]
    return {'schema': 'ringct-compact-independent-audit-v2', 'passed': True,
            'scope': 'Independent encoding/decoding and ledger commitments; cryptographic verification is separate.',
            'report_sha256': hashlib.sha256(report_path.read_bytes()).hexdigest(),
            'proof_bytes': {'min': min(sizes), 'median': statistics.median(sizes), 'max': max(sizes)},
            'cases': checked}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory), indent=2) + '\n'
    if args.output:
        with args.output.open('x') as f:
            f.write(result)
    print(result)
