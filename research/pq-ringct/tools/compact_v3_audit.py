#!/usr/bin/env python3
"""Independent integer/rANS transport audit; native proof verification is separate."""
import argparse
import bisect
import hashlib
import json
import math
from pathlib import Path
import statistics

import compact_v2_audit as v2

v1 = v2.v1
require = v2.require
MIN_PROOF, MAX_PROOF = v2.MIN_PROOF, v2.MAX_PROOF
HEAD_BYTES, LOW_BYTES = 11204, 24640
ANS_START = 1 + HEAD_BYTES + LOW_BYTES
LOWER = 1 << 23
TOTAL = 1 << 16
MODELS = json.loads(Path(__file__).with_name('compact_v3_models.json').read_text())
GROUPS = MODELS['groups']


def check_models():
    require(MODELS['schema'] == 'ringct-compact-v3-models-v1' and MODELS['scale_bits'] == 16
            and MODELS['lower_bound'] == LOWER, 'model profile')
    require(len(GROUPS) == 5, 'model groups')
    for model, part, k, scale in zip(GROUPS, v1.PARTS[3:], [0, 10, 4, 10, 17], [None, 7525, 111, 7525, 1219127]):
        count, width, base, _ = part
        require((model['count'], model['width'], model['base'], model['low_bits'], model['sampler_scale'])
                == (count, width, base, k, scale), 'model geometry')
        cdf = model['cdf']
        require(cdf[0] == 0 and cdf[-1] == TOTAL and all(a < b for a, b in zip(cdf, cdf[1:])), 'model CDF')
        require(len(cdf) == ((base + (1 << k) - 1) >> k) + 1, 'alphabet')
        if scale is None:
            frequencies = [54272, 5632, 5632]
        else:
            sigma = scale / math.sqrt(2 * math.log(2))
            def normal(u):
                return (math.erf((u / 2 - 0.5) / (sigma * math.sqrt(2)))
                        + math.erf((u / 2 + 0.5) / (sigma * math.sqrt(2)))) / 2
            n = len(cdf) - 1
            probabilities = [max(0., normal(min(base, (q + 1) << k)) - normal(q << k)) for q in range(n)]
            values = [p / sum(probabilities) * (TOTAL - n) for p in probabilities]
            frequencies = [1 + int(v) for v in values]
            for i in sorted(range(n), key=lambda i: (-(values[i] - int(values[i])), i))[:TOTAL - sum(frequencies)]:
                frequencies[i] += 1
        require([b - a for a, b in zip(cdf, cdf[1:])] == frequencies, 'reproduced model frequencies')


def encode_v3(native):
    previous = v2.encode_v2(native)  # Independently checks every native domain.
    c = v2.digits(native[:896], 28)
    if any(c[i] != 0 for i in [0, 1, 2, 3, 128, 129, 130, 131]):
        return previous
    number = 0
    for digit in reversed(c[4:128] + c[132:]):
        number = number * v1.Q + digit
    # The rest of the native head has the unchanged v1 radix representation.
    head = number.to_bytes(847, 'little') + v1.proof_encoding(native)[875:11232]
    require(len(head) == HEAD_BYTES, 'sparse head')
    low, symbol_groups, position = bytearray(), [], 11424
    for group in GROUPS:
        width, base, k = group['width'], group['base'], group['low_bits']
        symbols = []
        for _ in range(group['count']):
            packed = 0
            for i, digit in enumerate(v2.digits(native[position:position + 32 * width], width)):
                s = digit - (base - 1) // 2
                u = 2 * s if s >= 0 else -2 * s - 1
                symbols.append(u >> k)
                packed |= (u & ((1 << k) - 1)) << (k * i)
            low.extend(packed.to_bytes(32 * k, 'little'))
            position += 32 * width
        symbol_groups.append(symbols)
    require(position == len(native) and len(low) == LOW_BYTES, 'native layout')
    state, emitted = LOWER, bytearray()
    # The oracle calculates the complete candidate before selecting its format.
    # Production stops early at its smaller, planner-issued output capacity.
    for group, symbols in reversed(list(zip(GROUPS, symbol_groups))):
        cdf = group['cdf']
        for q in reversed(symbols):
            frequency = cdf[q + 1] - cdf[q]
            while state >= 32768 * frequency:
                emitted.append(state % 256); state //= 256
            quotient, remainder = divmod(state, frequency)
            state = quotient * TOTAL + remainder + cdf[q]
    candidate = b'\2' + head + low + state.to_bytes(4, 'little') + bytes(reversed(emitted))
    return bytes(candidate) if len(candidate) < len(previous) else previous


def decode_v3(encoded):
    require(MIN_PROOF <= len(encoded) <= MAX_PROOF, 'proof bounds')
    if encoded[0] in [0, 1]:
        native = v2.decode_v2(encoded)
    else:
        require(encoded[0] == 2 and len(encoded) >= ANS_START + 4, 'entropy framing')
        number = int.from_bytes(encoded[1:848], 'little')
        digits = []
        for _ in range(248):
            number, digit = divmod(number, v1.Q); digits.append(digit)
        require(number == 0, 'sparse head integer domain')
        c = [0] * 4 + digits[:124] + [0] * 4 + digits[124:]
        native = bytearray(sum(d << (28 * i) for i, d in enumerate(c)).to_bytes(896, 'little'))
        position = 848
        for count, width, base, size in [(6, 28, v1.Q, 875), (5, 32, 3489661057, 1015)]:
            for _ in range(count):
                native.extend(v2.decode_radix(encoded[position:position + size], width, base))
                position += size
        native.extend(encoded[position:position + 32]); position += 32
        require(position == 1 + HEAD_BYTES, 'head consumption')
        state = int.from_bytes(encoded[ANS_START:ANS_START + 4], 'little')
        require(LOWER <= state < LOWER * 256, 'initial state')
        consumed = ANS_START + 4
        for group in GROUPS:
            width, base, k, cdf = group['width'], group['base'], group['low_bits'], group['cdf']
            for _ in range(group['count']):
                low = int.from_bytes(encoded[position:position + 32 * k], 'little'); position += 32 * k
                polynomial = 0
                for i in range(256):
                    high, slot = divmod(state, TOTAL)
                    q = bisect.bisect_right(cdf, slot) - 1
                    state = (cdf[q + 1] - cdf[q]) * high + slot - cdf[q]
                    while state < LOWER:
                        require(consumed < len(encoded), 'truncated rANS stream')
                        state = state * 256 + encoded[consumed]; consumed += 1
                    u = (q << k) | ((low >> (i * k)) & ((1 << k) - 1))
                    require(u < base, 'coefficient bound')
                    signed = u // 2 if u % 2 == 0 else -(u + 1) // 2
                    polynomial |= (signed + (base - 1) // 2) << (i * width)
                native.extend(polynomial.to_bytes(32 * width, 'little'))
        require(position == ANS_START and consumed == len(encoded) and state == LOWER, 'terminal stream state')
        native = bytes(native)
    require(encode_v3(native) == encoded, 'canonical encoding selection')
    return native


def audit(directory):
    directory = Path(directory)
    check_models()
    report_path = directory / 'report.json'
    require(not report_path.is_symlink() and report_path.stat().st_size <= 524288, 'report storage')
    report = json.loads(report_path.read_text())
    require(report['schema'] == 'ringct-compact-encoding-measurement-v3', 'schema')
    require(report['artifact_digest'] == 'sha3-256', 'digest')
    require(report['gpu_used'] is False and report['production_acceptance_changed'] is False
            and report['recursive_workflow_speedup_measured'] is False, 'scope')
    require(report['proof_parser_bounds'] == {'min': MIN_PROOF, 'max': MAX_PROOF}, 'bounds')
    require(report['fixed_sizes_bytes'] == {'native_proof': 53600, 'v1_proof': 51578,
            'native_packet': 256532, 'v1_standalone': 225004, 'v1_referenced': 67696}, 'fixed census')
    require(len(report['cases']) == 32, '32 fresh cases required')
    checked, seen = [], set()
    for ordinal, case in enumerate(report['cases']):
        require(case['ordinal'] == ordinal and case['ring_index'] == ordinal % 10, 'case identity')
        require(all(case[name] is True for name in ['c_reference_verified', 'rust_verified',
                'exact_native_round_trips', 'proof_mutation_rejected', 'reference_mutation_rejected',
                'duplicate_serial_rejected', 'no_larger_than_v2']), 'verification report')
        require(all(type(x) is int and 0 <= x < 1 << 52 for x in case['input_amounts'] + case['output_amounts'])
                and len(case['input_amounts']) == len(case['output_amounts']) == 2
                and sum(case['input_amounts']) == sum(case['output_amounts']), 'amount profile')
        artifacts = {}
        limits = {'native': (256532, 256532), 'v1_proof': (51578, 51578),
                  'v2_proof': (MIN_PROOF, MAX_PROOF), 'proof': (MIN_PROOF, MAX_PROOF), 'standalone': (173426 + MIN_PROOF, 173426 + MAX_PROOF),
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
        previous = v2.encode_v2(proof)
        require(previous == artifacts['v2_proof'], 'preserved v2 encoding')
        encoded = encode_v3(proof)
        require(len(encoded) <= len(previous), 'v3 exceeds v2 size')
        require(encoded == artifacts['proof'] and decode_v3(encoded) == proof, 'independent proof round trip')
        require(case['proof_mode'] == encoded[0] and case['v2_proof_mode'] == previous[0] and case['v2_rice_parameters'] == (list(previous[1:6]) if previous[0] == 1 else None), 'mode/parameters')
        header = b'LPQMCP03' + native[8:76]
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
                        'proof_bytes': len(encoded), 'v2_proof_bytes': len(previous), 'saved_bytes':len(previous)-len(encoded), 'standalone_bytes': len(artifacts['standalone']),
                        'referenced_bytes': len(refs)})
    require(len(seen) == 32, 'distinct native cases')
    sizes = [case['proof_bytes'] for case in checked]
    return {'schema': 'ringct-compact-independent-audit-v3', 'passed': True,
            'scope': 'Independent encoding/decoding and ledger commitments; cryptographic verification is separate.',
            'report_sha256': hashlib.sha256(report_path.read_bytes()).hexdigest(),
            'proof_bytes': {'min': min(sizes), 'median': statistics.median(sizes), 'max': max(sizes)},
            'saved_bytes': {'min': min(c['saved_bytes'] for c in checked), 'median':statistics.median(c['saved_bytes'] for c in checked), 'max':max(c['saved_bytes'] for c in checked)},
            'models_sha256':hashlib.sha256(Path(__file__).with_name('compact_v3_models.json').read_bytes()).hexdigest(),
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
