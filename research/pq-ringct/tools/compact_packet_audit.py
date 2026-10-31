#!/usr/bin/env python3
"""Independent Python-integer oracle for the compact native packet artifacts.

This checks encoding bytes and ledger commitments, not lattice proof validity.
Native C/Rust verification is performed separately by the measurement executable.
"""
import hashlib
import json
from pathlib import Path
import sys

PROFILE = bytes.fromhex('4e3c0f074106a1f777f6e8ca9872958d1fc9744915f7d8688b6cbec50ea58d58')
Q = 167770241
SIZES = {'native': 256532, 'proof': 51578, 'standalone': 225004, 'referenced': 67696}
PARTS = [(7, 28, Q, 875), (5, 32, 3489661057, 1015), None,
         (1, 2, 3, 51), (49, 17, 76693, 520), (11, 11, 1131, 325),
         (10, 17, 76693, 520), (8, 24, 12425173, 755)]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def polynomial(raw, width, base, output_bytes):
    require(len(raw) == 256 * width // 8, 'polynomial source length')
    bits = int.from_bytes(raw, 'little')
    digits = [(bits >> (i * width)) & ((1 << width) - 1) for i in range(256)]
    require(all(value < base for value in digits), 'noncanonical original coefficient')
    # Independent arbitrary-precision conversion; Rust uses bounded u32 limbs.
    number = 0
    for digit in reversed(digits):
        number = number * base + digit
    return number.to_bytes(output_bytes, 'little')


def proof_encoding(proof):
    require(len(proof) == 53600, 'native proof length')
    position = 0
    out = bytearray()
    for part in PARTS:
        if part is None:
            out.extend(proof[position:position + 32])
            position += 32
            continue
        count, width, base, size = part
        for _ in range(count):
            end = position + 32 * width
            out.extend(polynomial(proof[position:end], width, base, size))
            position = end
    require(position == len(proof) and len(out) == 51578, 'proof layout census')
    return bytes(out)


def statement_encoding(statement, omit_ring=False):
    require(len(statement) == 202848, 'native statement length')
    start = 32 + 184320 if omit_ring else 32
    out = bytearray(statement[:32])
    for position in range(start, len(statement) - 64, 1024):
        out.extend(polynomial(statement[position:position + 1024], 32, Q, 875))
    out.extend(statement[-64:])
    return bytes(out)


def digest(tag, *parts):
    h = hashlib.sha3_256(tag + PROFILE)
    for part in parts:
        h.update(part)
    return h.digest()


def ledger(domain, seed, accounts):
    scope = digest(b'lattica/ringct/compact-ledger/scope/v1\0', domain, seed)
    level = [digest(b'lattica/ringct/compact-ledger/account/v1\0',
                    scope, i.to_bytes(8, 'little'), value) for i, value in enumerate(accounts)]
    power = 1 << (len(accounts) - 1).bit_length()
    level += [digest(b'lattica/ringct/compact-ledger/empty/v1\0', scope, i.to_bytes(8, 'little'))
              for i in range(len(accounts), power)]
    height = 1
    while len(level) != 1:
        level = [digest(b'lattica/ringct/compact-ledger/branch/v1\0', scope,
                        bytes([height]), level[i], level[i + 1]) for i in range(0, len(level), 2)]
        height += 1
    root = level[0]
    checkpoint = digest(b'lattica/ringct/compact-ledger/checkpoint/v1\0',
                        domain, seed, len(accounts).to_bytes(8, 'little'), root)
    return root, checkpoint


def audit(directory):
    directory = Path(directory)
    report_path = directory / 'report.json'
    require(report_path.stat().st_size <= 131072, 'oversized measurement report')
    report = json.loads(report_path.read_text())
    require(report['schema'] == 'ringct-compact-encoding-measurement-v1', 'measurement schema')
    require(report['artifact_digest'] == 'sha3-256', 'digest algorithm')
    require(report['gpu_used'] is False, 'codec measurement scope')
    require(report['sizes_bytes'] == {'native_proof': 53600, 'compact_proof': 51578,
        'native_packet': 256532, 'standalone_compact_packet': 225004,
        'referenced_compact_packet': 67696}, 'reported size census')
    require(len(report['cases']) == 3, 'three fresh measurement cases required')
    checked = []
    native_digests = set()
    for ordinal, case in enumerate(report['cases']):
        require(case['ordinal'] == ordinal, 'case ordering')
        artifacts = {}
        for kind, size in SIZES.items():
            record = case['artifacts'][kind]
            name = f'case-{ordinal}-{kind}.bin'
            require(record['file'] == name and record['bytes'] == size, 'artifact identity or length')
            path = directory / name
            require(not path.is_symlink() and path.stat().st_size == size, 'artifact storage')
            value = path.read_bytes()
            require(hashlib.sha3_256(value).hexdigest() == record['sha3_256'], 'artifact digest')
            artifacts[kind] = value
        native = artifacts['native']
        native_digests.add(hashlib.sha3_256(native).digest())
        require(native[:8] == b'LPQMPK01' and native[8:12] == b'\x01\0\x01\0', 'native framing')
        require(native[12:44] == PROFILE, 'native parameter profile')
        require(native[76:80] == (202848).to_bytes(4, 'little'), 'native statement prefix')
        statement = native[80:80 + 202848]
        require(native[202928:202932] == (53600).to_bytes(4, 'little'), 'native proof prefix')
        proof = native[202932:]
        require(native[44:76].hex() == case['context_hex'], 'context record')
        require(statement[:32].hex() == case['setup_seed_hex'], 'setup seed record')
        encoded_proof = proof_encoding(proof)
        require(artifacts['proof'] == encoded_proof, 'independent proof encoding mismatch')
        header = b'LPQMCP01' + native[8:76]
        expected_full = header + (1).to_bytes(4, 'little') + statement_encoding(statement) + encoded_proof
        require(artifacts['standalone'] == expected_full, 'independent standalone packet mismatch')
        accounts = [statement[i:i + 9216] for i in range(32, 32 + 184320, 9216)]
        domain = bytes.fromhex(case['ledger_domain_hex'])
        require(len(domain) == 32 and case['ledger_account_count'] == 20, 'ledger scope')
        root, checkpoint = ledger(domain, statement[:32], accounts)
        require(root.hex() == case['ledger_root_hex'], 'independent ledger root mismatch')
        require(checkpoint.hex() == case['ledger_checkpoint_hex'], 'independent checkpoint mismatch')
        suffix = statement_encoding(statement, omit_ring=True)
        expected_refs = (header + (2).to_bytes(4, 'little') + checkpoint + suffix[:32]
                         + b''.join(i.to_bytes(8, 'little') for i in range(20))
                         + suffix[32:] + encoded_proof)
        require(artifacts['referenced'] == expected_refs, 'independent referenced packet mismatch')
        checked.append({'ordinal': ordinal, 'native_sha3_256': hashlib.sha3_256(native).hexdigest(),
                        'proof_bytes': len(encoded_proof), 'standalone_bytes': len(expected_full),
                        'referenced_bytes': len(expected_refs)})
    require(len(native_digests) == 3, 'reused native artifact')
    return {'schema': 'ringct-compact-independent-audit-v1', 'passed': True,
            'scope': 'Independent Python encoding and Merkle commitment audit; native C/Rust proof validity is checked separately.',
            'report_sha256': hashlib.sha256(report_path.read_bytes()).hexdigest(), 'cases': checked}


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: compact_packet_audit.py ARTIFACT_DIRECTORY')
    print(json.dumps(audit(sys.argv[1]), indent=2))
