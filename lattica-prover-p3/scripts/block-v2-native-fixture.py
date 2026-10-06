#!/usr/bin/env python3
"""Prepare complete public bodies and fresh leaves from four synthetic wallets.

No private witness/key files are written. The native generator checks recipient
decryption and matches each complete body's commitment to its Rust leaf public
statement. Registry keys are independently supplied from a retained fixture.
This does not run recursive proving or qualify durable transaction delivery.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import time


KINDS = ('joinsplit', 'htlc_redeem', 'htlc_refund', 'issuance')
# V1 uses ML-KEM-768 (1088-byte KEM ciphertext), two inputs/two outputs,
# 256-byte ciphertext caps and at most 64 transactions. Match the native bound.
MAX_WALLET_EXPORT = 16 + 186252 + 2 * 1024 * 1024 + 264


def pin(path):
    return {'path': str(path.resolve()), 'bytes': path.stat().st_size,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def packet(data, index):
    if len(data) < 16 or data[:8] != b'LBV2FX01':
        raise ValueError('native fixture packet version/length')
    body_len, leaf_len = struct.unpack_from('<II', data, 8)
    if body_len < 12 or leaf_len < 16 or 16 + body_len + leaf_len != len(data):
        raise ValueError('native fixture packet bounds')
    body, leaf = data[16:16 + body_len], data[16 + body_len:]
    if body[:8] != b'LBV2BD01' or struct.unpack_from('<I', body, 8)[0] != 1 or leaf[:8] != b'LBV2WP01':
        raise ValueError('native single-body/leaf packet mismatch')
    wallet_len, count = struct.unpack_from('<II', leaf, 8)
    if (count != (31 if index % 4 in (1, 2) else 26) or wallet_len < 8
            or 16 + wallet_len + count * 8 != len(leaf)):
        raise ValueError('native leaf public-statement shape mismatch')
    wallet = leaf[16:16 + wallet_len]
    if wallet[:8] != b'LBV2TW01':
        raise ValueError('native wallet envelope version mismatch')
    public = list(struct.unpack_from('<' + 'Q' * count, leaf, 16 + wallet_len))
    if any(value >= 0xffff_ffff_0000_0001 for value in public):
        raise ValueError('noncanonical native public statement')
    return body, wallet, public


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--cpu-probe', type=Path, required=True)
    parser.add_argument('--registry-fixture', type=Path, required=True)
    parser.add_argument('--indices', type=int, nargs='+', default=[0, 1, 2, 3])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if (not 1 <= len(args.indices) <= 64 or len(set(args.indices)) != len(args.indices)
            or any(not 0 <= index < 64 for index in args.indices)):
        parser.error('choose one to 64 unique native fixture indices from 0 to 63')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    library, cpu = args.library.resolve(strict=True), args.cpu_probe.resolve(strict=True)
    source = args.registry_fixture.resolve(strict=True)
    report = {'schema_version': 1, 'status': 'running', 'indices': args.indices,
              'library': pin(library), 'cpu_probe': pin(cpu), 'registry_sources': [], 'wallets': [],
              'complete_native_bodies': True, 'fresh_recursive_proofs': 0,
              'durable_host_applied': False, 'delivered_transactions_measured': False, 'production_ready': False}
    started = time.monotonic()
    try:
        for name in ['height.json'] + [f'key.{i}' for i in range(1, 13)]:
            path = source / name
            source_pin = pin(path)
            report['registry_sources'].append(source_pin)
            shutil.copy2(path, out / name)
            if pin(out / name)['sha256'] != source_pin['sha256']:
                raise ValueError('registry source changed while copying')
        native = ctypes.CDLL(str(library))
        if pin(library) != report['library']:
            raise ValueError('native library changed during load')
        genesis_call = native.lattica_v2_research_fixture_genesis_v1
        genesis_call.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        genesis_call.restype = ctypes.c_int32
        wallet_call = native.lattica_v2_research_fixture_wallet_v1
        wallet_call.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        wallet_call.restype = ctypes.c_int32
        genesis = ctypes.create_string_buffer(1024 * 1024)
        length = ctypes.c_size_t()
        code = genesis_call(genesis, len(genesis), ctypes.byref(length))
        if code != 0 or not 68 <= length.value <= len(genesis):
            raise ValueError(f'native genesis generation failed: {code}')
        (out / 'genesis.bin').write_bytes(genesis.raw[:length.value])
        bodies, statements = [], []
        for position, index in enumerate(args.indices):
            buffer = ctypes.create_string_buffer(MAX_WALLET_EXPORT)
            length = ctypes.c_size_t()
            before = time.monotonic()
            code = wallet_call(index, buffer, len(buffer), ctypes.byref(length))
            if code != 0 or not 16 <= length.value <= len(buffer):
                raise ValueError(f'native wallet {index} generation failed: {code}')
            body, wallet, public = packet(buffer.raw[:length.value], index)
            body_path, wallet_path = out / f'complete-body.{position}', out / f'wallet.{position}'
            body_path.write_bytes(body)
            wallet_path.write_bytes(wallet)
            bodies.append(body)
            statements.append({'kind': KINDS[index % 4], 'statement': public})
            report['wallets'].append({'position': position, 'source_index': index,
                                      'seconds': time.monotonic() - before,
                                      'complete_body': pin(body_path), 'wallet': pin(wallet_path),
                                      'recipient_ciphertexts_checked': 2, 'cpu_leaf_verified': True})
            print(json.dumps({'event': 'native_wallet_prepared', 'index': index, 'position': position}), flush=True)
        aggregate = b'LBV2BD01' + struct.pack('<I', len(bodies)) + b''.join(body[12:] for body in bodies)
        (out / 'complete-body.bin').write_bytes(aggregate)
        public_body = {'schema_version': 1, 'chain': [0x6d] * 32, 'transactions': statements}
        (out / 'body.json').write_text(json.dumps(public_body, indent=2) + '\n')
        commands = [
            [str(cpu), 'export-host-registry', str(out), str(out / 'host-registry.bin')],
            [str(cpu), 'expected', str(out), str(len(bodies)), str(out / 'expected.json')],
            [str(cpu), 'export-host-expected', str(out / 'expected.json'), str(out / 'rust-expected.bin')],
        ]
        report['commands'] = []
        for number, command in enumerate(commands, 1):
            log = out / f'public-check-{number}.log'
            with log.open('x') as handle:
                result = subprocess.run(command, stdout=handle, stderr=subprocess.STDOUT)
            report['commands'].append({'command': command, 'exit_code': result.returncode, 'log': pin(log)})
            if result.returncode:
                raise ValueError(f'public validation command {number} failed')
        expected = (out / 'rust-expected.bin').read_bytes()
        if len(expected) != 112 or expected[:8] != b'LBV2EX01':
            raise ValueError('Rust expected-statement export mismatch')
        context = ctypes.create_string_buffer(expected[8:72])
        complete = ctypes.create_string_buffer(aggregate)
        native_expected = ctypes.create_string_buffer(112)
        derive = native.lattica_v2_research_body_expected_v1
        derive.argtypes = [ctypes.c_void_p, ctypes.c_size_t] * 3
        derive.restype = ctypes.c_int32
        if derive(context, 64, complete, len(aggregate), native_expected, 112) != 0 or native_expected.raw != expected:
            raise ValueError('complete native body root differs from Rust leaf-public root')
        (out / 'native-expected.bin').write_bytes(native_expected.raw)
        if pin(library) != report['library'] or pin(cpu) != report['cpu_probe']:
            raise ValueError('native preparation binary changed')
        if any(pin(Path(source['path'])) != source for source in report['registry_sources']):
            raise ValueError('trusted registry inputs changed during preparation')
        report['status'] = 'succeeded'
        report['native_rust_expected_statements_equal'] = True
        report['fresh_leaf_proofs'] = len(bodies)
        report['sources'] = [pin(out / name) for name in
                             ('genesis.bin', 'body.json', 'complete-body.bin', 'host-registry.bin',
                              'expected.json', 'rust-expected.bin', 'native-expected.bin')]
        report['sources'].append(pin(Path(__file__)))
        report['scope'] = 'Fresh CPU-verified leaves, usable recipient ciphertexts and independently derived '
        report['scope'] += 'native/Rust expected roots. No recursive root has been proved or durably applied.'
    except Exception as error:
        report['status'] = 'failed'
        report['failure'] = f'{type(error).__name__}: {error}'
    report['elapsed_seconds'] = time.monotonic() - started
    (out / 'manifest.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': report['status'], 'failure': report.get('failure'),
                      'manifest': str(out / 'manifest.json')}))
    return int(report['status'] != 'succeeded')


if __name__ == '__main__':
    raise SystemExit(main())
