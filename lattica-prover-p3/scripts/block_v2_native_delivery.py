"""Multi-height research delivery: verified snapshots, fresh leaves, fenced apply.

The caller supplies the native verifier and issuance policy independently. This
module neither activates production nor makes a throughput qualification claim.
All fixture preparation and history replay belongs in end-to-end timing.
"""

import ctypes
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import time

import block_v2_host_store as H


_spec = importlib.util.spec_from_file_location(
    'native_fixture_codec', Path(__file__).with_name('block-v2-native-fixture.py'))
_codec = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_codec)
pin = _codec.pin


def delivery_genesis(library, slots):
    if type(slots) is not int or not 1 <= slots <= 2048:
        raise ValueError('delivery funding requires 1..2048 synthetic slots')
    native = ctypes.CDLL(str(Path(library).resolve(strict=True)))
    call = native.lattica_v2_research_delivery_genesis_v1
    call.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t,
                     ctypes.POINTER(ctypes.c_size_t)]
    call.restype = ctypes.c_int32
    output = ctypes.create_string_buffer(68 + 4096 * (32 + 1088 + 2 + 256))
    length = ctypes.c_size_t()
    status = call(slots, output, len(output), ctypes.byref(length))
    if status != 0 or not 68 <= length.value <= len(output):
        raise H.RejectedBlock(f'native delivery genesis rejected (status {status})')
    return output.raw[:length.value]


def prepare_batch(store, indices, registry_fixture, cpu_probe, output):
    """Retain fresh proofs/bodies tied to an immutable, CPU-verified head.

    Returns a manifest; apply_prepared checks all pinned inputs and uses the
    original head token. Reorgs or concurrent writes may make work stale.
    """
    if (not 1 <= len(indices) <= 64 or len(set(indices)) != len(indices)
            or any(type(i) is not int or not 0 <= i < 2048 for i in indices)):
        raise ValueError('choose 1..64 distinct funded delivery slot indices')
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    fixture = Path(registry_fixture).resolve(strict=True)
    cpu = Path(cpu_probe).resolve(strict=True)
    started = time.monotonic()
    result = {'schema_version': 1, 'record_type': 'native_delivery_preparation',
              'status': 'running', 'production_ready': False, 'indices': list(indices),
              'cpu_probe': pin(cpu), 'verifier': store.verifier.identity,
              'host_configuration_sha256': H.sha(H.canonical(store.verifier.configuration)),
              'wallets': [], 'commands': [], 'registry_sources': []}
    try:
        view, history = store.snapshot()
        height = view.state['height'] + 1
        result.update(parent_head_token=view.token, parent_tip=view.tip,
                      parent_state=view.state, height=height,
                      history=[{'height': c.height, 'body_sha256': H.sha(c.body),
                                'proof_sha256': H.sha(c.proof)} for c in history])
        grants = store.verifier._policy.for_block(height, len(indices))
        if grants != tuple(7 if i % 4 == 3 else 0 for i in indices):
            raise H.RejectedBlock('selected slots differ from independent host issuance grants')
        for name in ['height.json'] + [f'key.{i}' for i in range(1, 13)]:
            source = fixture / name
            source_pin = pin(source)
            shutil.copy2(source, output / name)
            if H.sha((output / name).read_bytes()) != source_pin['sha256']:
                raise ValueError('registry input changed while copying')
            result['registry_sources'].append(source_pin)
        (output / 'genesis.bin').write_bytes(store.verifier._genesis)
        bodies, statements = [], []
        for position, index in enumerate(indices):
            before = time.monotonic()
            packet = store.verifier.prepare_wallet(history, index)
            body, wallet, public = _codec.packet(packet, index)
            body_path, wallet_path = output / f'complete-body.{position}', output / f'wallet.{position}'
            body_path.write_bytes(body)
            wallet_path.write_bytes(wallet)
            bodies.append(body)
            statements.append({'kind': _codec.KINDS[index % 4], 'statement': public})
            result['wallets'].append({'position': position, 'source_index': index,
                                      'participant': (index // 4) % 4,
                                      'seconds': time.monotonic() - before,
                                      'complete_body': pin(body_path), 'wallet': pin(wallet_path),
                                      'recipient_ciphertexts_checked': 2, 'cpu_leaf_verified': True})
        aggregate = b'LBV2BD01' + struct.pack('<I', len(bodies)) + b''.join(b[12:] for b in bodies)
        (output / 'complete-body.bin').write_bytes(aggregate)
        (output / 'body.json').write_text(json.dumps({
            'schema_version': 1, 'chain': list(store.verifier._context[32:]),
            'transactions': statements}, indent=2) + '\n')
        # Host policy comes from the verified snapshot and independent grants.
        # The benchmark's legacy `expected` command intentionally assumes the
        # fixed height-10 demo; actual proving/audit accepts this pinned input.
        derive = store.verifier._lib.lattica_v2_research_body_expected_v1
        derive.argtypes = [ctypes.c_void_p, ctypes.c_size_t] * 3
        derive.restype = ctypes.c_int32
        context = ctypes.create_string_buffer(store.verifier._context)
        native_body = ctypes.create_string_buffer(aggregate)
        native_expected = ctypes.create_string_buffer(112)
        if derive(context, 64, native_body, len(aggregate), native_expected, 112) != 0:
            raise H.RejectedBlock('native complete-body expectation derivation failed')
        expected = native_expected.raw
        if (expected[:8] != b'LBV2EX01' or expected[8:72] != store.verifier._context
                or int.from_bytes(expected[104:112], 'little') != len(indices)):
            raise H.RejectedBlock('native expectation differs from trusted context/count')
        (output / 'native-expected.bin').write_bytes(expected)
        host_expected = {'schema_version': 1, 'profile': list(expected[8:40]),
                         'chain': list(expected[40:72]),
                         'root': list(struct.unpack_from('<QQQQ', expected, 72)),
                         'count': len(indices), 'block_height': height,
                         'authorized_issuance': {i: n for i, n in enumerate(grants) if n}}
        (output / 'expected.json').write_bytes(H.canonical(host_expected))
        commands = [
            [str(cpu), 'export-host-registry', str(output), str(output / 'host-registry.bin')],
            [str(cpu), 'plan', str(output), str(output / 'expected.json')],
            [str(cpu), 'export-host-expected', str(output / 'expected.json'), str(output / 'rust-expected.bin')],
        ]
        for number, command in enumerate(commands, 1):
            log = output / f'public-check-{number}.log'
            with log.open('x') as handle:
                check = subprocess.run(command, stdout=handle, stderr=subprocess.STDOUT)
            result['commands'].append({'command': command, 'exit_code': check.returncode, 'log': pin(log)})
            if check.returncode:
                raise H.RejectedBlock(f'public validation command {number} failed')
        # `plan` independently recomputes every statement commitment from the
        # Rust public body, including policy checks. The binary export must then
        # match the native complete-body expectation byte for byte.
        if ((output / 'rust-expected.bin').read_bytes() != expected
                or (output / 'host-registry.bin').read_bytes() != store.verifier._registry):
            raise H.RejectedBlock('Rust plan/export differs from native host expectation')
        sources = [pin(output / name) for name in
                   ('genesis.bin', 'body.json', 'complete-body.bin', 'host-registry.bin',
                    'expected.json', 'rust-expected.bin', 'native-expected.bin', 'height.json')]
        sources += [pin(output / f'key.{i}') for i in range(1, 13)]
        sources += [row[key] for row in result['wallets'] for key in ('complete_body', 'wallet')]
        result.update(sources=sources, fresh_leaf_proofs=len(indices),
                      native_rust_expected_statements_equal=True, status='succeeded')
        for source in result['registry_sources'] + [result['cpu_probe']]:
            if pin(Path(source['path'])) != source:
                raise ValueError('preparation input changed')
    except Exception as error:
        result.update(status='failed', failure=f'{type(error).__name__}: {error}')
        raise
    finally:
        result['elapsed_seconds'] = time.monotonic() - started
        (output / 'manifest.json').write_bytes(H.canonical(result))
    return result


def apply_prepared(store, fixture, proof):
    """Apply only against the exact preparation head; native replay audits root."""
    fixture = Path(fixture).resolve(strict=True)
    manifest = json.loads((fixture / 'manifest.json').read_bytes())
    if (manifest.get('record_type') != 'native_delivery_preparation'
            or manifest.get('status') != 'succeeded'
            or manifest.get('host_configuration_sha256') != H.sha(H.canonical(store.verifier.configuration))):
        raise H.RejectedBlock('prepared candidate has a different trusted host configuration')
    for source in manifest['sources']:
        if pin(Path(source['path'])) != source:
            raise H.RejectedBlock('prepared candidate input changed')
    candidate = H.Candidate(manifest['height'], (fixture / 'complete-body.bin').read_bytes(),
                            Path(proof).read_bytes())
    candidate.validate()
    return store.commit(candidate, expected_head=manifest['parent_head_token'])
