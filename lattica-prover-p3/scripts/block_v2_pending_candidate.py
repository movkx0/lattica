"""Revalidate durable arrivals and assemble a candidate under native host policy."""

import os
from pathlib import Path
import shutil
import struct
import subprocess
import time
import block_v2_host_store as H
import block_v2_native_delivery as D
import block_v2_native_shared as N


def _complete(selected):
    return b'LBV2BD01' + struct.pack('<I', len(selected)) + b''.join(row['body'][12:] for row in selected)


def _verify_inputs(host, view, fixture, cpu, output, selected, preflight, manifest):
    """Retain native-derived statements, then authenticate the exact wallet bytes."""
    expected, height, grants = preflight['expected'], preflight['height'], preflight['grants']
    expected_json = {'schema_version': 1, 'profile': list(expected[8:40]),
                    'chain': list(expected[40:72]), 'root': list(struct.unpack_from('<QQQQ', expected, 72)),
                    'count': len(selected), 'block_height': height,
                    'authorized_issuance': {str(i): amount for i, amount in enumerate(grants) if amount}}
    for name in ['height.json'] + [f'key.{i}' for i in range(1, 13)]:
        source = D.pin(fixture / name)
        shutil.copyfile(fixture / name, output / name)
        if H.sha((output / name).read_bytes()) != source['sha256']:
            raise RuntimeError('registry changed during candidate preparation')
        manifest['registry_sources'].append(source)
    for position, row in enumerate(selected):
        (output / f'complete-body.{position}').write_bytes(row['body'])
        (output / f'wallet.{position}').write_bytes(row['wallet'])
        manifest['wallets'].append({'position': position, 'request_id': row['receipt']['request_id'],
            'complete_body': D.pin(output / f'complete-body.{position}'), 'wallet': D.pin(output / f'wallet.{position}')})
    (output / 'genesis.bin').write_bytes(host.verifier._genesis)
    (output / 'complete-body.bin').write_bytes(_complete(selected))
    (output / 'body.json').write_bytes(H.canonical(preflight['body']))
    (output / 'expected.json').write_bytes(H.canonical(expected_json))
    (output / 'native-expected.bin').write_bytes(expected)
    (output / 'pending-arrivals.json').write_bytes(H.canonical({
        'schema_version': 1, 'native_head': view.token, 'generation': view.generation,
        'host_configuration_sha256': manifest['host_configuration_sha256'],
        'request_ids': [r['receipt']['request_id'] for r in selected],
        'arrivals': [r['receipt'] for r in selected]}))
    commands = [
        [cpu, 'export-host-registry', output, output / 'host-registry.bin'],
        [cpu, 'export-host-expected', output / 'expected.json', output / 'rust-expected.bin'],
        [cpu, 'verify-wallets', output, output / 'expected.json', output / 'wallet-verification.json'],
    ]
    for number, command in enumerate(commands, 1):
        log = output / f'cpu-verification-{number}.log'
        with log.open('xb') as stream:
            done = subprocess.run([str(arg) for arg in command], stdout=stream, stderr=subprocess.STDOUT,
                                  env=os.environ | {'RAYON_NUM_THREADS': '1'})
        manifest['commands'].append({'command': [str(arg) for arg in command], 'exit_code': done.returncode, 'log': D.pin(log)})
        if done.returncode:
            if number == 3 and done.returncode == 1:
                raise H.RejectedBlock('CPU verification of pending wallet statements failed')
            raise RuntimeError('CPU verifier command failed unexpectedly')
        if number == 1 and (output / 'host-registry.bin').read_bytes() != host.verifier._registry:
            raise RuntimeError('CPU registry differs from the trusted native registry')
        if number == 2 and (output / 'rust-expected.bin').read_bytes() != expected:
            raise RuntimeError('native and CPU expected statements differ')
    verified = N.read(output / 'wallet-verification.json')
    if verified.get('cpu_leaf_verified') is not True or verified.get('count') != len(selected):
        raise RuntimeError('CPU verifier did not authenticate every selected wallet')
    if D.pin(cpu) != manifest['cpu_probe']:
        raise RuntimeError('CPU verifier binary changed during preparation')
    for wallet in manifest['wallets']:
        wallet['cpu_leaf_verified'] = True
    names = ['height.json', 'genesis.bin', 'body.json', 'complete-body.bin', 'expected.json',
             'native-expected.bin', 'rust-expected.bin', 'host-registry.bin', 'pending-arrivals.json', 'wallet-verification.json']
    names += [f'key.{i}' for i in range(1, 13)]
    names += [f'{kind}.{i}' for i in range(len(selected)) for kind in ('wallet', 'complete-body')]
    manifest.update(native_rust_expected_statements_equal=True, native_state_preflight_passed=True,
        independently_cpu_verified_wallets=len(selected),
        sources=[D.pin(output / name) for name in names] + [D.pin(cpu), D.pin(Path(__file__))])


def _base(intake, cpu):
    return {'schema_version': 1, 'status': 'running', 'production_ready': False,
            'fresh_leaf_proofs': 0, 'cpu_probe': D.pin(cpu), 'host_configuration_sha256': intake.configuration,
            'wallets': [], 'commands': [], 'registry_sources': []}


def _choose(host, view, history, pool, limit, screen, attempts, *, complete=True):
    """FIFO within each host-assigned role; invalid arrivals remain retained."""
    height = view.state['height'] + 1
    policy = host.verifier._policy.for_block if complete else host.verifier._policy.for_prefix
    grants = policy(height, limit)
    selected, used, rejected, invalid_wallets = [], set(), set(), set()
    for position in range(limit):
        accepted = None
        for row in pool:
            request = row['receipt']['request_id']
            role = len(row['body']) > 12 and row['body'][12] == 3
            key = (request, grants[position])
            if request in used or request in invalid_wallets or key in rejected or role != bool(grants[position]):
                continue
            attempt = {'request_id': request, 'position': position,
                       'authorized_issuance': grants[position], 'status': 'screening'}
            attempts.append(attempt)
            try:
                preflight = host.verifier.preflight_prefix(history, _complete(selected + [row]), height)
            except H.RejectedBlock as error:
                attempt.update(status='rejected_by_native_prefix', reason=str(error))
                rejected.add(key)
                continue
            try:
                attempt['screening'] = screen(row, position, preflight)
            except H.RejectedBlock as error:
                attempt.update(status='rejected_by_cpu_wallet_verification', reason=str(error))
                invalid_wallets.add(request)
                continue
            attempt['status'] = 'selected'
            selected.append(row)
            used.add(request)
            accepted = row
            if grants[position]:
                # Issuance may cover a previously unaffordable fee. Invalid
                # wallet proofs are independent of that supply change.
                rejected.clear()
            break
        if accepted is None:
            break
    if not selected:
        raise H.RejectedBlock('no eligible arrivals for the current native head and policy')
    if complete:
        host.verifier._policy.for_block(height, len(selected))
    return selected


def prepare(intake, host_config, registry_fixture, cpu_probe, output, *, request_ids=None, limit=64, scan_limit=256, prefix=False):
    if type(limit) is not int or not 1 <= limit <= 64:
        raise ValueError('candidate limit must be in 1..64')
    if type(scan_limit) is not int or not limit <= scan_limit <= 4096:
        raise ValueError('scan limit must cover the candidate limit and be at most 4096')
    if request_ids is not None and (not isinstance(request_ids, list) or not 1 <= len(request_ids) <= limit):
        raise ValueError('explicit selection exceeds the candidate limit')
    output = Path(output).resolve()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    fixture, cpu, config = [Path(p).resolve(strict=True) for p in (registry_fixture, cpu_probe, host_config)]
    started = time.monotonic()
    manifest = _base(intake, cpu)
    manifest.update(record_type='native_arrival_prefix_preparation' if prefix else 'native_delivery_preparation',
        preparation_backend='durable-pending-arrivals',
        arrival_head_revalidation=True, selection_policy='independent-host-policy-v1' if request_ids is None else 'explicit-host-order-v1',
        scan_limit=scan_limit, selection_attempts=[])
    try:
        host = N.open_host(config, intake.host.directory)
        if H.sha(H.canonical(host.verifier.configuration)) != intake.configuration:
            raise H.RejectedBlock('candidate builder and intake use different native configurations')
        manifest['verifier'] = host.verifier.identity
        view, history = host.snapshot()
        height = view.state['height'] + 1
        pool = intake.candidate_inputs(expected_head=view.token, request_ids=request_ids, limit=scan_limit)
        manifest.update(parent_head_token=view.token, parent_tip=view.tip, parent_state=view.state, height=height,
            scanned_request_ids=[r['receipt']['request_id'] for r in pool],
            history=[{'height': c.height, 'body_sha256': H.sha(c.body), 'proof_sha256': H.sha(c.proof)} for c in history])

        def screen(row, position, prefix):
            directory = output / f'screen-{len(manifest["selection_attempts"]):04d}'
            directory.mkdir(mode=0o700)
            record = _base(intake, cpu)
            record.update(record_type='native_arrival_screening', request_id=row['receipt']['request_id'],
                parent_head_token=view.token, original_receipt=row['receipt'], height=height,
                source_policy_position=position, authorized_issuance=prefix['grants'][position])
            began = time.monotonic()
            try:
                single = {'expected': N.native_expected(host.verifier, row['body']), 'height': height,
                          'grants': (prefix['grants'][position],),
                          'body': {**prefix['body'], 'transactions': [prefix['body']['transactions'][position]]}}
                _verify_inputs(host, view, fixture, cpu, directory, [row], single, record)
                record['status'] = 'passed'
            except BaseException as error:
                record.update(status='failed', failure=f'{type(error).__name__}: {error}')
                raise
            finally:
                record['elapsed_seconds'] = time.monotonic() - began
                (directory / 'manifest.json').write_bytes(H.canonical(record))
                manifest['selection_attempts'][-1]['screening'] = D.pin(directory / 'manifest.json')
            return D.pin(directory / 'manifest.json')

        selected = pool if request_ids is not None else _choose(host, view, history, pool, limit, screen, manifest['selection_attempts'], complete=not prefix)
        selected_ids = [r['receipt']['request_id'] for r in selected]
        manifest.update(request_ids=selected_ids, reused_leaf_proofs=len(selected),
            revalidated_request_ids=[r['receipt']['request_id'] for r in selected if r['receipt']['head_token'] != view.token],
            unselected_request_ids=[r['receipt']['request_id'] for r in pool if r['receipt']['request_id'] not in selected_ids])
        preflight_call = host.verifier.preflight_prefix if prefix else host.verifier.preflight
        preflight = preflight_call(history, _complete(selected), height)
        _verify_inputs(host, view, fixture, cpu, output, selected, preflight, manifest)
        if host.read().token != view.token:
            raise H.StaleHead('native head changed during candidate assembly')
        manifest['sources'] += [attempt['screening'] for attempt in manifest['selection_attempts'] if 'screening' in attempt]
        manifest['status'] = 'succeeded'
    except BaseException as error:
        manifest.update(status='failed', failure=f'{type(error).__name__}: {error}')
        raise
    finally:
        manifest['elapsed_seconds'] = time.monotonic() - started
        (output / 'manifest.json').write_bytes(H.canonical(manifest))
    return N.Candidate(config, intake.host.directory, output, len(selected), prefix=prefix)
