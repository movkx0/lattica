#!/usr/bin/env python3
"""Run fresh-wallet -> persistent GPU pool -> CPU audit -> durable native delivery.

All funding and issuance are synthetic research inputs. No production activation
or throughput promotion is implied. Each run owns a new evidence directory;
failures and the entire startup interval remain in lifecycle accounting.
"""
import argparse
from concurrent.futures import ProcessPoolExecutor
import importlib
import json
import multiprocessing
import os
from pathlib import Path
import queue
import secrets
import subprocess
import sys
import threading
import time

import block_v2_host_store as H
import block_v2_native_delivery as D
import block_v2_native_shared as N
from benchmark_report.campaign import analyze

ROOT = Path(__file__).resolve().parent
KINDS = ('joinsplit', 'htlc_redeem', 'htlc_refund', 'issuance')
_wallet_store = None
_wallet_identity = None


def publish(path, value):
    """Never expose a partial request or completion record to the other process."""
    data = H.canonical(value)
    temporary = path.with_name(path.name + '.tmp-' + secrets.token_hex(8))
    with temporary.open('xb') as handle:
        os.chmod(temporary, 0o600)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def wallet(config_path, journal, head, index):
    # Spawned participants receive public inputs. Witnesses and proving RNG stay
    # inside their own native process, and never enter the aggregation protocol.
    global _wallet_store, _wallet_identity
    identity = (str(config_path), str(journal), D.pin(Path(config_path))['sha256'])
    if _wallet_identity != identity:
        _wallet_store = N.open_host(config_path, journal)
        _wallet_identity = identity
    store = _wallet_store
    view, history = store.snapshot()
    if view.token != head:
        raise H.StaleHead('wallet participant observed another native head')
    return store.verifier.prepare_wallet(history, index)


def prepare(config, request):
    store = N.open_host(config['host_config'], config['host_journal'])
    indices = request['indices']
    head = store.read().token
    participants = config['wallet']['participants']
    os.environ['RAYON_NUM_THREADS'] = str(max(1, config['wallet']['threads'] // participants))
    with ProcessPoolExecutor(max_workers=participants, mp_context=multiprocessing.get_context('spawn')) as executor:
        futures = {i: executor.submit(wallet, config['host_config'], config['host_journal'], head, i) for i in indices}
        def provider(index, expected_head):
            if head != expected_head:
                raise H.StaleHead('native preparation changed before wallet dispatch')
            return futures[index].result()
        return D.prepare_batch(store, indices, config['registry_fixture'], config['cpu_binary'],
                               request['output'], wallet_provider=provider)


def validate(config):
    if config.get('schema_version') != 1 or config['count'] not in (4, 8, 16, 32, 64):
        raise ValueError('campaign requires a current-profile mixed count')
    integers = {'max_roots': (1, 256), 'min_roots': (1, 256),
                'min_duration_seconds': (0, 604800), 'max_wall_seconds': (1, 604800),
                'candidate_timeout_seconds': (1, 3600)}
    for key, (minimum, maximum) in integers.items():
        if type(config.get(key)) is not int or not minimum <= config[key] <= maximum:
            raise ValueError('invalid bounded campaign field: ' + key)
    cycle = config.get('cycle_seconds', 720)
    if type(cycle) is not int or not 0 <= cycle <= 720:
        raise ValueError('invalid research pacing interval')
    if config['max_roots'] < config['min_roots'] or config['max_wall_seconds'] <= config['min_duration_seconds']:
        raise ValueError('campaign stopping bounds differ')
    w = config['wallet']
    if (set(w) != {'participants', 'threads', 'ram_bytes'} or
            any(type(v) is not int or v <= 0 for v in w.values()) or
            w['participants'] > 4 or w['threads'] < w['participants']):
        raise ValueError('invalid wallet reservations')
    profile = N.read(Path(config['workload']))
    allocation = profile.get('pool_allocation')
    if (allocation is None or allocation['wallet_threads'] != w['threads']
            or allocation['wallet_bytes'] < w['ram_bytes']):
        raise ValueError('wallet workers must fit the pool resource reservation')
    if config.get('arrival_mode') not in ('saturated', 'fixed_rate'):
        raise ValueError('declare saturated or fixed_rate arrivals')
    if config['arrival_mode'] == 'fixed_rate' and (type(config.get('arrival_interval_ms')) is not int
                                                   or config['arrival_interval_ms'] <= 0):
        raise ValueError('fixed arrivals need a positive interval')
    if config.get('mode') not in ('exploratory', 'qualifying'):
        raise ValueError('declare exploratory or qualifying mode')
    if config['mode'] == 'qualifying':
        if config['min_roots'] < 150 or config['min_duration_seconds'] < 86400 or cycle != 720:
            raise ValueError('qualification requires both 24 hours and 150 completed roots')
        gate = config['qualification']
        from block_v2_throughput import load_contract, resource_snapshot, evaluate
        contract = load_contract(Path(gate['contract']))
        resources = resource_snapshot(N.read(Path(gate['resource_plan'])), contract)
        result = evaluate(contract, N.read(Path(gate['evidence'])),
                          ROOT.parents[1], contract_path=Path(gate['contract']), resources=resources)
        if result['status'] != 'ready_for_research_pilot':
            raise ValueError('existing full-size/cold/post-seal qualification gates are blocked')
    return profile


class Events:
    def __init__(self, output, config, initial_tip):
        self.lock = threading.RLock()
        self.output = output
        self.started = time.monotonic_ns()
        self.capture = {'run_id': secrets.token_hex(16),
                        'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                        'started_monotonic_ns': self.started, 'started_unix_ns': time.time_ns()}
        self.data = {'schema_version': 1, 'record_type': 'transaction_campaign',
                     'campaign_id': 'pool-' + secrets.token_hex(8), 'label': 'Fresh local pool delivery',
                     'track': 'current-workstation', 'resource_profile_id': 'local-pool-v1',
                     'measurement_scope': 'durable_test_chain', 'initial_tip': initial_tip,
                     'sources': [D.pin(Path(config[key])) for key in
                    ('host_config', 'library', 'cpu_binary', 'gpu_binary', 'workload')]
                    + [D.pin(p) for p in sorted(Path(__file__).parent.rglob('*.py'))],
                     'window': {'clock': 'coordinator CLOCK_MONOTONIC', 'started_ns': str(self.started),
                                'finished_ns': None}, 'events': []}

    def emit(self, kind, **fields):
        with self.lock:
            event = {'event_id': f'event-{len(self.data["events"]):08}',
                     'at_ns': str(time.monotonic_ns()), 'type': kind, **fields}
            # Write-ahead event log includes interrupted and failed attempts.
            with (self.output / 'events.jsonl').open('ab') as handle:
                handle.write(H.canonical(event).rstrip(b'\n') + b'\n')
                handle.flush()
                os.fsync(handle.fileno())
            self.data['events'].append(event)
            return event

    def close(self):
        with self.lock:
            event = self.emit('window_closed')
            self.data['window']['finished_ns'] = event['at_ns']
            publish(self.output / 'campaign.json', self.data)
            report = analyze(self.data)
            publish(self.output / 'accounting.json', report)
            return report


def reconcile_services(owned):
    """Observe all recorded units, including workers, and retain every failure."""
    bootstrap = importlib.import_module('block_v2_coordinator_bootstrap')
    supervisor = importlib.import_module('block_v2_supervisor')
    failures = []
    for unit in [owned['owner_unit']] + [w['budget']['unit'] for w in owned['workers']]:
        try:
            state = supervisor.observe(unit)
            if state.get('LoadState') != 'not-found':
                subprocess.run(['systemctl', '--user', 'stop', unit], check=True,
                               timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            bootstrap.quiescent(supervisor.observe(unit), unit, None)
        except BaseException as error:
            failures.append(f'{unit}: {error}')
    if failures:
        raise RuntimeError('; '.join(failures))


def run(config_path, output):
    config = N.read(config_path)
    validate(config)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    publish(output / 'config.json', config)
    config_path = output / 'config.json'
    requests = output / 'requests'
    requests.mkdir(mode=0o700)
    store = N.open_host(config['host_config'], config['host_journal'])
    initial = store.read()
    if initial.state['blocks'] != 0:
        raise ValueError('each campaign requires its own funded genesis journal')
    if config['count'] * config['max_roots'] > store.verifier.wallet_slot_limit:
        raise ValueError('declared workload exceeds funded fixture capacity')
    events = Events(output, config, initial.tip or '0' * 64)
    stop = threading.Event()
    arrivals = queue.Queue(maxsize=16384)
    failures = []
    namespace = events.data['campaign_id']
    def produce():
        try:
            for index in range(config['count'] * config['max_roots']):
                if config['arrival_mode'] == 'fixed_rate':
                    due = events.started + index * config['arrival_interval_ms'] * 1_000_000
                    if stop.wait(max(0, (due - time.monotonic_ns()) / 1e9)):
                        break
                if stop.is_set():
                    break
                tid = H.sha(f'{namespace}:{index}'.encode())
                events.emit('submitted', transaction_id=tid, transaction_kind=KINDS[index % 4])
                arrivals.put((index, tid))
        except BaseException as error:
            failures.append(str(error))
            stop.set()
    producer = threading.Thread(target=produce, daemon=True)
    producer.start()
    service = None
    service_log = None
    roots = deadline_misses = 0
    report = {'schema_version': 1, 'status': 'running', 'production_ready': False,
              'capture': events.capture, 'sources': events.data['sources'],
              'sustained_throughput_qualified': False, 'mode': config['mode'], 'resource_failures': 1,
              'comparison_contract': {
                  'workload': {key: config.get(key) for key in ('count', 'max_roots', 'min_roots',
                      'min_duration_seconds', 'arrival_mode', 'arrival_interval_ms', 'candidate_timeout_seconds')},
                  'cycle_seconds': config.get('cycle_seconds', 720), 'wallet': config['wallet'],
                  'genesis_sha256': H.sha(store.verifier._genesis), 'profile_id': store.verifier._context[:32].hex(),
                  'resource_policy': N.read(Path(config['workload']))['pool_allocation'],
              }}
    def bounded():
        if (time.monotonic_ns() - events.started) / 1e9 >= config['max_wall_seconds']:
            raise TimeoutError('campaign wall-clock bound reached')
        if failures:
            raise RuntimeError(failures[0])
        if service is not None and service.poll() is not None:
            raise RuntimeError('persistent GPU service exited before stop')
    try:
        for sequence in range(config['max_roots']):
            due = events.started + sequence * config.get('cycle_seconds', 720) * 10**9
            while time.monotonic_ns() < due:
                bounded()
                time.sleep(min(0.2, (due - time.monotonic_ns()) / 1e9))
            batch = []
            while len(batch) < config['count']:
                bounded()
                try:
                    batch.append(arrivals.get(timeout=0.2))
                except queue.Empty:
                    continue
            fixture = output / f'fixture-{sequence:06}'
            request = output / f'wallet-{sequence:06}.json'
            publish(request, {'indices': [i for i, _ in batch], 'output': str(fixture)})
            # Wallet subprocess tree has an aggregate hard RAM/CPU cap, separate
            # from the coordinator and GPU reservations in the shared slice.
            command = ['systemd-run', '--user', '--quiet', '--wait', '--pipe', '--collect',
                       '--unit=lattica-wallet-' + secrets.token_hex(16),
                       '--slice=lattica-v2-multi.slice', '--property=MemorySwapMax=0',
                       '--property=MemoryMax=' + str(config['wallet']['ram_bytes']),
                       '--property=CPUQuota=' + str(config['wallet']['threads'] * 100) + '%',
                       '--property=RuntimeMaxSec=' + str(config['candidate_timeout_seconds']),
                       '--property=KillMode=control-group', '--property=OOMPolicy=kill',
                       sys.executable, str(Path(__file__).resolve()), 'prepare', '--config', str(config_path),
                       '--request', str(request)]
            with (output / f'wallet-{sequence:06}.log').open('xb') as log:
                subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT,
                               timeout=min(config['max_wall_seconds'], config['candidate_timeout_seconds'] + 60))
            for _, tid in batch:
                events.emit('wallet_proof_ready', transaction_id=tid)
                events.emit('admitted', transaction_id=tid)
            candidate = N.Candidate(config['host_config'], config['host_journal'], fixture, config['count'], store=store)
            if service is None:
                command = [sys.executable, str(ROOT / 'block-v2-typed-shared-gpu-run.py'),
                           '--gpu-binary', config['gpu_binary'], '--cpu-binary', config['cpu_binary'],
                           '--fixture', str(fixture), '--host-config', config['host_config'],
                           '--host-journal', config['host_journal'], '--count', str(config['count']),
                           '--workload', config['workload'], '--scratch', config['scratch'],
                           '--pool-requests', str(requests), '--pool-runtime-seconds', str(max(7200, config['max_wall_seconds'])),
                           '--evidence', str(output / 'service')]
                for uuid in config['gpu_uuids']:
                    command += ['--gpu-uuid', uuid]
                if config.get('resource_assignment'):
                    command += ['--resource-assignment', config['resource_assignment']]
                for trial in config.get('calibration_trials', []):
                    command += ['--calibration-trial', trial]
                service_log = (output / 'service.log').open('xb')
                service = subprocess.Popen(command, stdout=service_log, stderr=subprocess.STDOUT)
                ready_path = output / 'service/owner/proofs/pool-ready.json'
                while not ready_path.exists():
                    bounded()
                    time.sleep(0.1)
                ready = N.read(ready_path)
                allocation = N.read(output / 'service/config.json')
                report['comparison_contract']['worker_limits'] = [{
                    'gpu': {key: worker['budget']['gpu'][key] for key in ('uuid', 'managed_bytes', 'context_bytes')},
                    'cpu': worker['budget']['cpu'],
                    'host': {key: worker['budget']['host'][key] for key in ('worker_bytes', 'spill_bytes', 'coordinator_bytes')},
                } for worker in allocation['workers']]
                service_clock = time.monotonic_ns()
            bid = H.sha(bytes.fromhex(candidate.head.token) + (fixture / 'complete-body.bin').read_bytes())
            sealed = events.emit('sealed', block_id=bid, transaction_ids=[tid for _, tid in batch])
            deadline_ms = ready['ready_ms'] + (time.monotonic_ns() - service_clock) // 1_000_000 + config['candidate_timeout_seconds'] * 1000
            publish(requests / f'{sequence:06}.json', {'schema_version': 1, 'fixture': str(fixture),
                    'expected': str(fixture / 'expected.json'), 'native_host': candidate.binding, 'deadline_ms': deadline_ms})
            result_dir = output / f'service/owner/proofs/candidate-{sequence:06}'
            while not (result_dir / 'result.json').exists():
                bounded()
                if store.published_head_token() != candidate.head.token:
                    publish(requests / f'{sequence:06}.cancel', {'reason': 'stale_native_head'})
                    raise H.StaleHead('native head changed during pool proving')
                time.sleep(0.1)
            result = N.read(result_dir / 'result.json')
            for failure in result.get('worker_failures', []):
                events.emit('failed', reason='pool worker failure: ' + failure['reason'])
            proof = result_dir / 'node.6.0'
            if result['status'] != 'proved_cpu_audit_pending' or result['native_host'] != candidate.binding:
                raise ValueError('pool completion does not match native candidate')
            with (output / f'audit-{sequence:06}.log').open('xb') as log:
                subprocess.run(['systemd-run', '--user', '--quiet', '--wait', '--pipe', '--collect',
                                '--unit=lattica-audit-' + secrets.token_hex(16), '--slice=lattica-v2-multi.slice',
                                '--property=MemoryMax=' + str(config['wallet']['ram_bytes']), '--property=MemorySwapMax=0',
                                '--property=CPUQuota=100%', '--property=RuntimeMaxSec=300', '--property=KillMode=control-group',
                                '--setenv=RAYON_NUM_THREADS=1', config['cpu_binary'], 'audit-root', str(fixture), str(fixture / 'expected.json'),
                                str(fixture / 'body.json'), str(proof)], check=True, stdout=log, stderr=subprocess.STDOUT,
                               env={k: v for k, v in os.environ.items() if not k.startswith('LATTICA_V2_')}, timeout=300)
            verified = events.emit('root_verified', block_id=bid, cpu_audited=True, expected_statement_verified=True,
                                  level=6, proof_bytes=str(proof.stat().st_size), proof_sha256=H.sha(proof.read_bytes()),
                                  profile_sha256=bytes(candidate.binding['expected']['profile']).hex())
            receipt = candidate.apply(proof, candidate.binding)
            candidate.verify_application(receipt, proof, candidate.binding)
            publish(output / f'application-{sequence:06}.json', receipt)
            applied = events.emit('block_applied', block_id=bid, parent_block_id=events.data['initial_tip'] if roots == 0 else previous_bid,
                        durable=True, host_validated=True, state_commit_sha256=receipt['head_token'])
            if (int(applied['at_ns']) - int(sealed['at_ns'])) / 1e9 > 180:
                deadline_misses += 1
            if sequence == 0:
                report['cold_first_delivery_seconds'] = (int(applied['at_ns']) - events.started) / 1e9
            previous_bid = bid
            roots += 1
            elapsed = (time.monotonic_ns() - events.started) / 1e9
            if roots >= config['min_roots'] and elapsed >= config['min_duration_seconds']:
                break
        if roots < config['min_roots'] or (time.monotonic_ns() - events.started) / 1e9 < config['min_duration_seconds']:
            raise RuntimeError('funded run bound reached before both duration and root requirements')
        report['status'] = 'succeeded'
    except BaseException as error:
        events.emit('failed', reason=f'{type(error).__name__}: {error}')
        report.update(status='failed', failure=f'{type(error).__name__}: {error}')
    finally:
        stop.set()
        producer.join(timeout=5)
        try:
            report['accounting'] = events.close()
        except BaseException as error:
            # Accounting failure must never bypass physical worker cleanup.
            report.update(status='failed', accounting_failure=str(error))
            report['accounting'] = {'status': 'failed', 'failures': 1}
            if events.data['window']['finished_ns'] is None:
                events.data['window']['finished_ns'] = str(time.monotonic_ns())
        if service is not None:
            try:
                publish(requests / 'stop', {'reason': 'campaign_end'})
                service.wait(timeout=config['candidate_timeout_seconds'] + 90)
                if service.returncode != 0 or N.read(output / 'service/summary.json').get('status') != 'succeeded':
                    raise RuntimeError('GPU service cleanup/accounting failed')
                report['resource_failures'] = 0
            except BaseException as error:
                report.update(status='failed', cleanup_failure=str(error))
                # A timed-out launcher is not evidence of stopped GPU work.
                # Stop the exact units recorded by this run and let their
                # existing supervisor reconcile cgroups/device leases.
                service_config = output / 'service/config.json'
                try:
                    if service_config.exists():
                        reconcile_services(N.read(service_config))
                    service.wait(timeout=60)
                except BaseException as stop_error:
                    report['cleanup_failure'] += '; reconciliation: ' + str(stop_error)
            service_log.close()
        report['capture'].update(finished_monotonic_ns=time.monotonic_ns(), finished_unix_ns=time.time_ns())
        duration_ns = int(events.data['window']['finished_ns']) - events.started
        report.update(completed_roots=roots, post_seal_deadline_misses=deadline_misses,
                      sustained_workload_complete=roots >= 150 and duration_ns >= 86400 * 10**9)
        # A complete workload is necessary but not sufficient for promotion.
        report['sustained_throughput_qualified'] = (config['mode'] == 'qualifying' and report['status'] == 'succeeded'
                                                  and report['sustained_workload_complete'] and deadline_misses == 0
                                                  and report['accounting']['failures'] == 0 and report['resource_failures'] == 0
                                                  and (config['count'] != 64 or report.get('cold_first_delivery_seconds', float('inf')) <= 600))
        publish(output / 'summary.json', report)
    return 0 if report['status'] == 'succeeded' else 1


def initialize(config_path, output):
    """Pin independently declared research grants and create a fresh journal."""
    config = N.read(config_path)
    validate(config)
    library = Path(config['library']).resolve(strict=True)
    fixture = Path(config['registry_fixture']).resolve(strict=True)
    count, roots = config['count'], config['max_roots']
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    genesis = output / 'genesis.bin'
    genesis.write_bytes(D.delivery_genesis(library, count * roots, sustained=True))
    registry = fixture / 'host-registry.bin'
    expected = N.read(fixture / 'expected.json')
    host_config = output / 'native-config.json'
    publish(host_config, {'schema_version': 1, 'library': str(library), 'registry': str(registry),
                         'genesis': str(genesis), 'profile_id': bytes(expected['profile']).hex(),
                         'chain_id': bytes(expected['chain']).hex(), 'native_adapter': 'session-v2',
                         'workload_fixture': 'sustained-v2', 'history_limit': roots + 1,
                         'issuance_grants': {str(10 + r): {str(i): 7 for i in range(3, count, 4)} for r in range(roots)},
                         'pins': [D.pin(p) for p in (library, registry, genesis)]})
    verifier = N.open_verifier(host_config)
    H.Store.create(output / 'journal', verifier)
    verifier.close()
    config.update(host_config=str(host_config), host_journal=str(output / 'journal'))
    publish(output / 'campaign-config.json', config)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('init', 'run', 'prepare'))
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--request', type=Path)
    args = parser.parse_args()
    if args.action == 'prepare':
        prepare(N.read(args.config), N.read(args.request))
        return 0
    if args.output is None:
        parser.error('run requires --output')
    if args.action == 'init':
        initialize(args.config.resolve(strict=True), args.output.resolve())
        return 0
    return run(args.config.resolve(strict=True), args.output.resolve())


if __name__ == '__main__':
    sys.exit(main())
