#!/usr/bin/env python3
"""Compare row and gathered query readback with one binary and fixed resources.

Each arm produces a fresh root and independent CPU audit. Wallet proving,
registration and durable application are excluded from the worker boundary.
"""
import argparse
import copy
import importlib.util
import json
import math
import os
from pathlib import Path
import shlex
import statistics
import sys
import time

SPEC = importlib.util.spec_from_file_location('typed_compare', Path(__file__).with_name('block-v2-typed-compare.py'))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
T = C.T
LAYOUTS = ('rows', 'gather')


def validate_profiles(profiles):
    if set(profiles) != set(LAYOUTS):
        raise ValueError('row/gather profiles are both required')
    normalized = []
    for layout in LAYOUTS:
        profile = copy.deepcopy(profiles[layout])
        if T.R.query_readback_layout(profile) != layout:
            raise ValueError('query profile does not match its arm')
        profile['geometry'].pop('query_readback_layout', None)
        normalized.append(profile)
    if normalized[0] != normalized[1]:
        raise ValueError('comparison profiles may differ only in query readback layout')


def query_checkpoints(log, layout):
    checkpoints = []
    for line in log.read_text().splitlines():
        if not line.startswith('bounded_gpu_query_checkpoint '):
            continue
        values = dict(token.split('=', 1) for token in shlex.split(line)[1:])
        if values.get('gather') != str(layout == 'gather').lower() or values.get('counters') != 'cumulative':
            raise ValueError('query checkpoint mode differs from the pinned profile')
        counts = {key: int(values[key]) for key in
                  ('calls', 'tiles', 'readbacks', 'downloaded_bytes', 'gather_device_ns', 'wall_ns')}
        if any(value < 0 for value in counts.values()):
            raise ValueError('invalid query checkpoint counter')
        if counts['calls']:
            if not counts['tiles'] or not counts['readbacks'] or not counts['downloaded_bytes']:
                raise ValueError('query reconstruction counters are incomplete')
            if layout == 'gather' and counts['readbacks'] != counts['tiles']:
                raise ValueError('gather must download exactly once per reconstructed tile')
        checkpoints.append({'label': values['label'], **counts})
    if not checkpoints or not any(c['calls'] for c in checkpoints):
        raise ValueError('query reconstruction was not observed')
    return checkpoints


def checked_trial(directory, construction, count, assignment, assignment_sha, gpu_sha, cpu_sha, profile, layout):
    trial = C.checked_trial(directory, construction, count, assignment, assignment_sha, gpu_sha)
    config = json.loads((directory / 'config.json').read_text())
    result = json.loads((directory / '001-typed/result.json').read_text())
    T.check_pins(config['pins'])
    if (config['workload'] != profile or result['profile_sha256'] != T.G.profile_digest(config)
            or T.G.digest(config['cpu_binary']) != cpu_sha
            or result['budget'].get('query_readback_layout', 'rows') != layout):
        raise ValueError('trial query profile or CPU auditor differs from its arm')
    trial.update(query_readback_layout=layout, profile_sha256=result['profile_sha256'],
                 binary_sha256=gpu_sha, cpu_binary_sha256=cpu_sha,
                 config_source=C.pin(directory / 'config.json'),
                 query_checkpoints=query_checkpoints(directory / '001-typed/prove.log', layout))
    return trial


def pair_measurement(number, trials):
    if len(trials) != 2 or [t['query_readback_layout'] for t in trials] != list(C.trial_order(number, *LAYOUTS)):
        raise ValueError('a query pair requires both layouts in the prescribed order')
    seconds = {t['query_readback_layout']: t['worker_seconds'] for t in trials}
    if any(type(s) not in (int, float) or not math.isfinite(s) or s <= 0 for s in seconds.values()):
        raise ValueError('query comparison timing must be positive and finite')
    return {'pair': number, 'order': [t['query_readback_layout'] for t in trials],
            'worker_seconds': seconds,
            'worker_reduction_percent': (1 - seconds['gather'] / seconds['rows']) * 100}


def aggregate(pairs):
    if not pairs:
        return None
    reductions = [p['worker_reduction_percent'] for p in pairs]
    return {'matched_pairs': len(pairs),
            'median_worker_seconds': {layout: statistics.median(p['worker_seconds'][layout] for p in pairs) for layout in LAYOUTS},
            'median_within_pair_reduction_percent': statistics.median(reductions),
            'within_pair_reduction_range_percent': [min(reductions), max(reductions)],
            'gather_faster_pairs': sum(value > 0 for value in reductions)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('gpu-binary', 'cpu-binary', 'fixture', 'rows-workload', 'gather-workload', 'evidence'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--gpu-uuid', required=True)
    parser.add_argument('--construction', choices=T.CONSTRUCTIONS, default='paired')
    parser.add_argument('--ram-admission', choices=('full','compact'), default='compact')
    parser.add_argument('--count', type=int, choices=T.COUNTS, default=4)
    parser.add_argument('--pairs', type=int, default=5)
    parser.add_argument('--trial-timeout', type=int, default=1800)
    parser.add_argument('--scratch', type=Path, default=Path('/tmp'))
    args = parser.parse_args()
    if not 1 <= args.pairs <= 10 or args.trial_timeout <= 0:
        parser.error('pairs must be 1 through 10 and timeout must be positive')
    os.umask(0o077)
    out = args.evidence.resolve()
    out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    report = {'schema': 'lattica-typed-query-comparison-v1', 'status': 'preparing',
              'construction': args.construction, 'count': args.count, 'requested_pairs': args.pairs,
              'baseline_query_layout': 'rows', 'candidate_query_layout': 'gather',
              'trials': [], 'pairs': [], 'active_trial': None, 'production_ready': False,
              'delivered_transactions_measured': False,
              'timing_boundary': 'Worker fixture copy, fresh recursive proving and independent CPU root audit. Wallet proving, registration and durable application excluded.'}
    try:
        workloads = {layout: getattr(args, layout + '_workload').resolve(strict=True) for layout in LAYOUTS}
        profiles = {layout: T.resource_profile(path, args.construction, args.ram_admission) for layout, path in workloads.items()}
        validate_profiles(profiles)
        fixture = args.fixture.resolve(strict=True)
        gpu, cpu = args.gpu_binary.resolve(strict=True), args.cpu_binary.resolve(strict=True)
        inputs = [Path(__file__), Path(C.__file__), Path(T.__file__), Path(T.G.__file__), Path(T.R.__file__),
                  gpu, cpu, *workloads.values(), *T.fixture_files(fixture, args.count, args.construction)]
        pins = dict(T.pin(p) for p in inputs)
        report.update(input_pins=pins, gpu_sha256=T.G.digest(gpu), cpu_sha256=T.G.digest(cpu),
                      profiles=profiles, profile_sha256={k: T.G.profile_digest({'workload': v}) for k,v in profiles.items()})
        locks = T.G.lock_fleet()
        try:
            if json.loads(T.G.systemctl('list-units', 'lattica-v2-multi-*.service', '--state=active,activating,deactivating', '--output=json', '--no-pager')):
                raise ValueError('another GPU worker is active')
            T.G.systemctl('start', T.G.SLICE)
            host = T.G.detect_worker_host(str(args.scratch.resolve(strict=True)))
            devices = [d for d in T.R.detect_gpus(str(gpu)) if d['uuid'] == args.gpu_uuid]
            if len(devices) != 1:
                raise ValueError('comparison GPU UUID was not uniquely detected')
            budget = T.assigned_budget(host, devices[0], profiles['rows'])
            assignment = T.comparison_assignment(budget, profiles['rows'])
            for profile in profiles.values():
                T.apply_resource_assignment(T.assigned_budget(host, devices[0], profile), assignment, profile)
            T.G.durable(out / 'initial-admission.json', {'host': host, 'device': devices[0], 'profiles': profiles}, True)
            assignment_path = out / 'resource-assignment.json'
            T.G.durable(assignment_path, assignment, True)
        finally:
            for lock in locks:
                os.close(lock)
        pins.update(dict([T.pin(assignment_path)]))
        report.update(status='running', resource_assignment=C.pin(assignment_path))
        T.G.durable(out / 'summary.json', report)
        for number in range(1, args.pairs + 1):
            pair = []
            for layout in C.trial_order(number, *LAYOUTS):
                T.check_pins(pins)
                directory = out / f'pair-{number:02d}-{layout}'
                command = [sys.executable, str(Path(T.__file__)), '--construction', args.construction,
                           '--ram-admission', args.ram_admission, '--gpu-binary', str(gpu), '--cpu-binary', str(cpu),
                           '--fixture', str(fixture), '--gpu-uuid', args.gpu_uuid, '--count', str(args.count),
                           '--scratch', str(args.scratch.resolve()), '--workload', str(workloads[layout]),
                           '--resource-assignment', str(assignment_path), '--evidence', str(directory)]
                report['active_trial'] = {'pair': number, 'query_readback_layout': layout, 'command': command}
                T.G.durable(out / 'summary.json', report)
                print(json.dumps({'event': 'trial_started', 'pair': number, 'layout': layout}), flush=True)
                C.execute_controller(command, out / f'pair-{number:02d}-{layout}.controller.log', args.trial_timeout)
                T.check_pins(pins)
                trial = checked_trial(directory, args.construction, args.count, assignment,
                                      report['resource_assignment']['sha256'], report['gpu_sha256'],
                                      report['cpu_sha256'], profiles[layout], layout)
                trial['pair'] = number
                report['trials'].append(trial)
                pair.append(trial)
                report['active_trial'] = None
                T.G.durable(out / 'summary.json', report)
                print(json.dumps({'event': 'trial_succeeded', 'pair': number, 'layout': layout,
                                  'worker_seconds': trial['worker_seconds']}), flush=True)
            report['pairs'].append(pair_measurement(number, pair))
            report['comparison'] = aggregate(report['pairs'])
            T.G.durable(out / 'summary.json', report)
        T.check_pins(pins)
        report.update(status='succeeded', input_pins_unchanged=True, repeat_qualified=args.pairs >= 5,
                      cpu_audited_roots=len(report['trials']),
                      fresh_recursive_proofs=sum(t['fresh_proofs'] for t in report['trials']))
    except BaseException as error:
        report.update(status='failed', failure=f'{type(error).__name__}: {error}')
    finally:
        report['controller_elapsed_seconds'] = time.monotonic() - started
        T.G.durable(out / 'summary.json', report)
        print(json.dumps({'status': report['status'], 'completed_pairs': len(report['pairs']),
                          'completed_trials': len(report['trials'])}), flush=True)
    return 0 if report['status'] == 'succeeded' else 1


if __name__ == '__main__':
    sys.exit(main())
