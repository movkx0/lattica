#!/usr/bin/env python3
"""Audit typed scheduler plans and durable recovery using retained real proofs.

This launches only the CPU diagnostic commands. It does not prove new nodes,
start workers, apply native blocks, or qualify delivered throughput.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def read(path):
    return json.loads(path.read_bytes())


def pin(path):
    path = path.resolve(strict=True)
    with path.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': digest}


def write(path, value):
    with path.open('x') as target:
        json.dump(value, target, indent=2, sort_keys=True)
        target.write('\n')


def qualify(args, result):
    out = args.output.resolve()
    binary = args.cpu_binary.resolve(strict=True)
    matrix = read(args.count_matrix)
    inputs = {}

    def retain(path):
        value = pin(path)
        inputs[value['path']] = value

    def fixture(directory, expected):
        count = read(expected)['count']
        for name in ('body.json', 'height.json', *(f'key.{i}' for i in range(1, 13)),
                     *(f'wallet.{i}' for i in range(count))):
            retain(directory / name)
        retain(expected)

    retain(binary)
    retain(Path(__file__))
    retain(args.count_matrix)
    trials = {}
    for trial in matrix['trials']:
        trials.setdefault(trial['count'], trial)
    counts = [1, 2, 3, 4, 8, 16, 32, 63, 64]
    if set(trials) != set(counts):
        raise ValueError('retained matrix must contain all nine expected counts')
    plans = []
    for count in counts:
        config_path = Path(trials[count]['config_source']['path'])
        if pin(config_path) != trials[count]['config_source']:
            raise ValueError('retained matrix configuration changed')
        config = read(config_path)
        if config['construction'] != 'paired':
            raise ValueError('retained matrix requires the paired construction')
        directory, expected = Path(config['fixture']), Path(config['expected'])
        if read(expected)['count'] != count:
            raise ValueError('retained matrix count mismatch')
        retain(config_path)
        fixture(directory, expected)
        plans.append((count, directory, expected))

    roots = []
    for label in ('first', 'second', 'third', 'alternate-second'):
        directory = args.native_campaign / f'{label}-fixture'
        manifest = read(directory / 'manifest.json')
        expected = directory / 'expected.json'
        nodes = args.native_campaign / f'{label}-root' / '001-typed' / 'proofs'
        fixture(directory, expected)
        retain(directory / 'manifest.json')
        for node in sorted(nodes.glob('node.*')):
            retain(node)
        roots.append((label, directory, expected, nodes, manifest['parent_head_token']))
    write(out / 'inputs.json', list(inputs.values()))
    result['input_manifest'] = pin(out / 'inputs.json')
    result['binary'] = pin(binary)
    env = {k: v for k, v in os.environ.items() if not k.startswith(('LATTICA_', 'RAYON_'))}
    env['RAYON_NUM_THREADS'] = '2'
    result['rayon_threads'] = 2

    def run(label, command):
        log = out / f'{label}.log'
        entry = {'command': [str(p) for p in command], 'label': label}
        result['commands'].append(entry)
        started = time.monotonic()
        with log.open('x') as target:
            try:
                process = subprocess.run(entry['command'], env=env, stdout=target,
                                         stderr=subprocess.STDOUT, timeout=600)
                entry['exit_code'] = process.returncode
            except subprocess.TimeoutExpired:
                entry['exit_code'] = 124
        entry['elapsed_seconds'] = time.monotonic() - started
        entry['log'] = pin(log)
        if entry['exit_code']:
            raise ValueError(f'{label} failed: {entry["exit_code"]}; see {log}')
        print(f'{label}: passed', flush=True)

    for count, directory, expected in plans:
        label = f'plan-{count:02d}'
        target = out / f'{label}.json'
        run(label, [binary, 'execution-plan', directory, expected, target])
        plan = read(target)
        if (plan['count'] != count or not plan['cpu_leaf_verified']
                or plan['prover_jobs_started'] != 0 or plan['production_ready']):
            raise ValueError('unexpected typed plan result')
        result['plans'].append({'count': count, 'jobs': len(plan['jobs']), 'result': pin(target)})

    for label, directory, expected, nodes, head in roots:
        target = out / f'audit-{label}'
        run(f'audit-{label}', [binary, 'execution-audit', directory, expected, nodes, head, target])
        summary = read(target / 'summary.json')
        if (summary['status'] != 'succeeded' or not summary['artifact_replay_only']
                or summary['prover_jobs_started'] != 0 or summary['native_blocks_applied'] != 0
                or summary['production_ready']):
            raise ValueError('unexpected typed replay result')
        result['audits'].append({'label': label, **summary, 'result': pin(target / 'summary.json')})
    for value in inputs.values():
        if pin(Path(value['path'])) != value:
            raise ValueError('input changed during typed execution audit')
    result['inputs_unchanged'] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cpu-binary', type=Path, required=True)
    parser.add_argument('--native-campaign', type=Path, required=True)
    parser.add_argument('--count-matrix', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    result = {'schema_version': 1, 'record_type': 'typed_execution_replay_qualification',
              'status': 'running', 'started_ns': time.time_ns(), 'commands': [], 'plans': [],
              'audits': [], 'artifact_replay_only': True, 'prover_jobs_started': 0,
              'native_blocks_applied': 0, 'production_ready': False}
    try:
        qualify(args, result)
        result['status'] = 'succeeded'
    except Exception as error:
        result['status'] = 'failed'
        result['error'] = f'{type(error).__name__}: {error}'
    finally:
        result['finished_ns'] = time.time_ns()
        write(args.output / 'summary.json', result)
    print(json.dumps({'status': result['status'], 'summary': str(args.output / 'summary.json'),
                      'plans': len(result['plans']), 'audits': len(result['audits'])}))
    return 0 if result['status'] == 'succeeded' else 1


if __name__ == '__main__':
    sys.exit(main())
