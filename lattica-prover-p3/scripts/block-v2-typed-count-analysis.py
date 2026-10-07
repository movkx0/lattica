#!/usr/bin/env python3
"""Revalidate a count-matrix snapshot and retain measured stage costs.

This reads existing results only. It never launches proving, changes a frozen
controller, or qualifies complete transaction delivery from recursive timings.
"""

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import statistics


ORIGINS = {'fresh_matrix_trial', 'retained_and_revalidated'}


def read(path):
    return json.loads(path.read_text())


def pin(path):
    return {'path': str(path.resolve()), 'bytes': path.stat().st_size,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def controller(path):
    spec = importlib.util.spec_from_file_location('count_matrix_analysis_controller', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def positive_number(value, label):
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise ValueError(f'invalid {label}')
    return value


def accounting(trials):
    groups = {origin: [] for origin in ORIGINS}
    identities = set()
    for trial in trials:
        identity = (trial['count'], trial['gpu_uuid'])
        if identity in identities:
            raise ValueError('duplicate count/device trial')
        identities.add(identity)
        if trial.get('origin') not in groups or trial.get('cpu_audited') is not True:
            raise ValueError('trial lacks an audited origin')
        if type(trial.get('fresh_proofs')) is not int or trial['fresh_proofs'] <= 0:
            raise ValueError('invalid recursive proof count')
        groups[trial['origin']].append(trial)
    new = groups['fresh_matrix_trial']
    prior = groups['retained_and_revalidated']
    return {
        'new_cpu_audited_roots': len(new),
        'new_recursive_proofs': sum(t['fresh_proofs'] for t in new),
        'revalidated_prior_roots': len(prior),
        'recursive_proofs_in_prior_roots': sum(t['fresh_proofs'] for t in prior),
        'total_covered_roots': len(trials),
        'recursive_proofs_in_all_covered_roots': sum(t['fresh_proofs'] for t in trials),
    }


def stage_costs(plan, log, proving_seconds):
    """Require one measured node per exact planned proof, in recorded order."""
    positive_number(proving_seconds, 'proving duration')
    stages, complete = [], []
    for line in log.splitlines():
        if not line.startswith('{'):
            continue
        row = json.loads(line)
        if row.get('event') == 'fresh_typed_node':
            stages.append(row)
        elif row.get('event') == 'typed_gpu_work_complete':
            complete.append(row)
    tasks = plan['tasks']
    if len(stages) != plan['fresh_proofs'] or len(stages) != len(tasks):
        raise ValueError('measured stages do not cover the proof plan')
    if (len(complete) != 1 or complete[0].get('recursive_proofs') != len(tasks)
            or complete[0].get('cpu_only') is not False):
        raise ValueError('missing or inconsistent GPU work completion')
    completion_seconds = positive_number(complete[0].get('seconds'), 'work completion')
    by_mode = defaultdict(list)
    names = set()
    for task, stage in zip(tasks, stages):
        for key in ('level', 'index', 'count', 'mode', 'bytes'):
            if type(stage.get(key)) is not int or stage[key] < 0:
                raise ValueError('invalid stage identity')
        name = f"node.{stage['level']}.{stage['index']}"
        if name in names or (name, stage['count'], stage['mode']) != (
                task['file'], task['count'], task['mode']):
            raise ValueError('measured stage differs from ordered proof plan')
        names.add(name)
        by_mode[stage['mode']].append(positive_number(stage.get('seconds'), 'stage duration'))
    total = sum(sum(values) for values in by_mode.values())
    if total > completion_seconds + 0.01 or completion_seconds > proving_seconds + 0.01:
        raise ValueError('nested stage timings exceed their enclosing duration')
    modes = []
    for mode, values in sorted(by_mode.items()):
        reused = values[1:]
        modes.append({
            'mode': mode, 'proofs': len(values), 'total_seconds': sum(values),
            'share_of_measured_node_seconds': sum(values) / total,
            'first_observed_seconds': values[0],
            'subsequent_proofs': len(reused),
            'subsequent_median_seconds': statistics.median(reused) if reused else None,
            'subsequent_min_seconds': min(reused) if reused else None,
            'subsequent_max_seconds': max(reused) if reused else None,
        })
    return {'measured_node_seconds': total, 'work_completion_seconds': completion_seconds,
            'outside_node_timers_seconds': proving_seconds - total, 'modes': modes,
            'stages': stages,
            'interpretation': 'First and subsequent nodes differ in inputs and may differ in level. '
                              'Their timing difference does not isolate setup cost or prove a speedup.'}


def analyze(snapshot, module):
    if snapshot.get('schema') != 'lattica-typed-count-matrix-v1':
        raise ValueError('unrecognized count matrix schema')
    if snapshot.get('status') not in ('running', 'failed', 'succeeded'):
        raise ValueError('unsupported matrix status')
    for flag in ('cold_full64_qualified', 'post_seal_qualified',
                 'delivered_transactions_measured', 'production_ready'):
        if snapshot.get(flag) is not False:
            raise ValueError(f'count matrix cannot qualify {flag}')
    module.T.check_pins(snapshot['input_pins'])
    trials = snapshot['trials']
    totals = accounting(trials)
    coverage = module.coverage(snapshot['counts'], snapshot['gpu_uuids'], trials)
    if coverage != snapshot['coverage']:
        raise ValueError('recorded coverage differs from count/device results')
    rows = []
    for trial in trials:
        directory = Path(trial['summary_source']['path']).parent
        checked = module.checked_trial(directory, snapshot['construction'], snapshot['profile'],
                                        snapshot['gpu_sha256'], snapshot['cpu_sha256'],
                                        snapshot['fixture_pins'])
        if checked != {k: v for k, v in trial.items() if k != 'origin'}:
            raise ValueError('retained count trial changed')
        log_path = directory / '001-typed/prove.log'
        plan_path = directory / 'plan.json'
        body_path = directory / '001-typed/root-only/body.json'
        body = read(body_path)
        kinds = Counter(item['kind'] for item in body['transactions'][:trial['count']])
        if (sum(kinds.values()) != trial['count'] or
                set(kinds) - {'joinsplit', 'htlc_redeem', 'htlc_refund', 'issuance'}):
            raise ValueError('incomplete audited public transaction mix')
        positive_number(trial['worker_seconds'], 'worker duration')
        useful = trial['count'] - kinds['issuance']
        rows.append({
            **{k: trial[k] for k in ('count', 'gpu_uuid', 'origin', 'worker_seconds',
                'proving_seconds', 'cpu_audit_seconds', 'fresh_proofs', 'root_bytes',
                'root_sha256', 'peak_charged_ram_bytes', 'budget', 'context_measurement')},
            'mix': dict(kinds), 'useful_fixture_inputs': useful,
            'useful_fixture_inputs_per_minute': 60 * useful / trial['worker_seconds'],
            'stage_costs': stage_costs(read(plan_path), log_path.read_text(), trial['proving_seconds']),
            'sources': [pin(log_path), pin(plan_path), pin(body_path),
                        trial['result_source'], trial['summary_source']],
        })
    if snapshot['status'] == 'succeeded':
        if (not coverage['all_requested_counts_passed'] or snapshot.get('input_pins_unchanged') is not True
                or snapshot.get('cpu_audited_roots') != totals['total_covered_roots']
                or snapshot.get('fresh_recursive_proofs') != totals['recursive_proofs_in_all_covered_roots']):
            raise ValueError('final matrix accounting is incomplete or inconsistent')
    return {
        'schema_version': 1, 'record_type': 'typed_count_matrix_analysis',
        'captured_utc': datetime.now(timezone.utc).isoformat(),
        'status': snapshot['status'], 'coverage': coverage, 'proof_accounting': totals,
        'active_trial': {k: snapshot.get('active_trial', {}).get(k)
                         for k in ('count', 'gpu_uuid')} if snapshot.get('active_trial') else None,
        'construction': snapshot['construction'], 'gpu_sha256': snapshot['gpu_sha256'],
        'cpu_sha256': snapshot['cpu_sha256'], 'profile_sha256': snapshot['profile_sha256'],
        'rows': rows, 'failure': snapshot.get('failure'),
        'delivered_transactions_measured': False, 'cold_full64_qualified': False,
        'post_seal_qualified': False, 'production_ready': False,
        'scope': 'One recorded trial per count/device. Fresh matrix work and revalidated prior roots '
                 'are counted separately. Rates cover recursive work on preproved fixture inputs, '
                 'fixture copying and CPU root audit; wallet proving, registry preparation and '
                 'durable host application are excluded. This is not repeated timing qualification.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--summary', type=Path, required=True)
    parser.add_argument('--controller', type=Path, required=True,
                        help='frozen count controller and its sibling dependencies')
    parser.add_argument('--output', type=Path, required=True, help='new directory; never overwritten')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    snapshot_path = args.output / 'matrix-summary.json'
    snapshot_path.write_bytes(args.summary.read_bytes())
    module = controller(args.controller.resolve())
    try:
        data = analyze(read(snapshot_path), module)
    except Exception as error:
        data = {'schema_version': 1, 'record_type': 'typed_count_matrix_analysis',
                'status': 'validation_failed', 'failure': f'{type(error).__name__}: {error}',
                'delivered_transactions_measured': False, 'production_ready': False}
    data['matrix_snapshot_source'] = pin(snapshot_path)
    data['analysis_sources'] = [pin(Path(__file__)), pin(args.controller)]
    output = args.output / 'analysis.json'
    output.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': data['status'], 'output': str(output),
                      'coverage': data.get('coverage'), 'proof_accounting': data.get('proof_accounting'),
                      'failure': data.get('failure')}))
    return int(data['status'] == 'validation_failed')


if __name__ == '__main__':
    raise SystemExit(main())
