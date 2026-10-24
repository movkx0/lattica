#!/usr/bin/env python3
"""Compare three alternating, audited N3/N4 workflow pairs; never promote code.

The manifest names one accepted candidate screening envelope and three pairs:
{"screening": "screen.json", "pairs": [{"baseline": "b1.json", "candidate":
"c1.json"}, {"baseline": "b2.json", "candidate": "c2.json"}, {"baseline":
"b3.json", "candidate": "c3.json"}]}. Paths are relative to the manifest.
Pair order is checked against actual guard timestamps and must alternate.
"""
import argparse
import datetime
import json
import math
import statistics
from pathlib import Path

import opencl_private_spend_validate as guard
import opencl_workflow_metrics as metrics


def load_run(path):
    path = Path(path).resolve()
    report = metrics.audited_metrics(path)
    envelope = json.loads(path.read_text())
    record_path = Path(envelope['guard'])
    guard.require(guard.sha(record_path) == report['provenance']['guard_sha256'],
                  'guard changed while loading comparison')
    record = json.loads(record_path.read_text())
    for key in ('source_inputs_unchanged', 'executable_unchanged', 'service_stop_completed'):
        guard.require(record.get(key) is True, 'comparison lacks terminal evidence: ' + key)
    guard.require('experiments' in record['correctness_result'],
                  'matched comparisons require explicit experiment provenance')
    return {'path': str(path), 'report': report, 'record': record,
            'guard_sha256': report['provenance']['guard_sha256']}


def timestamp(value):
    time = datetime.datetime.fromisoformat(value)
    guard.require(time.tzinfo is not None, 'comparison timestamp lacks timezone')
    return time


def positive(value):
    guard.require(type(value) in (int, float) and math.isfinite(value) and value > 0,
                  'comparison requires finite positive complete workflow timings')
    return value


def comparable(run):
    """Separate experiment selectors/output paths from fixed workflow settings."""
    record, report = run['record'], run['report']
    memory = report['memory']
    limits = {'--host-bytes': 32 << 30, '--device-bytes': 8 << 30,
              '--native-bytes': 24 << 30, '--max-rows': 1 << 20}
    guard.require(memory['driver_limits'] == limits
                  and memory['process_cap_bytes'] == 47 << 30
                  and int(memory['gpu_context_reserve_bytes']) == 4 << 30
                  and int(memory['cgroup_swap_limit_bytes']) == 0,
                  'comparison resource envelope differs from accepted baseline')
    guard.require(report['measurement']['transactions'] == 7
                  and [case['transactions'] for case in report['cases']] == [3, 4],
                  'comparison requires ordered complete N3 and N4 cases')
    positive(report['measurement']['run_wall_seconds'])
    for case in report['cases']:
        positive(case['active_workflow_seconds'])
    start, end = timestamp(record['started_utc']), timestamp(record['finished_utc'])
    guard.require(start < end, 'comparison run timestamps are reversed')
    environment = record['environment']
    guard.require(environment.get('RAYON_NUM_THREADS') == '8'
                  and environment.get('CARGO_BUILD_JOBS') == '2'
                  and record['cpu_quota'] == '800%', 'comparison thread envelope changed')
    device = record['correctness_result']['context']['device']
    guard.require(device.get('name') == 'NVIDIA GeForce RTX 5080', 'comparison device differs')
    ignored = {'--output-dir', '--metadata-capacity', '--registration-telemetry', '--shake-wrappers'}
    argv = record['command'][1:]
    fixed = []
    index = 0
    while index < len(argv):
        if argv[index] in ignored:
            guard.require(index + 1 < len(argv), 'incomplete comparison command')
            index += 2
        else:
            fixed.append(argv[index])
            index += 1
    return {
        'command': fixed, 'source': record['input_sha256'],
        'executable': record['executable_provenance']['sha256'], 'device': device,
        'environment': {k: v for k, v in environment.items()
                        if k.startswith('LATTICA_') or k in ('RAYON_NUM_THREADS', 'CARGO_BUILD_JOBS')},
        'memory_high': record['memory_high_bytes'], 'cpu_quota': record['cpu_quota'],
        'native_by_case': [{k: v for k, v in case['fresh_proofs_by_family'].items() if k != 'outer'}
                           for case in report['cases']],
    }


def compare(screening, pairs):
    guard.require(len(pairs) == 3 and all(set(pair) == {'baseline', 'candidate'} for pair in pairs),
                  'exactly three matched baseline/candidate pairs are required')
    baseline = pairs[0]['baseline']['report']['experiments']
    candidate = pairs[0]['candidate']['report']['experiments']
    defaults = guard.experiment_selection({'command': []})
    guard.require(baseline == defaults, 'baseline must use unchanged default selectors')
    changed = {k for k in set(baseline) | set(candidate) if baseline.get(k) != candidate.get(k)}
    guard.require(changed in ({'metadata_capacity'}, {'shake_wrappers'})
                  and candidate in (dict(defaults, metadata_capacity=512),
                                    dict(defaults, shake_wrappers='paired-v1')),
                  'compare independent protocol-preserving candidates before combination')
    runs = [screening] + [pair[role] for pair in pairs for role in ('baseline', 'candidate')]
    guard.require(len({run['guard_sha256'] for run in runs}) == 7,
                  'screening and repetitions must be seven distinct audited runs')
    guard.require(len({run['record']['raw_log_sha256'] for run in runs}) == 7,
                  'screening and repetitions must have seven distinct complete logs')
    reference = comparable(runs[0])
    for run in runs[1:]:
        guard.require(comparable(run) == reference,
                      'source, binary, device, native workload or resource settings differ')
    guard.require(screening['report']['experiments'] == candidate, 'screening candidate differs')
    previous_end = timestamp(screening['record']['finished_utc'])
    previous_order = None
    orders = []
    for pair in pairs:
        for role, selected in (('baseline', baseline), ('candidate', candidate)):
            guard.require(pair[role]['report']['experiments'] == selected,
                          'experiment selection changed between repetitions')
        order = sorted(pair, key=lambda role: timestamp(pair[role]['record']['started_utc']))
        guard.require(previous_order is None or order != previous_order,
                      'matched pair order must alternate')
        for role in order:
            record = pair[role]['record']
            guard.require(previous_end <= timestamp(record['started_utc']),
                          'screening/pairs overlap or are out of chronological order')
            previous_end = timestamp(record['finished_utc'])
        orders.append(order)
        previous_order = order
    medians = {role: statistics.median(pair[role]['report']['measurement']['run_wall_seconds']
                                    for pair in pairs) for role in ('baseline', 'candidate')}
    case_results = []
    for index, count in enumerate((3, 4)):
        times = {role: statistics.median(pair[role]['report']['cases'][index]['active_workflow_seconds']
                                        for pair in pairs) for role in ('baseline', 'candidate')}
        case_results.append({'transactions': count, 'median_seconds': times,
                             'regression_fraction': times['candidate'] / times['baseline'] - 1,
                             'within_two_percent': times['candidate'] <= times['baseline'] * 1.02})
    speed_pass = medians['candidate'] <= medians['baseline'] * 0.95
    return {'schema': 'pq-ringct-matched-workflow-timing-gate-v1',
            'scope': 'seven_fresh_transactions_complete_N3_N4_workflow',
            'baseline': baseline, 'candidate': candidate, 'pair_orders': orders,
            'median_workflow_seconds': medians,
            'improvement_fraction': 1 - medians['candidate'] / medians['baseline'],
            'at_least_five_percent_faster': speed_pass, 'cases': case_results,
            'timing_criteria_passed': speed_pass and all(c['within_two_percent'] for c in case_results),
            'performance_qualified': False,
            'limitations': ['Timing gate only; component screening, engineering review and campaign acceptance remain separate.',
                            'No automatic promotion, protocol redesign comparison or production throughput claim.'],
            'evidence': [{'envelope': run['path'], 'guard_sha256': run['guard_sha256'],
                          'envelope_sha256': run['report']['provenance']['envelope_sha256']} for run in runs]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path, help='JSON with screening envelope and three baseline/candidate pairs')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    guard.require(set(manifest) == {'screening', 'pairs'}, 'unknown comparison manifest fields')
    def load(path):
        return load_run(args.manifest.parent / path)
    result = compare(load(manifest['screening']),
                     [{role: load(path) for role, path in pair.items()} for pair in manifest['pairs']])
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write('\n')
    print(json.dumps({'output': str(args.output), 'timing_criteria_passed': result['timing_criteria_passed'],
                      'performance_qualified': False}))


if __name__ == '__main__':
    main()
