#!/usr/bin/env python3
"""Audit and compare fresh owned RingCT cases. No proof execution or promotion.

The manifest has schema ringct-owned-workflow-comparison-v1, one screening
sample and three baseline/candidate pairs. Each sample is {"n3": guard.json,
"n4": guard.json}; paths are relative to the manifest. Combined candidates
also name two independently passing comparison manifests in prerequisites.
"""
import argparse
import datetime
import json
import math
from pathlib import Path
import statistics

import full_workflow_case_guard as case_guard
import opencl_private_spend_validate as guard

SCHEMA = 'ringct-owned-workflow-comparison-v1'
BASELINE = {'identity_cpu_workers': 1, 'planning_cache': 'off'}
GIB = 1 << 30


def read_json(path):
    return case_guard.parse_record(Path(path).read_text(), str(path))


def timestamp(value):
    guard.require(type(value) is str, 'missing run timestamp')
    result = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    guard.require(result.tzinfo is not None, 'run timestamp lacks timezone')
    return result


def number(value, name):
    guard.require(type(value) in (int, float) and math.isfinite(value) and value > 0,
                  'invalid positive measurement: ' + name)
    return value


def selection(record):
    expected = record[case_guard.KEY]
    argv = record['command']
    guard.require(len(argv) % 2 == 1 and Path(argv[0]).name == 'pq-ringct-full-workflow',
                  'not an owned workflow command')
    options = dict(zip(argv[1::2], argv[2::2]))
    required = {'--case', '--layout', '--seed', '--context'}
    allowed = required | {'--identity-cpu-workers',
                          '--metadata-cpu-workers', '--planning-cache', '--host-profile'}
    guard.require(len(options) == len(argv) // 2 and required <= options.keys()
                  and options.keys() <= allowed, 'unknown, duplicate or missing case options')
    for key in ('case', 'layout'):
        guard.require(options['--' + key] == expected[key], 'command/case mismatch: ' + key)
    for key in ('seed', 'context'):
        reported = expected['setup_seed' if key == 'seed' else key]
        guard.require(options['--' + key] == bytes(reported).hex(), 'command/input mismatch: ' + key)
    identity = expected.get('identity_cpu')
    width = options.get('--identity-cpu-workers', 'auto')
    metadata = expected.get('metadata_cpu')
    # Old receipts predate the automatic metadata planner. Source/build equality
    # checks already prevent pairing those binaries with a new implementation.
    cache = options.get('--planning-cache', 'geometry-v1' if metadata is not None else 'off')
    guard.require(options.get('--metadata-cpu-workers', 'auto') == 'auto'
                  and (metadata is None and '--metadata-cpu-workers' not in options
                       or metadata == {'requested_workers': None, 'max_workers': 16}),
                  'identity campaigns require matching automatic metadata workers')
    guard.require(width in ('1', '2', '4', '8', '16')
                  and identity == {'requested_workers': int(width), 'max_streams': int(width)},
                  'unsupported CPU worker selection or fewer available physical cores')
    guard.require(record.get('cpu_quota') == '1600%'
                  and record.get('identity_physical_cpus') == record.get('observed_identity_cpu_affinity')
                  and len(record.get('identity_physical_cpus') or []) == 16,
                  'CPU comparisons require the same sixteen-physical-core budget and observed affinity')
    guard.require(cache in ('off', 'geometry-v1') and expected.get('planning_cache', 'off') == cache,
                  'planning cache selection mismatch')
    guard.require(options['--layout'] == 'singleton'
                  and options.get('--host-profile', 'standard') == 'standard'
                  and expected.get('host_profile', 'standard') == 'standard',
                  'campaign requires singleton layout and standard host profile')
    return dict(identity_cpu_workers=int(width), planning_cache=cache)


def terminal(record):
    guard.require(record.get('status') == 'passed' and record.get('error') is None,
                  'run did not complete successfully')
    for key in ('source_inputs_unchanged', 'executable_unchanged',
                'service_stop_completed', 'all_subprocesses_terminal_and_reaped'):
        guard.require(record.get(key) is True, 'missing terminal evidence: ' + key)
    state = record.get('terminal_state') or {}
    guard.require(state.get('Result') == 'success' and state.get('ExecMainStatus') == '0'
                  and state.get('MainPID') == '0' and state.get('ControlPID') == '0',
                  'terminal service state is not a completed success')


def load_case(path):
    """Revalidate the original log, exact dispatch receipts and on-disk artifact."""
    path = Path(path).resolve()
    digest = guard.sha(path)
    record = read_json(path)
    terminal(record)
    guard.require(record.get('schema') == 'pq-opencl-optimization-correctness-job-v2'
                  and record.get('profile') == 'full' and record.get(case_guard.KEY),
                  'not a guarded complete owned case')
    selected = selection(record)
    environment = record['environment']
    required_env = {
        'LATTICA_PROVING_POLICY': 'gpu-required', 'RAYON_NUM_THREADS': '8',
        'CARGO_BUILD_JOBS': '2', 'LATTICA_RINGCT_HOST_PROFILE': 'standard',
        'LATTICA_V2_GPU_MANAGED_BYTES': str(8 * GIB),
        'LATTICA_V2_GPU_CONTEXT_BYTES': str(4 * GIB),
        'LATTICA_V2_HOST_OUTPUT_BYTES': str(24 * GIB),
        'LATTICA_V2_GPU_RETAINED_TREE_STORAGE': 'host',
        'LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES': str(8 * GIB),
        'LATTICA_V2_GPU_LDE_WORKSPACE_BYTES': '0',
        'LATTICA_V2_GPU_PUBLIC_HASH': 'baseline',
    }
    guard.require(all(environment.get(k) == v for k, v in required_env.items()),
                  'owned comparison resource environment differs')
    guard.require(record.get('memory_max_bytes') == 47 * GIB
                  and record.get('memory_high_bytes') == 45 * GIB
                  and record.get('fresh_memavailable_required_bytes') == 49 * GIB
                  and record.get('cpu_quota') == '1600%'
                  and record.get('public_hash_kernel') == 'baseline',
                  'owned comparison resource envelope differs')
    state = record['terminal_state']
    guard.require(state.get('MemorySwapMax') == '0'
                  and state.get('MemoryMax') == str(47 * GIB)
                  and state.get('MemoryHigh') == str(45 * GIB), 'service limits changed')
    peak = int(state.get('MemoryPeak', '-1'))
    guard.require(0 < peak <= 47 * GIB, 'missing or excessive process memory peak')
    device = record.get('full_workflow_device') or {}
    guard.require(device.get('name') == 'NVIDIA GeForce RTX 5080'
                  and device.get('uuid') == environment.get('LATTICA_GPU_DEVICE_UUID')
                  and type(device.get('driver_version')) is str and device['driver_version']
                  and type(device.get('memory_total_mib')) is int and device['memory_total_mib'] > 0,
                  'missing matched physical GPU/driver identity')
    executable = record['executable_provenance']
    build_path = Path(executable['build_record'])
    guard.require(guard.sha(build_path) == executable['build_record_sha256'], 'build record changed')
    build = read_json(build_path)
    terminal(build)
    guard.require(build.get('profile') == 'build'
                  and build.get('input_sha256') == record['input_sha256']
                  and build.get('built_artifact_sha256', {}).get(record['command'][0]) == executable['sha256'],
                  'build/source/binary provenance differs')
    guard.require(guard.sha(build['raw_log']) == build['raw_log_sha256'], 'build log changed')
    raw = Path(record['raw_log'])
    guard.require(guard.sha(raw) == record['raw_log_sha256'], 'case log changed')
    accepted = case_guard.validate_log(raw.read_text(), record, guard.collect_gpu_receipts)
    guard.require(accepted == record.get('full_workflow_case_acceptance'), 'stored case acceptance differs')
    report = accepted['report']
    start, end = timestamp(record['started_utc']), timestamp(record['finished_utc'])
    guard.require(start < end, 'reversed case timestamps')
    number(record['wall_seconds'], 'process wall seconds')
    guard.require(report['complete_workflow_ns'] <= record['wall_seconds'] * 1e9,
                  'workflow exceeds process wall time')
    guard.require(guard.sha(path) == digest and guard.sha(raw) == record['raw_log_sha256'],
                  'record or log changed during audit')
    observed = report['owned_observations']
    metrics = {
        'schema': 'ringct-owned-workflow-metrics-v1', 'case': accepted['case'],
        'selection': selected, 'complete_workflow_ns': report['complete_workflow_ns'],
        'process_wall_seconds': record['wall_seconds'],
        'timings': {
            'generation_and_planning_ns': report['generation_and_planning_ns'],
            'proving_and_verification_ns': report['proving_and_verification_ns'],
            'final_cpu_verification_ns': report['final_cpu_verification_ns'],
            'machine_preprocessing': observed['machine_preprocessing'],
            'machine_proofs': observed['machine_proofs'],
            'native_proofs': observed['native_proofs'],
            'identity_preprocessing': observed.get('identity_preprocessing'),
            'source_geometry_cache': report.get('source_geometry_cache'),
            'cpu_receipts': accepted['receipts']['cpu_verification'],
        },
        'timing_scope': 'Nested receipt durations are attribution, not additive workflow intervals.',
        'memory': {'worker_host_peak_bytes': report['ledger_peak_host_bytes'],
                   'managed_device_peak_bytes': report['ledger_peak_device_bytes'],
                   'process_peak_bytes': peak},
        'proof_counts': {'native': report['native_proofs'], 'recursive': report['recursive_proofs']},
        'proof_rows': {'audit': accepted['receipts']['proof_rows'],
                       'native': [{'entry_point': entry['entry_point'], 'rows': entry['rows']}
                                  for entry in observed['native_proofs']]},
        'artifact_bytes': accepted['artifact']['packet_bytes'],
        'qualification_scope': 'final-aggregate', 'performance_qualified': False,
        'evidence': {'guard': str(path), 'guard_sha256': digest,
                     'raw_log_sha256': record['raw_log_sha256'],
                     'build_record_sha256': executable['build_record_sha256'],
                     'artifact_sha3_256': accepted['artifact']['packet_sha3_256']},
    }
    fixed = {'source': record['input_sha256'], 'binary': executable['sha256'],
             'device': device, 'environment': environment, 'runtime_seconds': record['runtime_seconds'],
             'batch_profile': report['final_qualification']['batch_profile']}
    return {'metrics': metrics, 'fixed': fixed, 'start': start, 'end': end,
            'inputs': {k: accepted[k] for k in ('setup_seed', 'context')}}


def load_sample(paths, base):
    guard.require(type(paths) is dict and set(paths) == {'n3', 'n4'}, 'sample requires N3 and N4')
    cases = [load_case(base / paths[name]) for name in ('n3', 'n4')]
    guard.require([c['metrics']['case'] for c in cases] == ['n3', 'n4'], 'mislabelled sample cases')
    guard.require(cases[0]['end'] <= cases[1]['start'], 'N3/N4 overlap or are reversed')
    guard.require(cases[0]['fixed'] == cases[1]['fixed'], 'N3/N4 fixed settings differ')
    guard.require(cases[0]['metrics']['selection'] == cases[1]['metrics']['selection'], 'N3/N4 selectors differ')
    return cases


def compare(screening, pairs):
    """Compare already audited samples; each sample contains N3 then N4."""
    guard.require(len(pairs) == 3 and all(set(p) == {'baseline', 'candidate'} for p in pairs),
                  'exactly three baseline/candidate pairs required')
    selected = screening[0]['metrics']['selection']
    guard.require(selected != BASELINE, 'screening candidate is the baseline')
    samples = [screening] + [p[role] for p in pairs for role in ('baseline', 'candidate')]
    cases = [case for sample in samples for case in sample]
    for key in ('guard_sha256', 'raw_log_sha256'):
        guard.require(len({c['metrics']['evidence'][key] for c in cases}) == 14, 'reused case evidence: ' + key)
    for case in cases:
        guard.require(case['fixed'] == screening[0]['fixed'], 'source, binary, device or settings differ')
    previous_end = screening[-1]['end']
    previous_order = None
    orders = []
    for pair in pairs:
        for role, choice in (('baseline', BASELINE), ('candidate', selected)):
            for index, case in enumerate(pair[role]):
                guard.require(case['metrics']['selection'] == choice, 'selection changed between repetitions')
                reference = screening[index]
                guard.require(case['inputs'] == reference['inputs'], 'workload seed/context differs')
                guard.require(case['metrics']['proof_counts'] == reference['metrics']['proof_counts']
                              and case['metrics']['proof_rows'] == reference['metrics']['proof_rows'],
                              'proof inventory or geometry differs')
        order = sorted(pair, key=lambda role: pair[role][0]['start'])
        guard.require(previous_order is None or order != previous_order, 'pair order must alternate')
        for role in order:
            guard.require(previous_end <= pair[role][0]['start'], 'screening/pairs overlap or are reordered')
            previous_end = pair[role][-1]['end']
        orders.append(order)
        previous_order = order
    totals = {role: statistics.median(sum(c['metrics']['complete_workflow_ns'] for c in p[role])
                                      for p in pairs) for role in ('baseline', 'candidate')}
    per_case = []
    for i, name in enumerate(('n3', 'n4')):
        medians = {role: statistics.median(p[role][i]['metrics']['complete_workflow_ns'] for p in pairs)
                   for role in ('baseline', 'candidate')}
        per_case.append({'case': name, 'median_ns': medians,
                         'within_two_percent': medians['candidate'] * 100 <= medians['baseline'] * 102})
    faster = totals['candidate'] * 100 <= totals['baseline'] * 95
    return {'schema': 'ringct-owned-workflow-timing-gate-v1', 'selection': selected,
            'scope': 'fresh_N3_N4_generation_through_retirement', 'pair_orders': orders,
            'screening_started_utc': screening[0]['start'].isoformat(),
            'completed_utc': previous_end.isoformat(),
            'median_workflow_ns': totals, 'cases': per_case,
            'improvement_fraction': 1 - totals['candidate'] / totals['baseline'],
            'at_least_five_percent_faster': faster,
            'timing_criteria_passed': faster and all(c['within_two_percent'] for c in per_case),
            'peak_host_bytes': max(c['metrics']['memory']['process_peak_bytes']
                                   for p in pairs for c in p['candidate']),
            'performance_qualified': False,
            'limitations': ['Timing gate only; no automatic default or production promotion.'],
            'evidence': [c['metrics']['evidence'] for c in cases]}


def compare_manifest(path, seen=None):
    path = Path(path).resolve()
    seen = set() if seen is None else set(seen)
    guard.require(path not in seen and len(seen) < 3, 'cyclic or excessive prerequisite manifests')
    seen.add(path)
    manifest = read_json(path)
    guard.require(type(manifest) is dict and manifest.get('schema') == SCHEMA
                  and {'schema', 'screening', 'pairs'} <= manifest.keys()
                  and manifest.keys() <= {'schema', 'screening', 'pairs', 'prerequisites'},
                  'invalid owned comparison manifest')
    screening = load_sample(manifest['screening'], path.parent)
    guard.require(type(manifest['pairs']) is list and len(manifest['pairs']) == 3,
                  'exactly three pairs required')
    pairs = []
    for pair in manifest['pairs']:
        guard.require(type(pair) is dict and set(pair) == {'baseline', 'candidate'}, 'invalid pair')
        pairs.append({role: load_sample(pair[role], path.parent) for role in pair})
    result = compare(screening, pairs)
    selected = result['selection']
    prerequisites = manifest.get('prerequisites', [])
    combined = selected['planning_cache'] == 'geometry-v1' and selected['identity_cpu_workers'] != 1
    guard.require(type(prerequisites) is list and len(prerequisites) == (2 if combined else 0),
                  'combined candidate requires two independent qualified comparisons')
    prior = [compare_manifest(path.parent / item, seen) for item in prerequisites]
    if combined:
        expected = [dict(BASELINE, planning_cache='geometry-v1'), dict(selected, planning_cache='off')]
        guard.require(all(p['timing_criteria_passed'] for p in prior)
                      and sorted((p['selection'] for p in prior), key=lambda v: v['planning_cache'])
                      == sorted(expected, key=lambda v: v['planning_cache']),
                      'combined candidate lacks passing independent changes')
        guard.require(all(p['comparison_identity'] == result_identity(screening) for p in prior),
                      'prerequisites used different sources, hardware or workloads')
        guard.require(all(timestamp(p['completed_utc']) <= screening[0]['start'] for p in prior),
                      'combined screening preceded independent comparisons')
    result['comparison_identity'] = result_identity(screening)
    result['prerequisites'] = [str((path.parent / p).resolve()) for p in prerequisites]
    return result


def result_identity(sample):
    return {'fixed': sample[0]['fixed'], 'inputs': [c['inputs'] for c in sample]}


def select_candidate(results):
    """Within 2% of the fastest passing result, prefer RAM then smaller width."""
    passing = [r for r in results if r['timing_criteria_passed']]
    guard.require(passing, 'no candidate passed the timing gate')
    guard.require(all(r['comparison_identity'] == passing[0]['comparison_identity'] for r in passing),
                  'cannot rank different campaigns')
    fastest = min(r['median_workflow_ns']['candidate'] for r in passing)
    tied = [r for r in passing if r['median_workflow_ns']['candidate'] * 100 <= fastest * 102]
    return min(tied, key=lambda r: (r['peak_host_bytes'], r['selection']['identity_cpu_workers'],
                                    r['median_workflow_ns']['candidate'], r['selection']['planning_cache']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('audit', 'compare', 'select'))
    parser.add_argument('inputs', nargs='+', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.mode == 'select':
        result = select_candidate([compare_manifest(p) for p in args.inputs])
    else:
        guard.require(len(args.inputs) == 1, 'audit/compare requires one input')
        result = load_case(args.inputs[0])['metrics'] if args.mode == 'audit' else compare_manifest(args.inputs[0])
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'output': str(args.output), 'performance_qualified': False}))


if __name__ == '__main__':
    main()
