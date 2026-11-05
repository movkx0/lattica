#!/usr/bin/env python3
"""Re-audit completed fresh cases and compare balanced full-workflow runs."""
import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import statistics

import full_workflow_case_guard as case_guard
import full_workflow_profiling as profiling
from opencl_private_spend_validate import collect_gpu_receipts
from owned_workflow_benchmark import terminal


def require(value, message):
    if not value:
        raise ValueError('workflow comparison: ' + message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def utilization(record):
    """Summarize external samples; their clock and GPU scope differ from the case."""
    evidence = record.get('full_workflow_telemetry')
    if evidence is None:
        return None
    path = Path(evidence['path'])
    require(digest(path) == evidence['sha256'], 'telemetry changed')
    samples = [json.loads(line) for line in path.read_text().splitlines()]
    require(len(samples) == evidence['samples'], 'telemetry sample count changed')
    previous = None
    cpu = []
    gpu_weighted = gpu_observed_ns = 0
    host_peak = gpu_peak = None
    for sample in samples:
        now = sample['since_start_ns']
        require(type(now) is int and now >= 0 and (previous is None or now > previous),
                'nonmonotonic telemetry')
        require(sample['schema'] == 'ringct-workflow-telemetry-v1', 'telemetry schema')
        if 'cpu_usage_usec' in sample:
            usage = sample['cpu_usage_usec']
            require(type(usage) is int and usage >= 0 and (not cpu or usage >= cpu[-1][1]),
                    'nonmonotonic CPU counter')
            cpu.append((now, usage))
        if 'memory_peak_bytes' in sample:
            memory = sample['memory_peak_bytes']
            require(type(memory) is int and memory >= 0, 'invalid host memory sample')
            host_peak = memory if host_peak is None else max(host_peak, memory)
        gpu = sample.get('gpu', {})
        busy = gpu.get('utilization.gpu')
        if busy is not None:
            require(type(busy) in (int, float) and math.isfinite(busy) and 0 <= busy <= 100,
                    'invalid GPU utilization')
            if previous is not None:
                duration = now - previous
                gpu_weighted += busy * duration
                gpu_observed_ns += duration
        memory = gpu.get('memory.used')
        if memory is not None:
            require(type(memory) in (int, float) and math.isfinite(memory) and memory >= 0,
                    'invalid GPU memory sample')
            gpu_peak = memory if gpu_peak is None else max(gpu_peak, memory)
        previous = now
    window_ns = samples[-1]['since_start_ns'] - samples[0]['since_start_ns'] if len(samples) > 1 else 0
    cpu_ns = cpu[-1][0] - cpu[0][0] if len(cpu) > 1 else 0
    return dict(samples=len(samples), window_seconds=window_ns / 1e9,
                mean_cpu_cores=(cpu[-1][1] - cpu[0][1]) * 1000 / cpu_ns if cpu_ns else None,
                whole_device_gpu_mean_percent=gpu_weighted / gpu_observed_ns if gpu_observed_ns else None,
                gpu_observation_fraction=gpu_observed_ns / window_ns if window_ns else None,
                host_peak_bytes=host_peak, whole_device_gpu_peak_mib=gpu_peak,
                samples_with_errors=evidence['samples_with_errors'], write_error=evidence['write_error'],
                scope='External sampler window, including launch and cleanup; GPU measurements cover the whole device. '
                      'Weighted sampled utilization is not a proof-stage duration or promotion criterion.')


def read_record(path):
    """Historical binaries may be gone; bind their recorded digests to the build."""
    path = Path(path).resolve()
    record = json.loads(path.read_text())
    require(record.get('status') == 'passed' and record.get('profile') == 'full',
            'only completed full-profile cases can be compared')
    terminal(record)
    for key in ('source_inputs_unchanged', 'executable_unchanged',
                'all_subprocesses_terminal_and_reaped', 'service_stop_completed'):
        require(record.get(key) is True, 'missing terminal provenance: ' + key)
    provenance = record['executable_provenance']
    build_path = Path(provenance['build_record'])
    require(digest(build_path) == provenance['build_record_sha256'], 'build record changed')
    build = json.loads(build_path.read_text())
    require(build['status'] == 'passed' and build['input_sha256'] == record['input_sha256'],
            'run is not bound to its successful source build')
    require(build['built_artifact_sha256'].get(provenance['resolved_path']) == provenance['sha256'],
            'executable differs from the recorded build')
    log = Path(record['raw_log'])
    require(digest(log) == record['raw_log_sha256'], 'raw log changed')
    accepted = case_guard.validate_log(log.read_text(), record, collect_gpu_receipts)
    require(accepted == record['full_workflow_case_acceptance'], 'saved acceptance changed')
    require(accepted['workflow_profile'] is not None, 'case has no complete workflow profile')
    return path, record, accepted


def identity_cpu_cost(report, total_ns):
    identity = report['owned_observations'].get('identity_preprocessing', {})
    # A cohort's worker sum measures parallel work, not time on the serial
    # workflow path. GPU analysis has its own clock and is excluded here.
    wall_ns = identity.get('hash_wall_ns', 0) + identity.get('finalization_ns', 0)
    return dict(kind='nested_operation', name='cpu_identity', seconds=wall_ns / 1e9,
                fraction=wall_ns / total_ns)


def identity_cpu_breakdown(content):
    """Optional detail clocks cover serial identities, excluding cohort prefixes."""
    count = fields = count_ns = hash_ns = total_ns = 0
    for line in content.splitlines():
        if not line.startswith('bounded_cpu_identity_hash '):
            continue
        values = dict(re.findall(r'(\w+)=([^ ]+)', line))
        require(set(values) == {'fields', 'count_ns', 'hash_and_framing_ns', 'total_ns'}
                and all(value.isdecimal() for value in values.values()), 'invalid CPU identity detail')
        values = {key: int(value) for key, value in values.items()}
        require(values['fields'] > 0 and values['total_ns'] > 0
                and values['count_ns'] + values['hash_and_framing_ns'] == values['total_ns'],
                'CPU identity detail clocks do not reconcile')
        count += 1
        fields += values['fields']
        count_ns += values['count_ns']
        hash_ns += values['hash_and_framing_ns']
        total_ns += values['total_ns']
    if not count:
        return None
    return dict(measurements=count, fields=fields, total_seconds=total_ns / 1e9,
                count_seconds=count_ns / 1e9, hash_and_framing_seconds=hash_ns / 1e9,
                count_fraction=count_ns / total_ns,
                scope='Detailed serial identity calls only; cohort prefixes and suffix-only finalization are excluded.')


def quotient_compilation_cost(content, total_ns):
    """Compiler wall intervals are nested in proof time, never added to it."""
    elapsed_ns = measured = selected = rejected = unmeasured = 0
    source_builds = {}
    for line in content.splitlines():
        if not line.startswith('bounded_gpu_quotient_specialization '):
            continue
        fields = dict(re.findall(r'(\w+)=([^ ]+)', line))
        require(fields.get('selected') in ('true', 'false'), 'invalid quotient compiler selection')
        selected += fields['selected'] == 'true'
        rejected += fields['selected'] == 'false'
        if 'build_ns' in fields:
            require(fields['build_ns'].isdecimal(), 'invalid quotient compiler duration')
            elapsed_ns += int(fields['build_ns'])
            measured += 1
        else:
            unmeasured += 1
        if 'source_sha3' in fields:
            key = fields['source_sha3']
            require(re.fullmatch(r'[0-9a-f]{64}', key) is not None, 'invalid compiler source digest')
            require('build_ns' in fields, 'compiler source digest has no wall clock')
            source_builds.setdefault(key, []).append(int(fields['build_ns']))
    return dict(kind='nested_operation', name='gpu_quotient_compilation',
                seconds=elapsed_ns / 1e9, fraction=elapsed_ns / total_ns,
                measured_builds=measured, selected_builds=selected, rejected_builds=rejected,
                builds_without_wall_clock=unmeasured, lower_bound=bool(unmeasured),
                distinct_observed_sources=len(source_builds),
                repeated_source_builds=sum(len(values) - 1 for values in source_builds.values()),
                source_build_seconds={key: [ns / 1e9 for ns in values]
                                      for key, values in source_builds.items()},
                source_note='Repeated source digests identify identical compiler input; no driver cache-hit or miss is inferred.')


def describe(path, record, accepted):
    report = accepted['report']
    profile = report['workflow_profile']
    total = profile['total_ns']
    phases = [dict(phase=phase, seconds=ns / 1e9, fraction=ns / total)
              for phase, ns in zip(profile['phase_order'], profile['phase_ns'])]
    groups = [dict(group=group, completed=row['completed'], seconds=row['elapsed_ns'] / 1e9,
                   fraction=row['elapsed_ns'] / total)
              for group, row in zip(profile['groups'], profile['execution']) if row['completed']]
    candidates = [dict(kind='phase', name=row['phase'], fraction=row['fraction'], seconds=row['seconds'])
                  for row in phases if row['phase'] != 'execution' and row['fraction'] >= .10]
    candidates += [dict(kind='execution_group', name=row['group'], fraction=row['fraction'],
                        seconds=row['seconds']) for row in groups if row['fraction'] >= .10]
    identity = identity_cpu_cost(report, total)
    if identity['fraction'] >= .10:
        candidates.append(identity)
    content = Path(record['raw_log']).read_text()
    compilation = quotient_compilation_cost(content, total)
    if compilation['fraction'] >= .10:
        candidates.append(compilation)
    return dict(record=str(path), record_sha256=digest(path), case=accepted['case'],
                complete_workflow_seconds=total / 1e9, phases=phases, execution_groups=groups,
                eligible_costs=sorted(candidates, key=lambda row: row['seconds'], reverse=True),
                identity_cpu=identity,
                identity_cpu_detail=identity_cpu_breakdown(content),
                quotient_compilation=compilation,
                native_input_seconds=[row['elapsed_ns'] / 1e9 for row in profile['native_inputs']
                                      if row['completed']],
                generation=report['generation'], metadata_wall=report['metadata_wall'],
                owned_observations=report['owned_observations'],
                source_preparation=report['source_preparation'],
                final_cpu_verification_seconds=report['final_cpu_verification_ns'] / 1e9,
                source_geometry_cache=report['source_geometry_cache'],
                native_metadata_cache=report['native_metadata_cache'],
                native_proofs=report['native_proofs'], recursive_proofs=report['recursive_proofs'],
                completed_phases=report['completed_phases'],
                ledger_peak_host_bytes=report['ledger_peak_host_bytes'],
                ledger_peak_device_bytes=report['ledger_peak_device_bytes'],
                telemetry=record.get('full_workflow_telemetry'), utilization=utilization(record),
                clock_note='Phase wall clocks partition the total. Execution groups, device time and metadata detail are nested observations.')


def compare(pairs):
    """Pairs hold audited records in their actual launch order, not sorted times."""
    require(len(pairs) == 8, 'need four pairs for each of N3 and N4')
    by_case = {'n3': [], 'n4': []}
    seen = set()
    sources, binaries, configurations = {}, {}, {}
    windows = []
    for pair in pairs:
        case, order, runs = pair['case'], pair['order'], pair['runs']
        require(case in by_case and order in (['baseline', 'candidate'], ['candidate', 'baseline']),
                'invalid case or run order')
        require(set(runs) == {'baseline', 'candidate'}, 'pair must contain both variants')
        first, second = (runs[name] for name in order)
        require(first['finished_utc'] <= second['started_utc'], 'record order differs from manifest')
        for variant, run in runs.items():
            require(run['record'] not in seen, 'a case run was reused')
            seen.add(run['record'])
            require(run['case'] == case and run['mode'] == 'summary', 'wrong case or timing mode')
            require(run['total_ns'] > 0, 'empty workflow duration')
            key = (variant, case)
            require(key not in configurations or configurations[key] == run['workers'],
                    'worker configuration changed within a case comparison')
            configurations[key] = run['workers']
            for registry, key in ((sources, 'source'), (binaries, 'binary')):
                require(variant not in registry or registry[variant] == run[key],
                        variant + ' changed during comparison')
                registry[variant] = run[key]
            windows.append((run['started_utc'], run['finished_utc']))
        baseline, candidate = runs['baseline'], runs['candidate']
        for key in ('case', 'workload', 'layout', 'host_profile', 'device', 'runtime', 'inventory'):
            require(baseline[key] == candidate[key], 'pair differs in ' + key)
        by_case[case].append(dict(order=order, workload=baseline['workload'],
                                  records={name: dict(path=run['record'], sha256=run['record_sha256'])
                                           for name, run in runs.items()},
                                  ratio=candidate['total_ns'] / baseline['total_ns'],
                                  baseline_seconds=baseline['total_ns'] / 1e9,
                                  candidate_seconds=candidate['total_ns'] / 1e9))
    windows.sort()
    require(all(start < end for start, end in windows), 'invalid run interval')
    require(all(left[1] <= right[0] for left, right in zip(windows, windows[1:])),
            'comparison runs overlapped')
    result = {}
    for case, values in by_case.items():
        require(len(values) == 4, 'case is missing comparison pairs')
        workloads = {tuple(row['workload']) for row in values}
        require(len(workloads) == 2, 'need two distinct public workloads')
        for workload in workloads:
            orders = [row['order'][0] for row in values if tuple(row['workload']) == workload]
            require(sorted(orders) == ['baseline', 'candidate'], 'workload/run orders are unbalanced')
        ratio = statistics.median(row['ratio'] for row in values)
        orders = {first: statistics.median(row['ratio'] for row in values if row['order'][0] == first)
                  for first in ('baseline', 'candidate')}
        limit = .95 if case == 'n4' else 1.03
        result[case] = dict(pairs=values, median_paired_ratio=ratio,
                            median_reduction=1 - ratio, ratios_by_first_variant=orders,
                            meets_promotion_gate=ratio <= limit and all(value <= limit for value in orders.values()))
    return dict(schema='ringct-full-workflow-comparison-v1', cases=result,
                binaries=binaries,
                source_manifest_sha256={name: hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest()
                                        for name, source in sources.items()},
                primary_metric='Complete fresh workflow wall time, including native transaction generation.',
                eligible_for_promotion=all(row['meets_promotion_gate'] for row in result.values()),
                n4_target_met=result['n4']['median_paired_ratio'] <= .90,
                note='Four fresh pairs per case; medians are observations, not confidence bounds. Individual guard receipts remain screening qualifications.')


def comparison_run(path, record, accepted):
    report = accepted['report']
    expected = record['full_workflow_case_environment']
    # Cargo paths differ by checkout. Worker choices may differ by selected stage.
    runtime = {key: value for key, value in record['environment'].items()
               if key.startswith('LATTICA_') or key == 'RAYON_NUM_THREADS'}
    runtime.pop('LATTICA_RINGCT_FULL_WORKFLOW_PROFILE', None)
    return dict(record=str(path), record_sha256=digest(path), case=accepted['case'], mode=expected['workflow_profile'],
                total_ns=report['complete_workflow_ns'],
                workers=[expected['identity_cpu'], expected['metadata_cpu']],
                workload=[bytes(accepted['setup_seed']).hex(), bytes(accepted['context']).hex()],
                layout=accepted['layout'], host_profile=expected['host_profile'],
                device=record['full_workflow_device'], runtime=runtime,
                inventory=[report[key] for key in ('transactions', 'native_proofs', 'recursive_proofs', 'completed_phases')],
                source=record['input_sha256'], binary=record['executable_provenance']['sha256'],
                started_utc=datetime.fromisoformat(record['started_utc']),
                finished_utc=datetime.fromisoformat(record['finished_utc']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--record', type=Path, action='append', default=[])
    parser.add_argument('--pairs', type=Path,
                        help='JSON list with case, order and records mapping baseline/candidate to receipt paths')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    require(bool(args.record) != bool(args.pairs), 'choose records or a comparison manifest')
    if args.pairs:
        pairs = json.loads(args.pairs.read_text())
        for pair in pairs:
            pair['runs'] = {name: comparison_run(*read_record(path))
                            for name, path in pair['records'].items()}
        result = compare(pairs)
    else:
        result = dict(schema='ringct-full-workflow-cost-report-v1',
                      cases=[describe(*read_record(path)) for path in args.record])
    rendered = json.dumps(result, indent=2, allow_nan=False) + '\n'
    if args.output:
        with args.output.open('x') as output:
            output.write(rendered)
    else:
        print(rendered, end='')


if __name__ == '__main__':
    main()
