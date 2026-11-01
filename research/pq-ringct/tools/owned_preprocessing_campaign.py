#!/usr/bin/env python3
"""Plan or run one fresh N3/N4 sample through the existing serialized guard.

Default is plan-only. Execution requires a same-source CPU source-matrix record
and the guard's exclusive window. Neither a source screen nor this launcher
grants complete admission or performance qualification.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

import opencl_private_spend_validate as guard
import owned_workflow_benchmark as benchmark

SELECTOR = ('graph_crypto::prover::paired::tests::full_workflow::identity_matrix::'
            'full_workflow_identity_source_admission_matrix')
SIXTEEN_SELECTOR = ('graph_crypto::prover::paired::tests::full_workflow::identity_matrix::'
                    'full_workflow_identity_width_sixteen_source_admission')
WIDTHS = (1, 2, 4, 8, 16)
SOURCE_SCHEDULES = {SELECTOR: WIDTHS, SIXTEEN_SELECTOR: (16,)}
CONFIGURATIONS = {
    'baseline': dict(benchmark.BASELINE),
    'geometry': dict(benchmark.BASELINE, planning_cache='geometry-v1'),
    **{f'cpu-{width}': dict(benchmark.BASELINE, identity_cpu_workers=width) for width in WIDTHS},
    **{f'geometry-cpu-{width}': dict(identity_cpu_workers=width, planning_cache='geometry-v1') for width in WIDTHS},
}


def source_matrix(path, selected, build_label):
    """Re-read the exact source screen, preserving refusals and scope limits."""
    record = benchmark.read_json(path)
    benchmark.terminal(record)
    guard.require(record.get('profile') == 'research-compile-large'
                  and record.get('expect_tests') is True
                  and record.get('environment', {}).get('LATTICA_PROVING_POLICY') == 'cpu-required',
                  'source matrix needs the CPU research compiler guard')
    command = record.get('command', [])
    guard.require(len(command) == 6 and command[1] in SOURCE_SCHEDULES
                  and command[2:] == ['--exact', '--ignored', '--nocapture', '--test-threads=1'],
                  'source matrix selector differs')
    schedules = SOURCE_SCHEDULES[command[1]]
    guard.require(selected['identity_cpu_workers'] in schedules,
                  'source screen does not cover selected width')
    raw = Path(record['raw_log'])
    guard.require(guard.sha(raw) == record['raw_log_sha256'], 'source matrix log changed')
    content = raw.read_text()
    guard.require(len(re.findall(r'^test result: ok\. 1 passed; 0 failed;.*$', content, re.M)) == 1,
                  'source matrix did not execute exactly one passing test')
    guard.require(not any(marker in content for marker in (
        'PUBLIC_HASH_EXECUTION', 'proving_stage_report ', 'RINGCT_FULL_WORKFLOW_CASE ', 'owned_generation_report ')),
        'CPU source matrix emitted GPU/workflow evidence')
    prefix = 'IDENTITY_SOURCE_MATRIX '
    rows = [benchmark.case_guard.parse_record(line[len(prefix):], prefix)
            for line in content.splitlines() if line.startswith(prefix)]
    expected = [(n, width) for n in (3, 4) for width in schedules]
    guard.require(len(rows) == len(expected), f'source screen must contain all {len(expected)} rows')
    fingerprint = rows[0].get('compiled_source_fingerprint')
    benchmark.case_guard.digest_bytes(fingerprint, 'source matrix fingerprint')
    accepted = []
    for row, (n, width) in zip(rows, expected):
        guard.require(row.get('schema') == 'ringct-cpu-identity-source-matrix-v1'
                      and row.get('transactions') == n and row.get('fixture_count') == n
                      and row.get('first_fixture') == (0 if n == 3 else 3)
                      and row.get('layout') == 'singleton'
                      and row.get('identity_cpu') == {'requested_workers': width, 'max_streams': width}
                      and row.get('compiled_source_fingerprint') == fingerprint,
                      'source matrix inventory/order differs')
        guard.require(row.get('worker_host_bytes') == 32 << 30 and row.get('managed_device_bytes') == 8 << 30
                      and row.get('terminal_empty') is True and row.get('complete_workflow_admitted') is False
                      and type(row.get('gpu_dispatches')) is int and row['gpu_dispatches'] == 0
                      and type(row.get('stark_proofs')) is int and row['stark_proofs'] == 0,
                      'source matrix scope, limits or cleanup differ')
        peak = benchmark.case_guard.natural(row.get('source_claim_peak_host_bytes'), 'source peak', positive=True)
        guard.require(peak <= 32 << 30, 'source matrix exceeded worker bound')
        compilers = benchmark.case_guard.natural(row.get('peak_compilers'), 'peak compilers')
        guard.require(compilers <= width, 'source matrix compiler cohort exceeds ceiling')
        compiler_host = benchmark.case_guard.natural(row.get('peak_retained_compiler_host_bytes'), 'retained compilers')
        prefix_host = benchmark.case_guard.natural(row.get('peak_prefix_incremental_host_bytes'), 'incremental prefixes')
        borrowed_host = benchmark.case_guard.natural(row.get('peak_prefix_borrowed_program_host_bytes'), 'borrowed programs')
        construction_host = benchmark.case_guard.natural(row.get('compiler_construction_ceiling_bytes'), 'compiler construction', positive=True)
        guard.require(construction_host == 2 << 30
                      and compiler_host <= peak and borrowed_host <= compiler_host
                      and prefix_host <= 24 << 30
                      and (width != 1 or prefix_host == borrowed_host == 0),
                      'source matrix compiler/prefix accounting differs')
        admitted = row.get('source_lifetimes_admitted')
        guard.require(type(admitted) is bool and ((admitted and row.get('refusal') is None)
                      or (not admitted and type(row.get('refusal')) is str and row['refusal'])),
                      'source matrix omitted an admission/refusal result')
        if width == selected['identity_cpu_workers']:
            guard.require(admitted and row.get('requests', 0) > 0, 'selected source geometry was refused')
            guard.require(compiler_host > 0 and (width == 1 or prefix_host > 0 and borrowed_host > 0),
                          'selected source memory census is missing')
            accepted.append(row)
    guard.require(len(accepted) == 2, 'source screen needs admitted N3 and N4 rows for selected width')
    build_path = guard.STATE / 'runs' / (build_label + '.json')
    build = benchmark.read_json(build_path)
    benchmark.terminal(build)
    guard.require(build.get('profile') == 'build'
                  and build['input_sha256'] == record['input_sha256'] == guard.source_manifest(),
                  'source matrix, workflow build and current sources differ')
    provenance = record['executable_provenance']
    test_build = benchmark.read_json(provenance['build_record'])
    guard.require(guard.sha(provenance['build_record']) == provenance['build_record_sha256']
                  and test_build['input_sha256'] == record['input_sha256']
                  and test_build.get('built_artifact_sha256', {}).get(command[0]) == provenance['sha256'],
                  'source matrix executable/build binding differs')
    benchmark.terminal(test_build)
    guard.require(guard.sha(test_build['raw_log']) == test_build['raw_log_sha256'], 'source matrix build log changed')
    return {'record': str(Path(path).resolve()), 'sha256': guard.sha(path),
            'selected_rows': accepted, 'complete_workflow_admitted': False}


def commands(args):
    guard.require(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,51}', args.label), 'unsafe sample label')
    guard.require(all(re.fullmatch('[0-9a-f]{64}', value) for value in (args.seed, args.context)),
                  'seed/context require canonical 64-digit lowercase hex')
    guard.require(1 <= args.seconds <= 86400, 'case runtime exceeds the full profile')
    selected = CONFIGURATIONS[args.configuration]
    executable = guard.ROOT / '.tools/target-opencl/release/pq-ringct-full-workflow'
    result = []
    for case in ('n3', 'n4'):
        command = [sys.executable, str(Path(guard.__file__).resolve()), '--profile', 'full',
                   '--label', args.label + '-' + case, '--seconds', str(args.seconds),
                   '--full-workflow-case', '--retained-tree-storage', 'host',
                   '--public-hash-kernel', 'baseline', '--host-profile', 'standard',
                   '--device-uuid', args.device_uuid, '--build-label', args.build_label]
        if args.execute:
            command += ['--execute', '--exclusive-window']
        command += ['--', str(executable), '--case', case, '--layout', 'singleton',
                    '--seed', args.seed, '--context', args.context,
                    '--identity-cpu-workers', str(selected['identity_cpu_workers']),
                    '--metadata-cpu-workers', 'auto',
                    '--planning-cache', selected['planning_cache'], '--host-profile', 'standard']
        result.append(command)
    return result


def combination_prerequisites(paths, selected, build_label, device_uuid, seed, context):
    combined = selected['planning_cache'] == 'geometry-v1' and selected['identity_cpu_workers'] != 1
    guard.require(len(paths) == (2 if combined else 0),
                  'combined execution requires two independent comparison manifests')
    if not combined:
        return []
    reports = [benchmark.compare_manifest(path) for path in paths]
    expected = [dict(benchmark.BASELINE, planning_cache='geometry-v1'), dict(selected, planning_cache='off')]
    guard.require(all(report['timing_criteria_passed'] for report in reports)
                  and sorted((r['selection'] for r in reports), key=lambda r: r['planning_cache'])
                  == sorted(expected, key=lambda r: r['planning_cache']),
                  'independent geometry/CPU concurrency comparisons did not pass')
    build = benchmark.read_json(guard.STATE / 'runs' / (build_label + '.json'))
    executable = str(guard.ROOT / '.tools/target-opencl/release/pq-ringct-full-workflow')
    for report in reports:
        identity = report['comparison_identity']
        guard.require(identity['fixed']['source'] == build['input_sha256']
                      and identity['fixed']['binary'] == build['built_artifact_sha256'][executable]
                      and identity['fixed']['device']['uuid'] == device_uuid
                      and identity['inputs'] == [{'setup_seed': list(bytes.fromhex(seed)),
                                                  'context': list(bytes.fromhex(context))}] * 2,
                      'combination prerequisites differ from selected source, binary, device or inputs')
    return [{'manifest': str(Path(path).resolve()), 'sha256': guard.sha(path)} for path in paths]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configuration', choices=CONFIGURATIONS, required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--build-label', required=True)
    parser.add_argument('--device-uuid', required=True)
    parser.add_argument('--seed', required=True)
    parser.add_argument('--context', required=True)
    parser.add_argument('--seconds', type=int, default=86400)
    parser.add_argument('--source-matrix', type=Path)
    parser.add_argument('--prerequisite-comparison', action='append', default=[], type=Path)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--exclusive-window', action='store_true')
    args = parser.parse_args()
    argv = commands(args)
    admission = None
    prerequisites = []
    if args.execute:
        guard.require(args.exclusive_window and args.source_matrix,
                      'execution requires the CPU source matrix and exclusive window')
        admission = source_matrix(args.source_matrix, CONFIGURATIONS[args.configuration], args.build_label)
        prerequisites = combination_prerequisites(args.prerequisite_comparison, CONFIGURATIONS[args.configuration],
                                                  args.build_label, args.device_uuid, args.seed, args.context)
    print(json.dumps({'schema': 'ringct-owned-preprocessing-sample-v1',
                      'configuration': CONFIGURATIONS[args.configuration], 'commands': argv,
                      'source_matrix': admission, 'prerequisites': prerequisites,
                      'performance_qualified': False}), flush=True)
    # Each subprocess owns the original guard's lock, admission and cleanup.
    # N4 never starts after an unsuccessful N3; labels cannot overwrite evidence.
    for command in argv:
        result = subprocess.run(command, cwd=guard.ROOT)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
