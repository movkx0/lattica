#!/usr/bin/env python3
"""Bounded v2 GPU private-spend and STARK correctness jobs. Historical v1 audits use opencl_opt_validate.py. Never runs comparison baselines.

Planning is the default. Execution requires a coordinator-owned exclusive
window; all subprocesses run in a transient, swap-free systemd user service.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[3]
STATE = ROOT / '.tools/pq-opencl-opt'
GIB = 1 << 30
PROFILES = {
    'build': (8, 6, 10, 2, 7200),
    'smoke': (16, 14, 20, 4, 7200),
    'full': (47, 45, 49, 8, 86400),
}
GPU_SWITCHES = (
    'HASH', 'RETAIN_TREES', 'QUERY_GATHER', 'RESIDENT_LDE', 'OPENINGS',
    'QUOTIENT_FUSION', 'QUOTIENT_LDE', 'QUOTIENT_EVAL', 'QUOTIENT_RESIDENT',
    'LOOKUP', 'OPENING_EVAL', 'FRI_RESIDENT', 'PCS_DEVICE_ONLY', 'WITNESS',
    'RANDOMNESS', 'TRANSCRIPT', 'FRI_FOLD',
)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def command(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=30)


def systemd_state(unit):
    properties = ['LoadState', 'ActiveState', 'SubState', 'MainPID', 'ControlPID',
                  'ControlGroup', 'Result', 'ExecMainCode', 'ExecMainStatus',
                  'MemoryMax', 'MemoryHigh', 'MemorySwapMax', 'MemoryPeak', 'NRestarts']
    response = command(['/usr/bin/systemctl', '--user', 'show', unit]
                       + ['--property=' + prop for prop in properties])
    require(response.returncode == 0, 'cannot inspect service: ' + response.stderr)
    return dict(line.split('=', 1) for line in response.stdout.splitlines() if '=' in line)


def source_manifest():
    paths = set()
    for directory in [ROOT / 'lattica-prover-p3/src', ROOT / 'lattica-prover-p3/vendor',
                      ROOT / 'research']:
        paths.update(path for path in directory.rglob('*')
                     if path.is_file() and '__pycache__' not in path.parts
                     and 'target' not in path.parts and '.tools' not in path.relative_to(ROOT).parts)
    for name in ['Cargo.toml', 'Cargo.lock', 'build.rs']:
        paths.add(ROOT / 'lattica-prover-p3' / name)
    return {str(path.relative_to(ROOT)): sha(path) for path in sorted(paths)}


def admission_helpers():
    # Reuse only read-only workload/memory inspection; do not call the historical
    # runner's baseline gate, build planner, executor, or acceptance validator.
    path = Path(__file__).with_name('opencl_qualify.py')
    spec = importlib.util.spec_from_file_location('opencl_readonly_admission', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_plan(args):
    require(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,55}', args.label), 'unsafe run label')
    maximum, high, admission, threads, runtime = PROFILES[args.profile]
    require(1 <= args.seconds <= runtime, 'runtime exceeds selected correctness profile')
    argv = list(args.command)
    if argv and argv[0] == '--':
        argv.pop(0)
    require(argv and Path(argv[0]).is_absolute(), 'command needs an absolute executable path')
    require(not (args.expect_tests and args.expect_result), 'choose one acceptance output')
    benchmark = getattr(args, 'benchmark', False)
    correctness_label = getattr(args, 'correctness_label', None)
    require(benchmark == ('--benchmark' in argv), 'runner and driver benchmark flags must agree')
    require(not benchmark or (args.profile == 'full' and args.expect_result and correctness_label),
            'benchmark requires full result validation and --correctness-label')
    require(not correctness_label or (benchmark and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,55}', correctness_label)),
            'correctness label requires benchmark mode and a safe label')
    require(not args.build_label or re.fullmatch(r'[a-z0-9][a-z0-9-]{0,55}', args.build_label),
            'unsafe build label')
    require(not args.expect_result or args.build_label, 'final driver requires --build-label')
    require(not args.record_artifact or (args.profile == 'build' and Path(argv[0]).name == 'cargo'
            and (argv[1:2] == ['build'] or (argv[1:2] == ['test'] and '--no-run' in argv))),
            '--record-artifact requires a Cargo build or test --no-run build profile')
    if args.expect_result:
        experiment_selection({'command': argv})
    require(all(Path(path).is_absolute() for path in args.record_artifact),
            'recorded artifact paths must be absolute')
    require(not args.expect_tests or Path(argv[0]).name == 'cargo' or args.build_label,
            'direct test executables require --build-label')
    environment = {
        'PATH': '/home/access/code/lattica/.tools/rust-1.96.0/bin:/usr/bin:/bin',
        'HOME': '/home/access',
        'CARGO_HOME': str(ROOT / '.tools/cargo-opencl'),
        'CARGO_TARGET_DIR': str(ROOT / '.tools/target-opencl'),
        'CARGO_BUILD_JOBS': '2', 'RAYON_NUM_THREADS': str(threads),
        'LATTICA_PROVING_REPORT': '1',
        'LATTICA_PROVING_POLICY': 'cpu-required' if args.profile == 'build' else 'gpu-required',
    }
    if args.profile != 'build':
        for switch in GPU_SWITCHES:
            prefix = 'LATTICA_V2_' if switch == 'QUOTIENT_FUSION' else 'LATTICA_V2_GPU_'
            environment[prefix + switch] = '1'
        environment.update(LATTICA_V2_GPU_DEVICE='0',
                           LATTICA_V2_GPU_MANAGED_BYTES=str(8 * GIB),
                           LATTICA_V2_GPU_CONTEXT_BYTES=str(4 * GIB),
                           LATTICA_V2_HOST_OUTPUT_BYTES=str((32 if args.profile == 'full' else 8) * GIB))
    if args.expect_tests and args.profile != 'build':
        environment['LATTICA_NATIVE_SPEND_QUALIFICATION'] = '1'
    return {'schema': 'pq-opencl-optimization-correctness-job-v2', 'label': args.label,
            'profile': args.profile, 'command': argv, 'environment': environment,
            'memory_max_bytes': maximum * GIB, 'memory_high_bytes': high * GIB,
            'fresh_memavailable_required_bytes': admission * GIB,
            'cpu_quota': str(threads * 100) + '%', 'runtime_seconds': args.seconds,
            'comparison_baseline': False, 'performance_qualified': False,
            'benchmark': benchmark, 'correctness_label': correctness_label,
            'expect_tests': args.expect_tests, 'expect_result': args.expect_result,
            'build_label': args.build_label, 'record_artifacts': args.record_artifact,
            'launch': False, 'status': 'planned'}


def executable_provenance(plan, sources, runs):
    executable = Path(plan['command'][0])
    require(executable.is_file() and os.access(executable, os.X_OK), 'executable is absent')
    identity = {'path': str(executable), 'resolved_path': str(executable.resolve()),
                'sha256': sha(executable)}
    if executable.name == 'cargo':
        response = command([str(executable), '--version'])
        require(response.returncode == 0, 'cannot identify Cargo executable')
        identity['cargo_version'] = response.stdout.strip()
    if plan['build_label']:
        record_path = runs / (plan['build_label'] + '.json')
        record = json.loads(record_path.read_text())
        require(record.get('status') == 'passed' and record.get('profile') == 'build'
                and record.get('source_inputs_unchanged') is True
                and record.get('all_subprocesses_terminal_and_reaped') is True
                and record.get('input_sha256') == sources,
                'executable build record does not match these sources')
        require(record.get('built_artifact_sha256', {}).get(str(executable)) == identity['sha256'],
                'executable differs from recorded build artifact')
        identity.update(build_record=str(record_path), build_record_sha256=sha(record_path))
    return identity


def requested_counts(plan):
    argv = plan['command']
    require(argv.count('--counts') == 1, 'benchmark needs one explicit --counts')
    index = argv.index('--counts')
    require(index + 1 < len(argv) and argv[index + 1] in ('3', '4', '3,4'),
            'invalid benchmark counts')
    return {int(v) for v in argv[index + 1].split(',')}


def driver_limits(plan):
    argv = plan['command']
    limits = {}
    for option in ('--host-bytes', '--device-bytes', '--max-rows', '--native-bytes'):
        require(argv.count(option) == 1, 'measurement needs one explicit ' + option)
        index = argv.index(option)
        require(index + 1 < len(argv), 'missing ' + option)
        value = int(argv[index + 1])
        require(value > 0, 'invalid ' + option)
        limits[option] = value
    return limits


def experiment_selection(plan):
    """Bind independently selected experiments to correctness and measurement."""
    argv = plan['command']
    choices = {
        '--metadata-capacity': ('256', '512'),
        '--registration-telemetry': ('off', 'bounded'),
        '--shake-wrappers': ('singleton', 'paired-v1'),
    }
    selected = {}
    for option, allowed in choices.items():
        require(not any(arg.startswith(option + '=') for arg in argv),
                'use a separate value for ' + option)
        require(argv.count(option) <= 1, 'duplicate ' + option)
        value = allowed[0]
        if option in argv:
            index = argv.index(option)
            require(index + 1 < len(argv), 'missing ' + option)
            value = argv[index + 1]
        require(value in allowed, 'unsupported ' + option)
        selected[option[2:].replace('-', '_')] = int(value) if option == '--metadata-capacity' else value
    selected['prepared_reuse'] = 'single_entry'
    return selected


def validate_experiments(result, plan):
    expected = experiment_selection(plan)
    baseline = experiment_selection({'command': []})
    # Historical baseline results predate these optional selectors. A candidate
    # must always report its exact selection; absence cannot mean a fallback.
    actual = result.get('experiments', baseline)
    require(actual == expected, 'driver experiment selection differs from command')
    if 'experiments' in result:
        require(set(actual) == set(baseline), 'unknown experiment report fields')
        require(type(actual['metadata_capacity']) is int, 'invalid metadata capacity report')
        context = result.get('context', {})
        require(context.get('maximum_metadata_entries') == actual['metadata_capacity'],
                'context metadata capacity differs from selection')
        for case in result.get('cases', []):
            require(case.get('experiments') == actual, 'case experiment selection differs')
    else:
        require(expected == baseline, 'candidate result omitted experiment selection')


def prior_correctness(plan, sources, executable, runs):
    """Replay complete acceptance before launch; a build/unit pass is insufficient."""
    label = plan['correctness_label']
    record_path, log_path = runs / (label + '.json'), runs / (label + '.log')
    record = json.loads(record_path.read_text())
    require(record.get('schema') == 'pq-opencl-optimization-correctness-job-v2'
            and record.get('status') == 'passed' and record.get('error') is None
            and record.get('profile') == 'full' and record.get('expect_result') is True
            and not record.get('benchmark', False)
            and record.get('source_inputs_unchanged') is True
            and record.get('executable_unchanged') is True
            and record.get('all_subprocesses_terminal_and_reaped') is True,
            'benchmark requires a terminal complete correctness pass')
    require(record.get('input_sha256') == sources
            and record.get('executable_provenance') == executable,
            'prior correctness source/executable/build provenance differs')
    require(record.get('environment') == plan['environment']
            and driver_limits(record) == driver_limits(plan),
            'prior correctness resource/thread/GPU limits differ')
    require(experiment_selection(record) == experiment_selection(plan),
            'prior correctness experiment selection differs')
    require(record.get('raw_log') == str(log_path)
            and log_path.is_file() and sha(log_path) == record.get('raw_log_sha256'),
            'prior correctness log changed')
    content = log_path.read_text(errors='replace')
    results = [json.loads(line.removeprefix('OPENCL_OPT_RESULT '))
               for line in content.splitlines() if line.startswith('OPENCL_OPT_RESULT ')]
    require(len(results) == 1 and results[0] == record.get('correctness_result'),
            'prior correctness result differs from its log')
    result = results[0]
    validate_result(result)
    validate_experiments(result, record)
    require(not result.get('benchmark_measured', False), 'prior run must be correctness mode')
    receipts = validate_receipts(content, result)
    require(receipts == record.get('receipt_acceptance'), 'prior receipt acceptance differs')
    counts = {case['count'] for case in result['cases']}
    require(requested_counts(plan) <= counts, 'requested count lacks a prior correctness pass')
    build_path = Path(executable['build_record'])
    require(sha(build_path) == executable['build_record_sha256'], 'prior executable build record changed')
    return {'record': str(record_path), 'record_sha256': sha(record_path),
            'log': str(log_path), 'log_sha256': sha(log_path),
            'build_record': str(build_path), 'build_record_sha256': sha(build_path),
            'executable_sha256': executable['sha256'],
            'source_manifest_sha256': hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest(),
            'validated_counts': sorted(counts), 'driver_limits': driver_limits(record),
            'device': result['context'].get('device'), 'receipt_acceptance': receipts}


def validate_receipts(content, result):
    """Require complete native and recursive GPU proof receipts; reject CPU proving."""
    # Pin each API's actual contract, rather than trusting a receipt's claim of
    # completeness for an arbitrarily shortened capability inventory.
    native_stages = {'public_values', 'witness_trace', 'preprocessing', 'transform',
                     'quotient', 'randomness', 'hiding', 'commitment', 'opening',
                     'fri_fold', 'fri_query', 'final_polynomial', 'scalar',
                     'transcript', 'grinding'}
    machine = {
        'block_v2_preprocessing': (
            'preprocessing', {'preprocessing', 'randomness', 'transform', 'commitment'}),
        'block_v2_registered_program': (
            'registered_proof', (native_stages - {'public_values'}) | {'lookup'}),
    }
    native_entries = {
        'pq_statement', 'pq_private_source',
        'matrict_affine_gpu', 'matrict_ntt_gpu', 'matrict_mul_gpu',
        'matrict_g_bound_gpu', 'matrict_permutation_gpu', 'matrict_linear_map_gpu',
        'pq_aes_lane_native', 'pq_shake_segment_native',
        'pq_aes_wide_native', 'pq_shake_wide_native',
        'pq_uniform_gpu', 'pq_sparse_gpu', 'pq_transcript_source',
    }
    counts = dict.fromkeys(machine, 0)
    native_reports = 0
    private_spend_reports = 0
    private_spend_completed = 0
    private_spend_devices = 0
    preparation_reports = 0
    preparation_completed = 0
    preparation_devices = 0
    for line in content.splitlines():
        if not line.startswith('proving_stage_report '):
            continue
        report = json.loads(line.removeprefix('proving_stage_report '))
        entry = report.get('entry_point')
        policy = report.get('policy')
        require(report.get('schema') == 'lattica-proving-stages-v1'
                and report.get('succeeded') is True
                and report.get('stage_coverage_complete') is True
                and report.get('completion_rejected') is False
                and report.get('observation_errors') == 0,
                'incomplete or failed proving receipt: ' + str(entry))
        capabilities = report.get('capabilities', {})
        stages, observations = capabilities.get('stages', []), report.get('observations', [])
        require(stages and observations, 'missing proving stage receipts')
        if entry in machine:
            scope, required_stages = machine[entry]
            require(policy == 'gpu_required' and capabilities.get('profile') == 'block_v2_cubic'
                    and capabilities.get('scope') == scope
                    and {stage.get('stage') for stage in stages} == required_stages,
                    'MachineAir work used incorrect GPU policy/profile/scope/stages')
            backend = 'open_cl'
            counts[entry] += 1
        elif entry == 'native_matrict_spend':
            require(policy == 'gpu_required' and capabilities.get('profile') == 'matrict_n10'
                    and capabilities.get('scope') == 'operation'
                    and len(stages) == 1 and len(observations) == 1
                    and {stage.get('stage') for stage in stages} == {'witness_trace'}
                    and report.get('components') == [],
                    'native private spend lacks strict GPU operation capabilities')
            backend = 'open_cl'
            private_spend_reports += 1
            private_spend_completed += sum(o.get('completed_calls', 0) for o in observations)
            private_spend_devices += sum(o.get('device_calls', 0) for o in observations)
        elif entry == 'pq_graph_witness_preparation':
            require(policy == 'gpu_required' and capabilities.get('profile') == 'block_v2_cubic'
                    and capabilities.get('scope') == 'operation'
                    and {stage.get('stage') for stage in stages} == {'witness_trace'}
                    and not report.get('components'),
                    'graph preparation lacks strict GPU operation capabilities')
            backend = 'open_cl'
            preparation_reports += 1
            preparation_completed += sum(o.get('completed_calls', 0) for o in observations)
            preparation_devices += sum(o.get('device_calls', 0) for o in observations)
        else:
            require(policy == 'gpu_required' and entry in native_entries
                    and capabilities.get('profile') == 'block_v2_cubic'
                    and capabilities.get('scope') == 'proof_request'
                    and {stage.get('stage') for stage in stages} == native_stages,
                    'native work lacks complete GPU proof capabilities')
            backend = 'open_cl'
            native_reports += 1
        expected = {stage.get('stage') for stage in stages}
        require(None not in expected and len(expected) == len(stages)
                and all(stage.get('backend') == backend for stage in stages),
                'incorrect stage capability backend')
        observed = set()
        for observation in observations:
            calls, devices = observation.get('calls'), observation.get('device_calls')
            stage = observation.get('stage')
            require(stage in expected and stage not in observed
                    and observation.get('backend') == backend
                    and type(calls) is int and calls > 0
                    and calls == observation.get('completed_calls')
                    and type(devices) is int
                    and (0 < devices <= calls if backend == 'open_cl' else devices == 0),
                    'missing completed device/native stage receipts')
            observed.add(stage)
        require(observed == expected, 'missing promised stage coverage')
    context = result.get('context', {})
    operations = context.get('operations', {})
    proofs = operations.get('prove_calls')
    require(context.get('policy') == 'gpu_required'
            and type(context.get('registrations')) is int and context['registrations'] > 0
            and counts['block_v2_preprocessing'] == context['registrations'],
            'registration receipt count does not match worker')
    require(type(proofs) is int and proofs > 0 and operations.get('prove_succeeded') == proofs
            and counts['block_v2_registered_program'] == proofs
            and not operations.get('failures'), 'proof receipt count does not match worker')
    require(operations.get('native_cpu_calls') == 0
            and operations.get('native_cpu_succeeded') == 0, 'native CPU proving is forbidden')
    native_calls = operations.get('native_gpu_calls')
    require(type(native_calls) is int and native_calls > 0
            and operations.get('native_gpu_succeeded') == native_calls
            and operations.get('native_gpu_complete_reports') == native_calls
            and native_reports == native_calls, 'native GPU receipt count does not match worker')
    expected_spends = sum(case.get('count', 0) for case in result.get('cases', []))
    private_stage = operations.get('native_spend_stage', {})
    require(expected_spends > 0 and private_spend_reports == expected_spends
            and operations.get('native_spend_calls') == expected_spends
            and operations.get('native_spend_succeeded') == expected_spends
            and operations.get('native_spend_complete_reports') == expected_spends
            and private_stage.get('stage') == 'witness_trace'
            and private_stage.get('completed_calls') == private_spend_completed
            and private_stage.get('device_calls') == private_spend_devices,
            'native private-spend receipts differ from fresh transaction inventory')
    families = ('sources', 'algebra', 'crypto', 'auxiliary')
    expected_native = sum(case.get('cache', {}).get('families', {}).get(family, {}).get('fresh_proofs', 0)
                          for case in result.get('cases', []) for family in families)
    require(expected_native == native_calls, 'native GPU coverage differs from fresh proof inventory')
    preparation_calls = operations.get('witness_preparation_calls')
    preparation_stage = operations.get('witness_preparation_stage', {})
    require(type(preparation_calls) is int and preparation_calls > 0
            and preparation_calls == preparation_reports
            and operations.get('witness_preparation_succeeded') == preparation_calls
            and operations.get('witness_preparation_complete_reports') == preparation_calls
            and preparation_stage.get('stage') == 'witness_trace'
            and preparation_stage.get('completed_calls') == preparation_completed
            and preparation_stage.get('device_calls') == preparation_devices,
            'graph preparation GPU receipts differ from worker operation counts')
    return {'machine_gpu_reports': counts, 'native_gpu_reports': native_reports,
            'native_private_spend_gpu_reports': private_spend_reports,
            'witness_preparation_gpu_reports': preparation_reports,
            'native_cpu_calls': 0, 'completed_stage_receipts_checked': True}



def validate_result(result):
    require(result.get('schema') == 'pq-opencl-opt-correctness-v2'
            and result.get('passed') is True, 'missing successful correctness result')
    require(result.get('comparison_baseline') is False
            and result.get('performance_qualified') is False
            and result.get('fixture_pattern') == 'fresh_distinct', 'incorrect optimization scope')
    require(result.get('proving_scope') == 'native_private_spend_and_native_recursive_stark_proving'
            and result.get('fixture_generation') == 'cpu_ring_ask_inputs_only'
            and result.get('native_private_spend_generation') == 'gpu_required'
            and result.get('independent_verification') == 'cpu'
            and result.get('native_gpu_required') is True,
            'incorrect GPU proving or CPU fixture/verification scope')
    require(result.get('witness_preparation') == 'gpu_required',
            'graph witness preparation must require GPU execution')
    require(result.get('original_profile') is True and result.get('hiding') is True
            and result.get('num_queries') == 128 and result.get('blowup') == 16
            and result.get('extension') == 'Goldilocks cubic trinomial', 'proof profile changed')
    context = result.get('context', {})
    require(context.get('session_closed') is True and context.get('prepared_entries') == 0
            and context.get('maximum_prepared_entries') == 1, 'worker did not release its session')
    require(0 <= context.get('metadata_cache_payload_bytes', -1) <= 64 << 20,
            'worker metadata allowance exceeded')
    session = context.get('session_finish', {})
    require(session.get('commits', 0) > 0 and session.get('allocations', 0) > 0
            and 0 < session.get('managed_peak_bytes', 0) <= 8 * GIB,
            'missing bounded OpenCL work')
    cases = result.get('cases', [])
    require(len(cases) in (1, 2), 'missing correctness cases')
    seen = set()
    for case in cases:
        count = case.get('count')
        require(count in (3, 4) and count not in seen, 'unexpected or repeated case')
        seen.add(count)
        require(case.get('fresh_distinct_transactions') == count
                and case.get('complete_graphs_verified') == count, 'missing distinct complete graph proofs')
        digests = case.get('statement_digests', [])
        require(len(digests) == count and len({tuple(v) for v in digests}) == count,
                'transaction digests are not distinct')
        require(case.get('changed_public_rejected_count') == 25, 'public mutation coverage incomplete')
        for name in ('changed_proof_rejected', 'distinct_reordering_rejected',
                     'distinct_substitution_rejected', 'graph_proof_substitution_rejected',
                     'decoded_verification_after_gpu_shutdown'):
            require(case.get(name) is True, 'missing correctness check: ' + name)
        cache = case.get('cache', {})
        families = cache.get('families', {})
        require(cache.get('policy') == 'fresh_only' and set(families) ==
                {'sources', 'algebra', 'crypto', 'auxiliary', 'outer'}, 'incomplete fresh-cache accounting')
        for family in families.values():
            require(family.get('reads') == family.get('hits') == 0, 'cached proof payload was read')
            require(family.get('fresh_proofs', 0) > 0
                    and family.get('fresh_proofs') == family.get('proof_attempts'),
                    'incomplete fresh proof attempts')
        require(sum(v['fresh_proofs'] for v in families.values()) > 0, 'no fresh proofs produced')
        require(len(case.get('merges', [])) == count - 1, 'incomplete aggregation tree')
        checked_children = 0
        for merge in case['merges']:
            require(merge.get('backend') == 'opencl' and merge.get('strict_gpu_request') is True
                    and merge.get('native_parent_verification') is True
                    and merge.get('cache_policy') == 'fresh_only'
                    and merge.get('proof_cache_hit') is False, 'incorrect merge execution policy')
            checks = merge.get('recursive_witness_checks', [])
            require(len(checks) == merge.get('aggregate_children'), 'missing aggregate-child witness checks')
            require(all(v.get('altered_opening_rejected') is True for v in checks),
                    'altered aggregate-child opening accepted')
            checked_children += len(checks)
        require(checked_children == count - 2, 'incomplete recursive witness mutation coverage')


def validate_measurement(result, plan):
    benchmark = plan.get('benchmark', False)
    require(result.get('benchmark_measured', False) is benchmark, 'benchmark measurement mode differs')
    if not benchmark:
        require('measurement' not in result, 'unrequested benchmark measurement')
        return None

    def number(value, name, positive=False):
        require(type(value) in (int, float) and math.isfinite(value)
                and (value > 0 if positive else value >= 0), 'invalid measurement: ' + name)
        return value

    def close(actual, expected, name):
        number(actual, name)
        require(math.isclose(actual, expected, rel_tol=1e-9, abs_tol=1e-8), 'measurement mismatch: ' + name)

    names = ('witness_preparation_seconds', 'native_stark_proving_seconds',
             'recursive_stark_proving_seconds', 'registration_preprocessing_seconds',
             'native_private_spend_seconds')

    def gpu_wall(value):
        require(value.get('clock') == 'host_monotonic_wall'
                and value.get('scope') == 'serialized_gpu_required_calls_including_host_setup_and_waits'
                and value.get('device_only') is False
                and value.get('throughput_denominator') is False, 'incorrect GPU-operation timing scope')
        components = [number(value.get(name), name) for name in names]
        close(value.get('sum_seconds'), sum(components), 'GPU-operation sum')
        return components

    measurement = result.get('measurement', {})
    require(measurement.get('schema') == 'pq-opencl-fresh-workflow-timing-v2'
            and measurement.get('scope') == 'single_serial_context_fresh_fixtures_preparation_native_recursive_proving_verification_mutations_artifact_io_shutdown'
            and measurement.get('excludes') == 'process_launch_and_final_result_serialization'
            and measurement.get('clock') == 'host_monotonic_wall'
            and measurement.get('device_only') is False
            and measurement.get('production_throughput') is False
            and measurement.get('comparison_baseline') is False, 'incorrect benchmark scope')
    cases = result['cases']
    require({case['count'] for case in cases} == requested_counts(plan), 'measured cases differ from command')
    count = sum(case['count'] for case in cases)
    require(type(measurement.get('transactions')) is int and measurement['transactions'] == count,
            'incorrect measured transaction count')
    wall = number(measurement.get('run_wall_seconds'), 'run wall', True)
    close(measurement.get('fresh_end_to_end_correctness_workflow_transactions_per_hour'),
          count * 3600.0 / wall, 'run transactions/hour')
    summed_active = 0.0
    summed_gpu = [0.0] * len(names)
    for case in cases:
        timing = case.get('timing', {})
        require(timing.get('scope') == 'fresh_case_with_fixtures_preparation_native_recursive_proving_verification_mutations_artifact_io'
                and timing.get('excludes') == 'shared_session_setup_shutdown_and_other_cases'
                and timing.get('includes_internal_cpu_verification') is True
                and timing.get('includes_cpu_correctness_diagnostics') is True, 'incorrect case timing scope')
        active = number(timing.get('active_wall_seconds'), 'case active wall', True)
        close(timing.get('active_workflow_transactions_per_hour'), case['count'] * 3600.0 / active,
              'case transactions/hour')
        cpu_seconds = 0.0
        for name in ('cpu_input_fixture_setup_seconds', 'cpu_input_validation_decode_seconds',
                     'cpu_post_shutdown_artifact_decode_verify_seconds'):
            seconds = number(timing.get(name), name)
            require(seconds <= active, 'CPU stage exceeds active case wall')
            cpu_seconds += seconds
        components = gpu_wall(timing.get('gpu_operation_wall', {}))
        require(sum(components) <= active + 1e-8, 'GPU-operation wall exceeds active case wall')
        require(cpu_seconds + sum(components) <= active + 1e-8,
                'disjoint CPU and GPU-operation stages exceed active case wall')
        summed_gpu = [a + b for a, b in zip(summed_gpu, components)]
        summed_active += active
    require(summed_active <= wall + 1e-8, 'active cases exceed complete run wall')
    components = gpu_wall(measurement.get('gpu_operation_wall', {}))
    context = result['context']
    require(context.get('device') == plan['prior_correctness']['device'],
            'measured device differs from prior correctness device')
    counters = context.get('operations', {})
    observed = [counters.get('witness_preparation_seconds'), counters.get('native_gpu_seconds'),
                counters.get('prove_seconds'), context.get('registration_seconds'),
                counters.get('native_spend_seconds')]
    for actual, expected in zip(components, observed):
        close(actual, number(expected, 'context GPU-operation wall'), 'diagnostic GPU-operation accounting')
    for actual, expected in zip(components, summed_gpu):
        close(actual, expected, 'case GPU-operation accounting')
    require(sum(components) <= wall + 1e-8, 'GPU-operation wall exceeds run wall')
    return {'scope': 'fresh_end_to_end_correctness_workflow', 'transactions': count,
            'run_wall_seconds': wall,
            'transactions_per_hour': measurement['fresh_end_to_end_correctness_workflow_transactions_per_hour'],
            'production_throughput': False, 'device_only': False}


def validate_output(log, plan):
    content = log.read_text(errors='replace')
    if plan['expect_tests']:
        require(re.search(r'test result: ok\. [1-9][0-9]* passed; 0 failed;', content),
                'no nonempty passing correctness tests')
    if plan['expect_result']:
        results = [json.loads(line.removeprefix('OPENCL_OPT_RESULT '))
                   for line in content.splitlines() if line.startswith('OPENCL_OPT_RESULT ')]
        require(len(results) == 1, 'expected exactly one correctness result')
        validate_result(results[0])
        validate_experiments(results[0], plan)
        plan['receipt_acceptance'] = validate_receipts(content, results[0])
        plan['correctness_result'] = results[0]
        plan['measurement_acceptance'] = validate_measurement(results[0], plan)


def interrupted(signum, _frame):
    raise InterruptedError('correctness job interrupted by signal ' + str(signum))


def execute(args, plan):
    require(args.exclusive_window, 'execution requires coordinator --exclusive-window')
    STATE.mkdir(parents=True, exist_ok=True)
    with (STATE / 'validation.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        helper = admission_helpers()
        observed = helper.conflicting_processes()
        require(not observed['conflicts'], 'competing build/prover: ' + json.dumps(observed))
        require(helper.available() >= plan['fresh_memavailable_required_bytes'], 'fresh memory admission failed')
        require(shutil.disk_usage(ROOT).free >= 10 * GIB, 'disk reserve failed')
        require(Path(plan['command'][0]).is_file(), 'executable is absent')
        runs = STATE / 'runs'
        runs.mkdir(exist_ok=True)
        record, log = runs / (args.label + '.json'), runs / (args.label + '.log')
        require(not record.exists() and not log.exists(), 'run label already used')
        unit = 'lattica-opencl-opt-' + args.label + '.service'
        require(systemd_state(unit).get('LoadState') == 'not-found', 'service name already exists')
        before = source_manifest()
        executable = executable_provenance(plan, before, runs)
        if plan.get('benchmark', False):
            plan['prior_correctness'] = prior_correctness(plan, before, executable, runs)
        properties = {'Type': 'exec', 'RemainAfterExit': 'yes', 'Restart': 'no',
                      'MemoryMax': str(plan['memory_max_bytes']),
                      'MemoryHigh': str(plan['memory_high_bytes']), 'MemorySwapMax': '0',
                      'CPUQuota': plan['cpu_quota'], 'TasksMax': '256',
                      'RuntimeMaxSec': str(args.seconds), 'TimeoutStopSec': '10',
                      'KillMode': 'control-group', 'WorkingDirectory': str(ROOT),
                      'StandardOutput': 'append:' + str(log), 'StandardError': 'inherit'}
        argv = ['/usr/bin/systemd-run', '--user', '--quiet', '--unit=' + unit]
        argv += ['--property=' + key + '=' + value for key, value in properties.items()]
        argv += ['/usr/bin/env', '-i'] + [key + '=' + value for key, value in plan['environment'].items()]
        argv += plan['command']
        plan.update(status='starting', unit=unit, started_utc=now(), input_sha256=before,
                    executable_provenance=executable,
                    process_admission=observed, service_command=argv)
        with record.open('x') as output:
            json.dump(plan, output, indent=2)
        error, state, attempted = None, None, False
        started = time.monotonic()
        try:
            attempted = True
            response = command(argv)
            require(response.returncode == 0, 'launch failed: ' + response.stderr)
            plan['launch'] = True
            while True:
                state = systemd_state(unit)
                require(state.get('MemoryMax') == properties['MemoryMax']
                        and state.get('MemoryHigh') == properties['MemoryHigh']
                        and state.get('MemorySwapMax') == '0', 'service memory policy changed')
                if state.get('MainPID') == '0' and state.get('SubState') in ('exited', 'failed', 'dead'):
                    break
                require(time.monotonic() - started <= args.seconds + 30, 'observation exceeded runtime limit')
                time.sleep(2)
            require(state.get('Result') == 'success' and state.get('ExecMainCode') == '1'
                    and state.get('ExecMainStatus') == '0', 'command failed: ' + json.dumps(state))
            validate_output(log, plan)
            if plan.get('benchmark', False):
                require(prior_correctness(plan, before, executable, runs) == plan['prior_correctness'],
                        'prior correctness provenance changed during benchmark')
            artifacts = {}
            for path in plan['record_artifacts']:
                require(Path(path).is_file() and os.access(path, os.X_OK),
                        'missing executable build artifact: ' + path)
                artifacts[path] = sha(path)
            plan['built_artifact_sha256'] = artifacts
        except BaseException as caught:
            error = repr(caught)
        finally:
            for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                signal.signal(sig, signal.SIG_IGN)
            try:
                if attempted:
                    stopped = command(['/usr/bin/systemctl', '--user', 'stop', unit])
                    require(stopped.returncode == 0, 'service stop failed: ' + stopped.stderr)
                plan['service_stop_completed'] = attempted
                after = systemd_state(unit)
                remaining = []
                if after.get('ControlGroup'):
                    group = Path('/sys/fs/cgroup') / after['ControlGroup'].lstrip('/')
                    if group.exists():
                        for process_file in group.rglob('cgroup.procs'):
                            remaining += process_file.read_text().split()
                reaped = (after.get('LoadState') == 'not-found'
                          or after.get('MainPID') == after.get('ControlPID') == '0') and not remaining
                plan.update(post_stop_state=after, all_subprocesses_terminal_and_reaped=reaped)
                require(reaped, 'service process cleanup unverified')
            except Exception as cleanup:
                error = (error or '') + '; cleanup: ' + repr(cleanup)
            try:
                require(sha(plan['command'][0]) == executable['sha256'],
                        'executed binary changed during correctness job')
                plan['executable_unchanged'] = True
                unchanged = source_manifest() == before
                plan['source_inputs_unchanged'] = unchanged
                require(unchanged, 'sources changed during correctness job')
            except Exception as changed:
                error = (error or '') + '; source check: ' + repr(changed)
            plan.update(status='passed' if error is None else 'failed_or_incomplete', error=error,
                        finished_utc=now(), wall_seconds=time.monotonic() - started,
                        terminal_state=state, raw_log=str(log), raw_log_sha256=sha(log) if log.exists() else None)
            record.write_text(json.dumps(plan, indent=2) + '\n')
        print(json.dumps({'status': plan['status'], 'record': str(record), 'error': error}))
        return int(error is not None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=PROFILES, required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--seconds', type=int, default=1800)
    parser.add_argument('--expect-tests', action='store_true')
    parser.add_argument('--expect-result', action='store_true')
    parser.add_argument('--build-label')
    parser.add_argument('--benchmark', action='store_true')
    parser.add_argument('--correctness-label')
    parser.add_argument('--record-artifact', action='append', default=[])
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--exclusive-window', action='store_true')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    plan = build_plan(args)
    if not args.execute:
        print(json.dumps(plan, indent=2))
        return 0
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    return execute(args, plan)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status': 'refused', 'error': repr(error)}), file=sys.stderr)
        raise SystemExit(1)
