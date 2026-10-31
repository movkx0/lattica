#!/usr/bin/env python3
"""Audit fixed pair/odd-tail GPU qualifiers; never claim full RingCT closure."""
import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import sys
from types import SimpleNamespace

GIB = 1 << 30
PREFIX = 'component_tree::owned_shake::outer_producer::production::preissued::sequence::'
SHAPES = {
    'pair': ('native-pair-sequence', 'gpu_two_native_segments_pair_original_successors', 2),
    'pair-and-tail': ('native-odd-tail-sequence', 'gpu_three_native_segments_pair_and_tail_original_successors', 3),
}
NATIVE_STAGES = set('public_values witness_trace preprocessing transform quotient randomness hiding commitment opening fri_fold fri_query final_polynomial scalar transcript grinding'.split())
CONTRACTS = {
    'ringct_owned_native_shake': ('proof_request', NATIVE_STAGES),
    'block_v2_preprocessing': ('preprocessing', set('preprocessing randomness transform commitment'.split())),
    'block_v2_registered_program': ('registered_proof', (NATIVE_STAGES - {'public_values'}) | {'lookup'}),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def positive(value, label):
    require(type(value) is int and 0 < value < 1 << 128, 'invalid ' + label)
    return value


def exact(actual, expected):
    """JSON booleans and integers must not compare equal as they do in Python."""
    return json.dumps(actual, sort_keys=True, allow_nan=False) == json.dumps(expected, sort_keys=True)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: require(False, 'nonfinite JSON number'))


def read(path, maximum=4 << 20):
    with Path(path).open('rb') as stream:
        data = stream.read(maximum + 1)
    require(len(data) <= maximum, 'file too large')
    return data


def sha(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            result.update(block)
    return result.hexdigest()


def fields(line):
    result = {}
    for item in line.split():
        require(item.count('=') == 1, 'malformed marker')
        key, value = item.split('=')
        require(key and key not in result, 'duplicate marker field')
        if value in ('true', 'false'):
            value = value == 'true'
        elif re.fullmatch(r'0|[1-9][0-9]{0,38}', value):
            value = int(value)
        result[key] = value
    return result


def receipt(report, entry):
    scope, stages = CONTRACTS[entry]
    require(report.get('schema') == 'lattica-proving-stages-v1'
            and report.get('entry_point') == entry and report.get('policy') == 'gpu_required'
            and report.get('succeeded') is True and report.get('stage_coverage_complete') is True
            and report.get('completion_rejected') is False
            and type(report.get('observation_errors')) is int and report['observation_errors'] == 0
            and report.get('components') == [], 'failed or unexpected GPU receipt')
    caps = report.get('capabilities', {})
    require(caps.get('scope') == scope and caps.get('profile') == 'block_v2_cubic'
            and type(caps.get('max_log_fri_arity')) is int and caps['max_log_fri_arity'] == 1,
            'changed proof capabilities')
    declared = caps.get('stages', [])
    require(len(declared) == len(stages) and {s.get('stage') for s in declared} == stages
            and all(s.get('backend') == 'open_cl' for s in declared), 'changed stage inventory')
    observations = report.get('observations', [])
    require(len(observations) == len(stages) and {s.get('stage') for s in observations} == stages,
            'missing or duplicate stage observations')
    for observed in observations:
        calls = positive(observed.get('calls'), 'calls')
        devices = positive(observed.get('device_calls'), 'device calls')
        # This fixed qualifier also requires recorded event timing. The core
        # proving policy permits completed device calls without event timing;
        # that is insufficient for this timing-bearing qualification report.
        positive(observed.get('device_ns'), 'device event time')
        inclusive = observed.get('inclusive_ns')
        require(type(inclusive) is int and 0 <= inclusive < 1 << 128,
                'invalid inclusive stage time')
        # Inclusive and device event intervals may nest; never sum them.
        require(observed.get('backend') == 'open_cl'
                and type(observed.get('completed_calls')) is int
                and observed['completed_calls'] == calls and devices <= calls,
                'uncompleted GPU stage')
    return positive(report.get('elapsed_ns'), 'receipt time')


def audit_log(content, shape):
    require(shape in SHAPES, 'unknown sequence shape')
    _, selector, natives = SHAPES[shape]
    groups = natives - 1
    events = []
    for line in content.splitlines():
        if line.startswith('proving_stage_report '):
            events.append(('receipt', decode(line.removeprefix('proving_stage_report '))))
        elif line.startswith('ringct_native_sequence_'):
            name, body = line.split(' ', 1)
            events.append((name.removeprefix('ringct_native_sequence_'), fields(body)))
    expected = ['preissued']
    if groups == 2:
        expected.append('handoff_refusal')
    expected += ['receipt'] * (natives + 2 * groups)
    expected += ['group'] * groups + ['complete', 'terminal']
    require([event[0] for event in events] == expected, 'missing, extra, or reordered sequence events')
    preissued = events[0][1]
    require(exact(preissued, dict(shape=shape, native_proofs_expected=natives,
        recursive_proofs_expected=groups, all_source_bounds_complete=True,
        original_phase_owners_live=True, native_dispatch_started=False,
        host_bytes=32 * GIB, device_bytes=8 * GIB)), 'pre-dispatch admission differs')
    if groups == 2:
        require(exact(events[1][1], dict(shape=shape, previous_index=0, refused_next_index=2,
            complete_owners_returned=True, ledger_snapshot_unchanged=True,
            proof_dispatch_attempted=False)), 'handoff refusal lost original owners')
    receipts = [value for name, value in events if name == 'receipt']
    entries = ['ringct_owned_native_shake'] * natives
    entries += ['block_v2_preprocessing', 'block_v2_registered_program'] * groups
    elapsed = [receipt(value, entry) for value, entry in zip(receipts, entries)]
    metrics = [value for name, value in events if name == 'group']
    metric_keys = set('shape ordinal active_rows padded_rows compiler_ns setup_ns proving_ns cpu_verification_ns independent_cpu_verified mutation_rejections'.split())
    for ordinal, metric in enumerate(metrics):
        require(set(metric) == metric_keys and metric['shape'] == shape
                and type(metric['ordinal']) is int and metric['ordinal'] == ordinal
                and metric['independent_cpu_verified'] is True
                and type(metric['mutation_rejections']) is int and metric['mutation_rejections'] == 2,
                'group coverage/verification differs')
        active = positive(metric['active_rows'], 'active rows')
        padded = positive(metric['padded_rows'], 'padded rows')
        require(active <= padded <= 1 << 19 and padded & (padded - 1) == 0, 'invalid row geometry')
        for field in ('compiler_ns', 'setup_ns', 'proving_ns', 'cpu_verification_ns'):
            positive(metric[field], field)
        require(metric['setup_ns'] == elapsed[natives + 2 * ordinal]
                and metric['proving_ns'] == elapsed[natives + 2 * ordinal + 1],
                'group timing differs from actual receipts')
    complete = events[-2][1].copy()
    preissue = positive(complete.pop('source_preissue_ns', None), 'source preissue time')
    component = positive(complete.pop('component_including_mutations_ns', None), 'component time')
    require(component >= preissue + sum(elapsed) + sum(
        metric['compiler_ns'] + metric['cpu_verification_ns'] for metric in metrics),
        'component interval does not enclose serialized stages')
    require(exact(complete, dict(shape=shape, native_proofs=natives, recursive_proofs=groups,
        mutation_rejections=2 * groups, fresh_gpu_required=True, compiler_backend='cpu',
        public_endpoint_preprocessing='cpu', original_startup_pcs_reused=True,
        native_successor_and_attachment_snapshots_unchanged=True,
        skipped_predecessor_handoff_refusals=groups - 1, second_outer_dispatched=groups == 2,
        request_aggregate_proofs=0, complete_ringct_workflow=False)), 'incorrect completion scope')
    require(exact(events[-1][1], dict(shape=shape, original_quota_released=True,
        complete_ringct_workflow=False)), 'missing quota release')
    summaries = re.findall(r'^test result: (.+)$', content, re.MULTILINE)
    require(len(summaries) == 1 and re.fullmatch(
        r'ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s',
        summaries[0]), 'wrong exact-test result')
    require('FAILED' not in content and 'panicked at' not in content, 'test failure in log')
    return dict(shape=shape, native_proofs=natives, recursive_group_proofs=groups,
        stage_receipts=len(receipts), mutation_rejections=2 * groups, groups=metrics,
        source_preissue_ns=preissue, component_including_mutations_ns=component,
        original_quota_released=True)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def check_build(build, record, terminal_validator, hash_file):
    terminal_validator(build)
    require(build.get('profile') == 'build' and build.get('input_sha256') == record['input_sha256'],
            'build profile/snapshot differs')
    require(build.get('command') == ['/home/access/code/lattica/.tools/rust-1.96.0/bin/cargo',
        'test', '--release', '--locked', '--offline', '--manifest-path', 'research/pq-ringct/Cargo.toml',
        '--no-default-features', '--features', 'native-matrict,owned-native-shake', '--lib', '--no-run'],
        'build command/features differ')
    require(hash_file(build['raw_log']) == build['raw_log_sha256'], 'build log hash differs')
    intervals = []
    for item in (build, record):
        start, finish = (datetime.fromisoformat(item[key]) for key in ('started_utc', 'finished_utc'))
        require(start.utcoffset() is not None and finish.utcoffset() is not None and finish > start,
                'invalid record interval')
        intervals.append((start, finish))
    require(intervals[0][1] <= intervals[1][0], 'build and execution overlap or reverse chronology')


def check_service(record, root, path, command, environment, maximum, high):
    label = record.get('label')
    require(type(label) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,55}', label), 'invalid label')
    require(record.get('unit') == 'lattica-opencl-opt-' + label + '.service'
            and Path(path) == root / '.tools/pq-opencl-opt/runs' / (label + '.json')
            and Path(record['raw_log']) == root / '.tools/pq-opencl-opt/runs' / (label + '.log'),
            'record/log paths do not bind label')
    runtime = positive(record.get('runtime_seconds'), 'runtime limit')
    require(runtime <= 86400, 'runtime limit exceeded')
    service = record.get('service_command', [])
    require(service.count('/usr/bin/env') == 1, 'missing env-clear launch')
    env_index = service.index('/usr/bin/env')
    require(service[:4] == ['/usr/bin/systemd-run', '--user', '--quiet', '--unit=' + record['unit']],
            'wrong service launcher')
    properties = {}
    for entry in service[4:env_index]:
        require(type(entry) is str and entry.startswith('--property='), 'unknown service option')
        key, value = entry.removeprefix('--property=').split('=', 1)
        require(key not in properties, 'duplicate service property')
        properties[key] = value
    require(properties == dict(Type='exec', RemainAfterExit='yes', Restart='no',
        MemoryMax=str(maximum * GIB), MemoryHigh=str(high * GIB), MemorySwapMax='0',
        CPUQuota='800%', TasksMax='256', RuntimeMaxSec=str(runtime), TimeoutStopSec='10',
        KillMode='control-group', WorkingDirectory=str(root),
        StandardOutput='append:' + record['raw_log'], StandardError='inherit'), 'service envelope differs')
    require(service[env_index + 1:] == ['-i', *[key + '=' + value for key, value in environment.items()],
            *command], 'actual launch differs')


def audit(path, shape):
    root = Path(__file__).resolve().parents[3]
    pins = decode(read(Path(__file__).with_name('native_sequence_source_pins.json')))
    require(all(sha(root / key) == value for key, value in pins.items()), 'audited sources changed')
    guard = load_module('sequence_guard', root / 'research/pq-ringct/tools/opencl_private_spend_validate.py')
    # Shared terminal validation is independently pinned before importing it.
    helper_dir = root / 'research/pq-direct-spend/tools'
    sys.path.insert(0, str(helper_dir))
    helper = load_module('sequence_terminal', helper_dir / 'note_workflow_report.py')
    record = decode(read(path))
    peak = helper.terminal(record)
    require(shape in SHAPES, 'unknown shape')
    mode, selector, _ = SHAPES[shape]
    profile = record.get('profile')
    require(profile in ('full', 'direct-full'), 'wrong resource profile')
    maximum, high, admission, _, _ = guard.PROFILES[profile]
    require((record.get('memory_max_bytes'), record.get('memory_high_bytes'),
        record.get('fresh_memavailable_required_bytes')) == (maximum * GIB, high * GIB, admission * GIB),
        'changed resource envelope')
    require(record.get('expect_tests') is True and record.get('public_hash_kernel') == 'baseline',
            'wrong test or hashing profile')
    for key in ('expect_result', 'expect_direct_result', 'benchmark', 'comparison_baseline', 'performance_qualified'):
        require(record.get(key) is False, 'mixed qualification mode')
    command = record.get('command', [])
    require(len(command) == 6 and command[1:] == [PREFIX + selector, '--exact', '--ignored',
            '--test-threads=1', '--nocapture'], 'wrong exact selector')
    executable = Path(command[0])
    require(executable.parent == root / '.tools/target-opencl/release/deps'
            and executable.name.startswith('lattica_pq_ringct_research-'), 'unexpected executable')
    sources = guard.source_manifest()
    require(record.get('input_sha256') == sources and all(sources.get(k) == v for k, v in pins.items()),
            'source snapshot differs')
    provenance = guard.executable_provenance(record, sources, root / '.tools/pq-opencl-opt/runs')
    require(record.get('build_label') and record.get('executable_provenance') == provenance,
            'recorded build/executable differs')
    build = decode(read(provenance['build_record']))
    check_build(build, record, helper.terminal, sha)
    environment = record.get('environment', {})
    args = SimpleNamespace(owned_runtime_test=mode, profile=profile, expect_tests=True,
        build_label=record['build_label'], device_uuid=environment.get('LATTICA_GPU_DEVICE_UUID'))
    expected_env, expected_receipt = guard.owned_runtime_environment(args, command, 'host', 'baseline')
    require(environment == expected_env and record.get('owned_runtime_environment') == expected_receipt,
            'qualification environment differs')
    for key in ('note_startup_environment', 'note_cpu_environment', 'direct_ring_screen_environment',
                'direct_ring_identity_environment', 'owned_source_shape_environment'):
        require(key in record and record[key] is None, 'mixed isolated environment')
    check_service(record, root, path, command, environment, maximum, high)
    require(record['raw_log_sha256'] == sha(record['raw_log']), 'log hash differs')
    content = read(record['raw_log'], 16 << 20).decode()
    result = audit_log(content, shape)
    require(type(record.get('wall_seconds')) in (int, float)
            and math.isfinite(record['wall_seconds'])
            and record['wall_seconds'] * 1e9 >= result['component_including_mutations_ns'],
            'guard interval does not enclose component')
    return dict(schema='lattica-native-sequence-evidence-v1', research_only=True,
        complete_faithful_ringct_workflow=False, request_aggregate_qualified=False,
        n3_n4_qualified=False, artifact_roundtrip_qualified=False, performance_qualified=False,
        production_promotion_qualified=False, source_executable_log_bound=True,
        guard_record=str(path), guard_record_sha256=sha(path), raw_log_sha256=record['raw_log_sha256'],
        build_record_sha256=provenance['build_record_sha256'], executable_sha256=provenance['sha256'],
        source_snapshot_sha256=hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest(),
        physical_gpu_uuid=args.device_uuid, guard_wall_seconds=record['wall_seconds'],
        guarded_cgroup_host_peak_bytes=peak, qualification=result,
        limitations=['Fixed singleton-native component fixtures; placeholder graph context.',
            'No request/transaction/final aggregate, artifact roundtrip, or full-workflow speedup.',
            'Component timer excludes initial guards/claim and final owner cleanup; guard wall encloses them.',
            'Compiler and public endpoint preprocessing execute on CPU.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shape', required=True, choices=SHAPES)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = audit(args.record.resolve(), args.shape)
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write('\n')


if __name__ == '__main__':
    main()
