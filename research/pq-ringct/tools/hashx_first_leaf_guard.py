"""Exact first-leaf component guard. Capacity reports grant no GPU authority."""
from hashlib import sha256
import json
from pathlib import PurePosixPath
import re

GIB = 1 << 30
PREFIX = 'component_tree::owned_shake::request_merge::source::capture::acceptance::hashx::qualification::'
SELECTORS = {
    'capacity': PREFIX + 'cpu_original_hashx_first_paired_leaf_capacity',
    'gpu': PREFIX + 'gpu_original_hashx_first_paired_leaf_source_authenticated',
}
FLAG = 'LATTICA_OWNED_HASHX_FIRST_LEAF_QUALIFICATION'
EXCLUSIVE = ('owned_hashx_interior_opening_test', 'owned_hashx_root_opening_test', 'owned_hashx_root_transport_test', 'note_owned_proof', 'note_workflow_cpu', 'owned_runtime_test',
             'direct_ring_screen', 'direct_ring_identity_test', 'owned_source_shape_test',
             'active_hashx_preflight', 'owned_request_source_test', 'direct_ring_recursion_test',
             'owned_native_hashx_test')
REQUIRED_SOURCES = (
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake/quota_projection.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake/retirement/hashx/outer.rs',
    'lattica-prover-p3/src/block_v2/machine/backend/verification_outcome.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace/quota_projection.rs',
    'research/pq-ringct/src/component_tree/owned_shake/outer_producer/production/preissued/hashx_leaf.rs',
    'research/pq-ringct/src/component_tree/owned_shake/output/preissued.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/hashx/qualification.rs',
    'research/pq-ringct/tools/hashx_first_leaf_guard.py',
    'research/pq-ringct/tools/test_hashx_first_leaf_guard.py',
    'research/pq-ringct/tools/native_sequence_report.py',
    'research/pq-ringct/tools/opencl_private_spend_validate.py',
)


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def absolute(value):
    return (type(value) is str and '\0' not in value and PurePosixPath(value).is_absolute()
            and '..' not in PurePosixPath(value).parts)


def expected_environment(mode, root, uuid=None):
    require(mode in SELECTORS and absolute(root), 'first-leaf mode or root')
    result = {'PATH': '/home/access/code/lattica/.tools/rust-1.96.0/bin:/usr/bin:/bin',
              'HOME': '/home/access', 'CARGO_HOME': root + '/.tools/cargo-opencl',
              'CARGO_TARGET_DIR': root + '/.tools/target-opencl', 'CARGO_BUILD_JOBS': '2',
              'RAYON_NUM_THREADS': '2', 'LATTICA_PROVING_REPORT': '1',
              'LATTICA_PROVING_POLICY': 'cpu-required'}
    if mode == 'capacity':
        require(uuid is None, 'capacity mode cannot select a GPU')
        return result
    require(type(uuid) is str and re.fullmatch(
        r'GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', uuid),
        'first-leaf GPU mode requires physical UUID')
    switches = ('HASH', 'RETAIN_TREES', 'QUERY_GATHER', 'RESIDENT_LDE', 'OPENINGS',
                'QUOTIENT_LDE', 'QUOTIENT_EVAL', 'QUOTIENT_RESIDENT', 'LOOKUP',
                'OPENING_EVAL', 'FRI_RESIDENT', 'PCS_DEVICE_ONLY', 'WITNESS',
                'RANDOMNESS', 'TRANSCRIPT', 'FRI_FOLD')
    result.update({'LATTICA_V2_GPU_' + switch: '1' for switch in switches})
    result.update({'RAYON_NUM_THREADS': '8', 'LATTICA_PROVING_POLICY': 'gpu-required',
                   'LATTICA_V2_QUOTIENT_FUSION': '1', 'LATTICA_V2_GPU_DEVICE': '0',
                   'LATTICA_GPU_DEVICE_UUID': uuid, 'LATTICA_V2_GPU_PIPELINE': '0',
                   'LATTICA_V2_GPU_PUBLIC_HASH': 'baseline',
                   'LATTICA_V2_GPU_MANAGED_BYTES': str(8 * GIB),
                   'LATTICA_V2_GPU_CONTEXT_BYTES': str(4 * GIB),
                   'LATTICA_V2_HOST_OUTPUT_BYTES': str(24 * GIB),
                   'LATTICA_V2_GPU_RETAINED_TREE_STORAGE': 'host',
                   'LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES': str(8 * GIB), FLAG: '1'})
    return result


def receipt(environment, mode):
    encoded = b''.join((key + '=' + environment[key] + '\0').encode()
                       for key in sorted(environment))
    require(len(environment) <= 64 and len(encoded) <= 8192, 'first-leaf environment bound')
    return {'schema': 'ringct-first-leaf-environment-v1', 'mode': mode,
            'selector': SELECTORS[mode], 'entry_count': len(environment),
            'serialized_bytes': len(encoded), 'sha256_sorted_name_equals_value_nul': sha256(encoded).hexdigest(),
            'requires_env_clear_before_exec': True, 'requires_immutable_environment_after_exec': True,
            'dispatch_authority': False, 'complete_ringct_workflow': False}


def exact_command(command, mode):
    require(type(command) is list and len(command) == 6 and absolute(command[0])
            and PurePosixPath(command[0]).name.startswith('lattica_pq_ringct_research-')
            and command[1:] == [SELECTORS[mode], '--exact', '--ignored', '--test-threads=1', '--nocapture'],
            'first-leaf requires the exact recorded isolated test')


def build_environment(args, argv, tree_storage, kernel, base, root):
    mode = getattr(args, 'owned_hashx_leaf_test', None)
    require(mode in SELECTORS, 'unknown first-leaf mode')
    exact_command(argv, mode)
    require(args.profile == ('full' if mode == 'gpu' else 'research-compile-large')
            and args.expect_tests and args.build_label, 'first-leaf profile/build differs')
    require(not any(bool(getattr(args, key, False)) for key in EXCLUSIVE + (
        'expect_result', 'expect_direct_result', 'benchmark', 'correctness_label',
        'record_artifact', 'direct_ring_recursion_census_label')), 'first-leaf modes are exclusive')
    require(kernel == 'baseline' and tree_storage == ('host' if mode == 'gpu' else 'device'),
            'first-leaf hash/tree mode differs')
    environment = expected_environment(mode, root, getattr(args, 'device_uuid', None))
    if mode == 'gpu':
        expected_base = dict(environment)
        for name in (FLAG, 'LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'):
            expected_base.pop(name)
        expected_base['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'device'
    else:
        expected_base = environment
    require(base == expected_base, 'first-leaf fixed base environment differs')
    return environment, receipt(environment, mode)


def bind_execution(plan, sources, executable, root):
    require(plan.get('owned_hashx_interior_opening_environment') is None,
            'interior-opening qualification cannot mix with this mode')
    require(plan.get('owned_hashx_root_opening_environment') is None,
            'root-opening qualification cannot mix with this mode')
    require(plan.get('owned_hashx_root_transport_environment') is None,
            'root-transport qualification cannot mix with this mode')
    note = plan.get('owned_hashx_leaf_environment')
    require(type(note) is dict and note.get('mode') in SELECTORS, 'first-leaf receipt absent')
    mode = note['mode']
    exact_command(plan.get('command'), mode)
    env = plan.get('environment')
    require(type(env) is dict, 'first-leaf environment absent')
    expected = expected_environment(mode, root, env.get('LATTICA_GPU_DEVICE_UUID'))
    require(env == expected and note == receipt(env, mode), 'first-leaf environment changed')
    max_gib, high_gib, admit_gib, quota = (47, 45, 49, '800%') if mode == 'gpu' else (32, 30, 36, '200%')
    require(plan.get('profile') == ('full' if mode == 'gpu' else 'research-compile-large')
            and plan.get('expect_tests') is True and plan.get('memory_max_bytes') == max_gib * GIB
            and plan.get('memory_high_bytes') == high_gib * GIB
            and plan.get('fresh_memavailable_required_bytes') == admit_gib * GIB
            and plan.get('cpu_quota') == quota and plan.get('benchmark') is False
            and plan.get('public_hash_kernel') == 'baseline' and not plan.get('expect_result')
            and not plan.get('expect_direct_result'), 'first-leaf resource contract changed')
    require(type(sources) is dict and all(path in sources for path in REQUIRED_SOURCES),
            'first-leaf source manifest is incomplete')
    require(all(type(path) is str and path and not PurePosixPath(path).is_absolute()
                and '..' not in PurePosixPath(path).parts and digest(value)
                for path, value in sources.items()), 'first-leaf source manifest malformed')
    label = plan.get('build_label')
    require(type(label) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,55}', label), 'missing first-leaf build')
    require(type(executable) is dict and executable.get('path') == plan['command'][0]
            and absolute(executable.get('resolved_path')) and digest(executable.get('sha256'))
            and executable.get('build_record') == root + '/.tools/pq-opencl-opt/runs/' + label + '.json'
            and digest(executable.get('build_record_sha256')), 'first-leaf executable binding differs')
    return {'schema': 'ringct-first-leaf-binding-v1', 'mode': mode, 'selector': SELECTORS[mode],
            'source_manifest_sha256': sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest(),
            'executable_sha256': executable['sha256'], 'build_record_sha256': executable['build_record_sha256'],
            'environment_sha256': note['sha256_sorted_name_equals_value_nul'],
            'requires_terminal_reaping_and_unchanged_sources': True,
            'dispatch_authority': False, 'complete_ringct_workflow': False}


def fields(text):
    result = {}
    for token in text.split():
        require(token.count('=') == 1, 'malformed first-leaf marker')
        key, value = token.split('=')
        require(key and key not in result, 'duplicate first-leaf field')
        if value in ('true', 'false'):
            value = value == 'true'
        elif re.fullmatch(r'0|[1-9][0-9]{0,38}', value):
            value = int(value)
        result[key] = value
    return result


def integer(value, low=0, high=(1 << 128) - 1):
    require(type(value) is int and low <= value <= high, 'first-leaf integer out of bounds')
    return value


def fixed(record, expected, variable):
    require(set(record) == set(expected) | set(variable), 'missing or extra first-leaf fields')
    require(all(type(record[k]) is type(v) and record[k] == v for k, v in expected.items()),
            'first-leaf scope or fixed values differ')


def validate_log(content, plan, receipt_check):
    note = plan.get('owned_hashx_leaf_environment', {})
    mode = note.get('mode')
    require(mode in SELECTORS and note.get('selector') == SELECTORS[mode], 'first-leaf mode missing')
    binding = plan.get('owned_hashx_leaf_binding', {})
    require(binding.get('mode') == mode and binding.get('selector') == SELECTORS[mode]
            and binding.get('environment_sha256') == note.get('sha256_sorted_name_equals_value_nul')
            and digest(binding.get('source_manifest_sha256')) and digest(binding.get('executable_sha256')),
            'first-leaf log lacks original source/build binding')
    require(type(content) is str and not any(word in content for word in (
        'panicked at', 'test result: FAILED', 'OPENCL_OPT_RESULT', 'DIRECT_SPEND_RESULT', 'DIRECT_RING_RESULT')),
        'first-leaf emitted failure or unrelated workflow evidence')
    prefix = 'test ' + SELECTORS[mode] + ' ... '
    require(content.count(prefix) == 1, 'first-leaf invocation missing or duplicated')
    content = content.replace(prefix, '', 1)
    footers = re.findall(r'^test result: (.+)$', content, re.M)
    require(len(footers) == 1 and re.fullmatch(
        r'ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s', footers[0]),
        'first-leaf requires one passing exact test')
    events = []
    for line in content.splitlines():
        if line.startswith('ringct_hashx_first_leaf_'):
            name, body = line.split(' ', 1)
            events.append((name.removeprefix('ringct_hashx_first_leaf_'), fields(body)))
        elif line.startswith('proving_stage_report '):
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    require(key not in result, 'duplicate receipt key')
                    result[key] = value
                return result
            report = json.loads(line.removeprefix('proving_stage_report '), object_pairs_hook=unique)
            require(type(report) is dict, 'malformed first-leaf receipt')
            events.append(('receipt', report))
    expected_order = ['source_claims', 'capacity_complete', 'terminal'] if mode == 'capacity' else (
        ['source_claims', 'preissued'] + ['receipt'] * 12 + ['complete', 'terminal'])
    require([name for name, _ in events] == expected_order, 'missing, duplicate or reordered first-leaf events')
    require(content.rfind('ringct_hashx_first_leaf_terminal ') < content.index('test result:'),
            'first-leaf terminal follows test completion')
    source, terminal = events[0][1], events[-1][1]
    fixed(source, dict(native_outputs=10, native_attachments=10, retained_leaf_sources=5,
        compiler_claims=1, acceptance_claims=1, mutation_claims=1, mode=mode,
        native_dispatch_started=False, complete_request_admitted=False), ('host_bytes', 'device_bytes'))
    claimed_host = integer(source['host_bytes'], 1, 32 * GIB)
    claimed_device = integer(source['device_bytes'], 0, 8 * GIB)
    fixed(terminal, dict(original_quota_released=True, current_host_bytes=0, current_device_bytes=0,
        component_success=True, mode=mode, complete_ringct_workflow=False),
        ('peak_host_bytes', 'peak_device_bytes', 'component_wall_ns'))
    peak_host = integer(terminal['peak_host_bytes'], claimed_host, 32 * GIB)
    peak_device = integer(terminal['peak_device_bytes'], claimed_device, 8 * GIB)
    wall = integer(terminal['component_wall_ns'], 1)
    if mode == 'capacity':
        cap = events[1][1]
        values = ('original_claims_host_bytes', 'startup_host_bytes', 'startup_device_bytes',
                  'phase_wrappers_host_bytes', 'phase_wrappers_device_bytes', 'pcs_host_bytes',
                  'pcs_device_bytes', 'simultaneous_host_bytes', 'simultaneous_device_bytes',
                  'projection_ns', 'source_preissue_ns')
        fixed(cap, dict(native_proofs=0, recursive_proofs=0, wrong_request_and_ledger_refused=True,
            original_claims_preserved=True, physical_backend_fit=False,
            native_dispatch_started=False, complete_ringct_workflow=False), values)
        for name in values:
            integer(cap[name], 0 if 'device_bytes' in name else 1)
        require(cap['original_claims_host_bytes'] == claimed_host
                and cap['simultaneous_host_bytes'] == claimed_host + cap['startup_host_bytes']
                    + cap['phase_wrappers_host_bytes'] + cap['pcs_host_bytes']
                and cap['simultaneous_device_bytes'] == claimed_device + cap['startup_device_bytes']
                    + cap['phase_wrappers_device_bytes'] + cap['pcs_device_bytes'] == 8 * GIB
                and cap['simultaneous_host_bytes'] <= peak_host and peak_device == 8 * GIB
                and cap['pcs_host_bytes'] <= 24 * GIB
                and wall >= cap['source_preissue_ns'] >= cap['projection_ns'], 'first-leaf projection does not conserve original quota/time')
        return dict(mode=mode, native_proofs=0, recursive_proofs=0, quota_projection=cap,
                    physical_backend_fit=False, complete_ringct_workflow=False)
    pre, complete = events[1][1], events[-2][1]
    fixed(pre, dict(native_proofs_expected=10, recursive_proofs_expected=1,
        wrong_request_and_ledger_refused=True, native_dispatch_started=False,
        complete_request_admitted=False), ('source_preissue_ns', 'host_bytes', 'device_bytes'))
    preissue = integer(pre['source_preissue_ns'], 1)
    integer(pre['host_bytes'], claimed_host, peak_host)
    require(type(pre['device_bytes']) is int and pre['device_bytes'] == peak_device == 8 * GIB,
            'first-leaf original device claim differs')
    entries = ['ringct_owned_native_shake'] * 10 + ['block_v2_preprocessing', 'block_v2_registered_program']
    elapsed = [receipt_check(event[1], entry) for event, entry in zip(events[2:14], entries)]
    times = ('compiler_ns', 'setup_ns', 'proving_ns', 'output_cpu_verification_ns',
             'source_cpu_verification_ns', 'component_including_mutations_ns')
    fixed(complete, dict(native_proofs=10, recursive_proofs=1, recursive_parent_proofs=0,
        mutation_rejections=2, source_key_authenticated=True, transaction_context_authenticated=False,
        complete_ringct_workflow=False), ('active_rows', 'padded_rows', 'wires', 'input_values') + times)
    active = integer(complete['active_rows'], 1, 1 << 20)
    padded = integer(complete['padded_rows'], active, 1 << 20)
    require(padded & (padded - 1) == 0, 'first-leaf padded height is not a power of two')
    integer(complete['wires'], 1, 1 << 26)
    integer(complete['input_values'], 1, 1 << 26)
    for name in times:
        integer(complete[name], 1)
    require(complete['setup_ns'] == elapsed[10] and complete['proving_ns'] == elapsed[11],
            'first-leaf report timing differs from actual stage receipts')
    lower = preissue + sum(elapsed) + complete['compiler_ns'] + complete['output_cpu_verification_ns'] + complete['source_cpu_verification_ns']
    require(wall >= complete['component_including_mutations_ns'] >= lower,
            'first-leaf timing does not enclose serialized stages')
    return dict(mode=mode, native_proofs=10, recursive_proofs=1, recursive_parent_proofs=0,
                stage_receipts=12, component=complete, terminal_zero_claims=True,
                fresh_only=True, gpu_required=True, complete_ringct_workflow=False,
                performance_qualified=False)
