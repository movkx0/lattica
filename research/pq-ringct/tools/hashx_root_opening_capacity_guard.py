"""Exact CPU-only opening admission projection; no proof or GPU authority."""
from hashlib import sha256
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re


def _gpu_contract():
    path = Path(__file__).with_name('hashx_root_opening_gpu_guard.py')
    spec = importlib.util.spec_from_file_location('root_opening_capacity_shared_contract', path)
    if spec is None or spec.loader is None:
        raise ValueError('missing maintained root-opening source contract')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gpu = _gpu_contract()
require, exact, fields = gpu.require, gpu.exact, gpu.fields
GIB, HOST, DEVICE, U128_MAX = gpu.GIB, gpu.HOST, gpu.DEVICE, gpu.U128_MAX
NATIVE_HOST = 24 * GIB
STARTUP_DEVICE = (64 << 20) + (32 + 22 + 32 + 8) * 8
SELECTOR = ('component_tree::owned_shake::request_merge::source::capture::acceptance::'
            'parent::production::sequence::qualification::opening::'
            'cpu_original_hashx_sequence_root_opening_capacity')
FLAG = 'LATTICA_OWNED_HASHX_ROOT_OPENING_SOURCE_QUALIFICATION'
SEQUENCE_FLAG = 'LATTICA_OWNED_HASHX_SEQUENCE_SOURCE_QUALIFICATION'
ENV_KEY = 'owned_source_shape_environment'
BINDING_KEY = 'owned_hashx_root_opening_capacity_binding'
EXCLUSIVE = tuple(key for key in gpu.EXCLUSIVE if key != 'owned_source_shape_test') + ('owned_hashx_root_opening_test',)
FOREIGN_RECEIPTS = tuple(key for key in gpu.FOREIGN_RECEIPTS if key != ENV_KEY) + (gpu.ENV_KEY,)
REQUIRED_SOURCES = tuple(sorted(set(gpu.REQUIRED_SOURCES) | {
    'research/pq-ringct/tools/hashx_root_opening_capacity_guard.py',
    'research/pq-ringct/tools/test_hashx_root_opening_capacity_guard.py',
    'research/pq-ringct/tools/test_hashx_root_opening_capacity_runner.py',
}))
ROOT_CLAIMS = gpu.ROOT_CLAIMS
SOURCE_CLAIMS = gpu.SOURCE_CLAIMS
CAPACITY_COMPLETE = 'ringct_hashx_sequence_capacity_complete'
TERMINAL = gpu.TERMINAL
MARKERS = (ROOT_CLAIMS, SOURCE_CLAIMS, CAPACITY_COMPLETE, TERMINAL)
ROOT_FIXED = dict(gpu.ROOT_FIXED, mode='root-opening-capacity')
SOURCE_FIXED = dict(gpu.SOURCE_FIXED, mode='root-opening-capacity')
CAPACITY_FIXED = dict(native_proofs='0', recursive_proofs='0', wrong_request_and_ledger_refused='true',
                      original_claims_preserved='true', physical_backend_fit='false',
                      native_dispatch_started='false', complete_ringct_workflow='false')
TERMINAL_FIXED = dict(gpu.TERMINAL_FIXED, mode='root-opening-capacity', component_success='false')
CAPACITY_NUMBERS = ('original_claims_host_bytes', 'startup_host_bytes', 'startup_device_bytes',
                    'phase_wrappers_host_bytes', 'phase_wrappers_device_bytes', 'pcs_host_bytes',
                    'pcs_device_bytes', 'simultaneous_host_bytes', 'simultaneous_device_bytes', 'projection_ns')
TERMINAL_NUMBERS = ('peak_host_bytes', 'peak_device_bytes', 'component_through_destruction_ns',
                    'terminal_observer_fixed_host_bytes')


def expected_environment(root):
    environment = gpu.helper('hashx_first_leaf_guard').expected_environment('capacity', root)
    environment[SEQUENCE_FLAG] = '1'
    environment[FLAG] = '1'
    require(environment.get('LATTICA_PROVING_POLICY') == 'cpu-required'
            and environment.get('RAYON_NUM_THREADS') == '2'
            and not any('GPU' in key for key in environment), 'opening capacity CPU base changed')
    return environment


def receipt(environment):
    require(type(environment) is dict and all(type(k) is str and type(v) is str and k
            and '=' not in k and '\0' not in k + v for k, v in environment.items()),
            'malformed root-opening capacity environment')
    encoded = b''.join((key + '=' + environment[key] + '\0').encode() for key in sorted(environment))
    require(len(environment) <= 64 and len(encoded) <= 8192, 'root-opening capacity environment bound')
    return dict(schema='ringct-root-opening-capacity-environment-v1', mode='root-opening-capacity',
                selector=SELECTOR, entry_count=len(environment), serialized_bytes=len(encoded),
                sha256_sorted_name_equals_value_nul=sha256(encoded).hexdigest(),
                requires_env_clear_before_exec=True, requires_immutable_environment_after_exec=True,
                scope='source-planning-only', gpu_dispatch=False, dispatch_authority=False,
                complete_faithful_ringct_workflow=False, performance_qualified=False)


def exact_command(command):
    require(type(command) is list and len(command) == 6 and gpu.absolute(command[0])
            and PurePosixPath(command[0]).name.startswith('lattica_pq_ringct_research-')
            and command[1:] == [SELECTOR, '--exact', '--ignored', '--test-threads=1', '--nocapture'],
            'opening capacity requires its exact recorded isolated CPU selector')


def build_environment(args, base, root, kernel, tree_storage):
    require(getattr(args, 'owned_source_shape_test', None) is True, 'opening capacity requires source-only mode')
    command = list(args.command)
    if command[:1] == ['--']:
        command.pop(0)
    exact_command(command)
    require(args.profile == 'research-compile-large' and args.expect_tests is True and args.build_label,
            'opening capacity requires its recorded CPU research profile')
    require(not any(bool(getattr(args, key, False)) for key in EXCLUSIVE), 'opening capacity mode is exclusive')
    require(kernel == 'baseline' and tree_storage == 'device' and getattr(args, 'device_uuid', None) is None,
            'opening capacity cannot select GPU device, storage or kernel')
    environment = expected_environment(root)
    expected_base = dict(environment)
    expected_base.pop(FLAG)
    expected_base.pop(SEQUENCE_FLAG)
    require(base == expected_base, 'opening capacity fixed CPU startup base changed')
    return environment, receipt(environment)


def bind_execution(plan, sources, executable, root):
    require(gpu.absolute(root), 'opening capacity source root is not absolute')
    exact_command(plan.get('command'))
    expected = expected_environment(root)
    require(plan.get('environment') == expected and exact(plan.get(ENV_KEY), receipt(expected)),
            'opening capacity environment or receipt changed')
    require(all(plan.get(key) is None for key in FOREIGN_RECEIPTS), 'foreign opening capacity qualification mode')
    resources = dict(memory_max_bytes=32 * GIB, memory_high_bytes=30 * GIB, fresh_memavailable_required_bytes=36 * GIB)
    require(all(type(plan.get(key)) is int and plan[key] == value for key, value in resources.items())
            and plan.get('profile') == 'research-compile-large' and plan.get('expect_tests') is True
            and plan.get('cpu_quota') == '200%' and plan.get('benchmark') is False
            and plan.get('performance_qualified') is False and plan.get('comparison_baseline') is False
            and plan.get('public_hash_kernel') == 'baseline' and plan.get('expect_result') is False
            and plan.get('expect_direct_result') is False and plan.get('correctness_label') is None
            and plan.get('record_artifacts') == [], 'opening capacity resource/profile contract changed')
    require(type(plan.get('runtime_seconds')) is int and 1 <= plan['runtime_seconds'] <= 86400,
            'opening capacity runtime bound changed')
    require(type(sources) is dict and all(path in sources for path in REQUIRED_SOURCES),
            'opening capacity source manifest incomplete')
    require(all(type(path) is str and path and '\0' not in path and not PurePosixPath(path).is_absolute()
                and '..' not in PurePosixPath(path).parts and str(PurePosixPath(path)) == path and gpu.digest(value)
                for path, value in sources.items()), 'malformed opening capacity source manifest')
    label = plan.get('build_label')
    require(type(label) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,55}', label),
            'opening capacity recorded build absent')
    require(type(executable) is dict and executable.get('path') == plan['command'][0]
            and gpu.absolute(executable.get('resolved_path')) and gpu.digest(executable.get('sha256'))
            and executable.get('build_record') == root + '/.tools/pq-opencl-opt/runs/' + label + '.json'
            and gpu.digest(executable.get('build_record_sha256')), 'opening capacity executable binding differs')
    return dict(schema='ringct-root-opening-capacity-binding-v1', mode='root-opening-capacity', selector=SELECTOR,
                source_root=root, source_manifest_sha256=sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest(),
                executable_sha256=executable['sha256'], resolved_executable=executable['resolved_path'],
                build_record_sha256=executable['build_record_sha256'],
                environment_sha256=plan[ENV_KEY]['sha256_sorted_name_equals_value_nul'],
                selected_physical_device_uuid=None, requires_terminal_reaping_and_unchanged_sources=True,
                requires_independent_terminal_process_audit=True, dispatch_authority=False,
                complete_ringct_workflow=False, performance_qualified=False)


def validate_log(content, plan):
    binding = plan.get(BINDING_KEY)
    require(type(binding) is dict and gpu.absolute(binding.get('source_root')), 'opening capacity binding absent')
    require(exact(binding, bind_execution(plan, plan.get('input_sha256'), plan.get('executable_provenance'),
                                         binding['source_root'])), 'opening capacity original binding changed')
    observation = plan.get('observation_before_validation_ns')
    require(type(observation) is int and 0 < observation <= U128_MAX, 'opening capacity runner observation absent')
    require(type(content) is str and len(content) <= 16 << 20, 'opening capacity log text/bound differs')
    require(not any(token in content for token in ('proving_stage_report', 'NATIVE_EXECUTION_RECEIPT',
            'PUBLIC_HASH_EXECUTION', 'OPENCL_OPT_RESULT', 'DIRECT_SPEND_RESULT', 'DIRECT_RING_RESULT',
            'bounded_decoded_proof_storage', 'transport_schema_case', 'opening_schema_case',
            'retained_output_immutable', 'panicked at', 'FAILED',
            'fallback=true', 'retry=true')), 'opening capacity emitted proof, decode, synthetic or failed evidence')
    headers = list(re.finditer(r'^test (\S+) \.\.\. ([^\n]*)$', content, re.M))
    completions = list(re.finditer(r'^ok$', content, re.M))
    footers = list(re.finditer(r'^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; '
                             r'(?:0|[1-9][0-9]*) filtered out; finished in [0-9]+\.[0-9]+s$', content, re.M))
    require(len(headers) == len(completions) == len(footers) == 1 and headers[0].group(1) == SELECTOR
            and gpu.valid_header_payload(headers[0].group(2)) and content.count('test result:') == 1,
            'opening capacity requires its exact passing isolated test/footer')
    prefix = 'test ' + SELECTOR + ' ... '
    require(content.count(prefix) == 1, 'duplicate opening capacity invocation')
    events = []
    observer_bytes = 0
    for line_number, line in enumerate(content.splitlines()):
        if line.startswith(prefix):
            line = line[len(prefix):]
        names = re.findall(r'\bringct_[A-Za-z0-9_]+', line)
        if names or 'ringct_' in line:
            require(len(names) == 1 and names[0] in MARKERS and line.startswith(names[0] + ' '),
                    'foreign or malformed opening capacity marker')
            name, body = line.split(' ', 1)
            if name == TERMINAL:
                require(line.isascii(), 'opening capacity observer must be ASCII')
                observer_bytes = len(line) + 1
            events.append((name, body, line_number))
    require([name for name, _, _ in events] == list(MARKERS),
            'missing, duplicate or reordered opening capacity events')
    require(observer_bytes <= gpu.OBSERVER_EVENT_LIMIT, 'opening capacity observer output bound')
    header_line = content[:headers[0].start()].count('\n')
    completion_line = content[:completions[0].start()].count('\n')
    require(header_line <= events[0][2] and events[-1][2] < completion_line
            and completions[0].start() < footers[0].start(), 'opening capacity events outside isolated invocation')
    root = fields(events[0][1], ROOT_FIXED, gpu.ROOT_NUMBERS)
    source = fields(events[1][1], SOURCE_FIXED, ('host_bytes', 'device_bytes'))
    capacity = fields(events[2][1], CAPACITY_FIXED, CAPACITY_NUMBERS)
    terminal = fields(events[3][1], TERMINAL_FIXED, TERMINAL_NUMBERS)
    gpu.validate_claims(root, source)
    require(capacity['original_claims_host_bytes'] == source['host_bytes'], 'opening capacity originals changed')
    require(capacity['startup_host_bytes'] > DEVICE and capacity['phase_wrappers_host_bytes'] > 0
            and 0 < capacity['pcs_host_bytes'] <= NATIVE_HOST, 'opening capacity host quota pieces changed')
    require(capacity['startup_device_bytes'] == STARTUP_DEVICE and capacity['phase_wrappers_device_bytes'] == 0
            and capacity['pcs_device_bytes'] == DEVICE - STARTUP_DEVICE,
            'opening capacity original device quota pieces changed')
    remaining = HOST - source['host_bytes'] - capacity['startup_host_bytes'] - capacity['phase_wrappers_host_bytes']
    require(capacity['pcs_host_bytes'] == min(NATIVE_HOST, remaining),
            'opening capacity PCS projection does not use original remaining allowance')
    host = source['host_bytes'] + sum(capacity[key] for key in
        ('startup_host_bytes', 'phase_wrappers_host_bytes', 'pcs_host_bytes'))
    device = source['device_bytes'] + sum(capacity[key] for key in
        ('startup_device_bytes', 'phase_wrappers_device_bytes', 'pcs_device_bytes'))
    require(host == capacity['simultaneous_host_bytes'] <= HOST
            and device == capacity['simultaneous_device_bytes'] == DEVICE,
            'opening capacity simultaneous original-ledger projection differs')
    require(host <= terminal['peak_host_bytes'] <= HOST and device == terminal['peak_device_bytes'],
            'opening capacity projected terminal peaks disagree')
    require(0 < terminal['terminal_observer_fixed_host_bytes'] <= gpu.OBSERVER_HOST_LIMIT,
            'opening capacity process-only observer census differs')
    require(0 < capacity['projection_ns'] <= terminal['component_through_destruction_ns'] <= observation,
            'opening capacity timing exceeds cleanup or runner observation')
    return dict(schema='ringct-root-opening-capacity-qualification-v1', scope='root-opening-quota-projection-only',
                cpu_heights=18, native_proofs=0, recursive_proofs=0, stage_receipts=0,
                numerical_positive_checks=0, typed_opening_relation_rejections=0, actual_opening_probes=0,
                root_opening_claims=root, source_claims=source, quota_projection=capacity, terminal=terminal,
                memory_peak_kind='original-ledger-projected-quota', original_quota_released=True,
                owner_quota_cleanup_complete=True, wrong_request_and_ledger_refused=True, original_claims_preserved=True,
                terminal_observer_scope='process-audit-only', terminal_observer_event_bytes=observer_bytes,
                released_claims_cover_terminal_observer=False, terminal_observer_census_is_physical_measurement=False,
                process_engine_device_audit_complete=False, native_dispatch_started=False, physical_backend_fit=False,
                actual_proving_fit=False, root_opening_probe_complete=False, transaction_context_authenticated=False,
                raw_proof_mutation_checks_complete=False, interior_mutation_checks_complete=False,
                mutation_checks_complete=False, disk_artifact_roundtrip_complete=False,
                artifact_roundtrip_complete=False, complete_ringct_workflow=False, performance_qualified=False)
