"""Exact source-bound GPU opening probe; never complete RingCT workflow evidence."""
from hashlib import sha256
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re


def _maintained_contract():
    path = Path(__file__).with_name('hashx_root_transport_gpu_guard.py')
    spec = importlib.util.spec_from_file_location('root_opening_shared_contract', path)
    if spec is None or spec.loader is None:
        raise ValueError('missing maintained original-root sequence contract')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


shared = _maintained_contract()
require, exact, fields = shared.require, shared.exact, shared.fields
helper, digest, absolute = shared.helper, shared.digest, shared.absolute
decode_report, geometry = shared.decode_report, shared.geometry
GIB, HOST, DEVICE = shared.GIB, shared.HOST, shared.DEVICE
U64_MAX, U128_MAX = shared.U64_MAX, shared.U128_MAX
SEQUENCE = shared.SEQUENCE
SELECTOR = ('component_tree::owned_shake::request_merge::source::capture::acceptance::'
            'parent::production::sequence::qualification::opening::'
            'gpu_original_hashx_sequence_root_opening_recheck')
FLAG = 'LATTICA_OWNED_HASHX_ROOT_OPENING_QUALIFICATION'
ENV_KEY = 'owned_hashx_root_opening_environment'
BINDING_KEY = 'owned_hashx_root_opening_binding'
EXCLUSIVE = tuple(key for key in shared.EXCLUSIVE if key != 'owned_hashx_root_opening_test') + (
    'owned_hashx_root_transport_test',)
FOREIGN_RECEIPTS = tuple(key for key in shared.FOREIGN_RECEIPTS if key != ENV_KEY) + (shared.ENV_KEY,)
# Keep the inherited complete sequence, original B066 mutation/classification,
# private adapters and maintained parser dependencies in this exact source set.
REQUIRED_SOURCES = tuple(sorted(set(shared.REQUIRED_SOURCES) | {
    SEQUENCE + '/qualification/opening.rs',
    SEQUENCE + '/qualification/opening/BOUNDS.md',
    SEQUENCE + '/qualification/opening/claims.rs',
    SEQUENCE + '/qualification/opening/claims/BOUNDS.md',
    SEQUENCE + '/qualification/opening/claims/tests.rs',
    'research/pq-ringct/tools/hashx_root_transport_capacity_guard.py',
    'research/pq-ringct/tools/test_hashx_root_transport_capacity_guard.py',
    'research/pq-ringct/tools/test_hashx_root_transport_capacity_runner.py',
    'research/pq-ringct/tools/hashx_root_opening_gpu_guard.py',
    'research/pq-ringct/tools/test_hashx_root_opening_gpu_guard.py',
    'research/pq-ringct/tools/test_hashx_root_opening_gpu_runner.py',
    'research/pq-ringct/tools/test_hashx_root_opening_reciprocal_guards.py',
}))
ROOT_CLAIMS = 'ringct_hashx_root_opening_claims'
SOURCE_CLAIMS = shared.SOURCE_CLAIMS
LEAF, PARENT, ACCEPTANCE = shared.LEAF, shared.PARENT, shared.ACCEPTANCE
ROOT_SCOPE = 'ringct_hashx_root_opening_scope'
COMPLETE = 'ringct_hashx_root_opening_complete'
TERMINAL = shared.TERMINAL
MARKERS = (ROOT_CLAIMS, SOURCE_CLAIMS, LEAF, PARENT, ACCEPTANCE, ROOT_SCOPE, COMPLETE, TERMINAL)
LEAF_SPANS, PARENT_SPANS, ORDER, ENTRIES = shared.LEAF_SPANS, shared.PARENT_SPANS, shared.ORDER, shared.ENTRIES
PROVISIONAL = shared.PROVISIONAL
OBSERVER_EVENT_LIMIT, OBSERVER_HOST_LIMIT = shared.OBSERVER_EVENT_LIMIT, shared.OBSERVER_HOST_LIMIT
ROOT_FIXED = {'actual_opening_probes': '0', 'complete_ringct_workflow': 'false', 'cpu_heights': '18', 'mode': 'root-opening', 'native_dispatch_started': 'false', 'planned_opening_probes': '1'}
SOURCE_FIXED = {'complete_ringct_workflow': 'false', 'leaf_output_claims': '5', 'mode': 'root-opening', 'native_attachments': '10', 'native_dispatch_started': 'false', 'native_outputs': '10', 'original_compiler_bank': '1', 'original_outer_sequence': 'true', 'parent_output_claims': '4', 'retained_leaf_sources': '5', 'retained_parent_sources': '4', 'source_acceptance_claims': '9'}
ROOT_SCOPE_FIXED = {'artifact_roundtrip_complete': 'false', 'complete_ringct_workflow': 'false', 'cpu_heights': '18', 'disk_artifact_roundtrip_complete': 'false', 'interior_mutation_checks_complete': 'false', 'mutation_checks_complete': 'false', 'numerical_positive_checks': '2', 'opening_scope': 'single-root-first-local-permutation-opening', 'provisional': 'true', 'raw_proof_mutation_checks_complete': 'false', 'retained_output_restored': 'true', 'source_key_authenticated': 'true', 'terminal_cleanup_complete': 'false', 'transaction_context_authenticated': 'false', 'typed_opening_relation_rejections': '1'}
COMPLETE_FIXED = {'artifact_roundtrip_complete': 'false', 'compiler_reclamations': '9', 'complete_ringct_workflow': 'false', 'cpu_heights': '18', 'disk_artifact_roundtrip_complete': 'false', 'first_unit': '0', 'interior_mutation_checks_complete': 'false', 'level': '3', 'mutation_checks_complete': 'false', 'native_proofs': '10', 'numerical_positive_checks': '2', 'opening_scope': 'single-root-first-local-permutation-opening', 'original_quota_released': 'true', 'owner_quota_cleanup_complete': 'true', 'process_engine_device_audit_complete': 'false', 'raw_proof_mutation_checks_complete': 'false', 'recursive_leaf_proofs': '5', 'recursive_parent_proofs': '4', 'recursive_proofs': '9', 'released_claims_cover_terminal_observer': 'false', 'retained_output_restored': 'true', 'root_opening_probe_complete': 'true', 'source_key_authenticated': 'true', 'terminal_observer_scope': 'process-audit-only', 'transaction_context_authenticated': 'false', 'typed_opening_relation_rejections': '1', 'units': '122'}
TERMINAL_FIXED = {'artifact_roundtrip_complete': 'false', 'complete_ringct_workflow': 'false', 'component_success': 'true', 'current_device_bytes': '0', 'current_host_bytes': '0', 'mode': 'root-opening', 'mutation_checks_complete': 'false', 'original_quota_released': 'true', 'process_engine_device_audit_complete': 'false', 'released_claims_cover_terminal_observer': 'false', 'terminal_observer_scope': 'process-audit-only'}
ROOT_NUMBERS = ('probe_verifier_host_bytes', 'probe_caller_host_bytes', 'probe_host_bytes', 'driver_host_bytes', 'total_host_bytes')
SCOPE_NUMBERS = ('positive_verification_ns', 'mutation_verification_ns', 'opening_action_ns')
COUNTS = dict(cpu_heights='18', numerical_positive_checks='2', typed_opening_relation_rejections='1')
NO_WIDER_CHECKS = {key: 'false' for key in ('raw_proof_mutation_checks_complete', 'interior_mutation_checks_complete', 'mutation_checks_complete', 'disk_artifact_roundtrip_complete', 'artifact_roundtrip_complete', 'complete_ringct_workflow')}



def expected_environment(root, uuid):
    environment = helper('hashx_sequence_preissue_guard').expected_environment(root, uuid)
    require(environment.get('LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION') == '1',
            'maintained full sequence environment changed')
    environment[FLAG] = '1'
    return environment


def receipt(environment):
    require(type(environment) is dict and all(type(k) is str and type(v) is str and k
            and '=' not in k and '\0' not in k + v for k, v in environment.items()),
            'malformed root-opening GPU environment')
    encoded = b''.join((key + '=' + environment[key] + '\0').encode() for key in sorted(environment))
    require(len(environment) <= 64 and len(encoded) <= 8192, 'root-opening GPU environment bound')
    return dict(schema='ringct-root-opening-gpu-environment-v1', mode='root-opening', selector=SELECTOR,
                entry_count=len(environment), serialized_bytes=len(encoded),
                sha256_sorted_name_equals_value_nul=sha256(encoded).hexdigest(),
                requires_env_clear_before_exec=True, requires_immutable_environment_after_exec=True,
                dispatch_authority=False, complete_ringct_workflow=False, performance_qualified=False)


def exact_command(command):
    require(type(command) is list and len(command) == 6 and absolute(command[0])
            and PurePosixPath(command[0]).name.startswith('lattica_pq_ringct_research-')
            and command[1:] == [SELECTOR, '--exact', '--ignored', '--test-threads=1', '--nocapture'],
            'root-opening GPU requires its exact recorded isolated test')


def build_environment(args, base, root, kernel, tree_storage):
    require(getattr(args, 'owned_hashx_root_opening_test', None) == 'gpu', 'unknown root-opening GPU mode')
    command = list(args.command)
    if command[:1] == ['--']:
        command.pop(0)
    exact_command(command)
    require(args.profile == 'full' and args.expect_tests is True and args.build_label,
            'root-opening GPU requires recorded full profile')
    require(not any(bool(getattr(args, key, False)) for key in EXCLUSIVE), 'root-opening GPU mode is exclusive')
    require(kernel == 'baseline' and tree_storage == 'host', 'root-opening GPU hash/tree mode changed')
    environment = expected_environment(root, getattr(args, 'device_uuid', None))
    expected_base = dict(environment)
    for flag in (FLAG, 'LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION', 'LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'):
        expected_base.pop(flag)
    expected_base['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'device'
    require(base == expected_base, 'root-opening GPU fixed startup base changed')
    return environment, receipt(environment)


def bind_execution(plan, sources, executable, root):
    require(absolute(root), 'root-opening GPU source root is not absolute')
    exact_command(plan.get('command'))
    environment = plan.get('environment')
    require(type(environment) is dict, 'root-opening GPU environment absent')
    expected = expected_environment(root, environment.get('LATTICA_GPU_DEVICE_UUID'))
    require(environment == expected and exact(plan.get(ENV_KEY), receipt(expected)),
            'root-opening GPU environment or receipt changed')
    require(all(plan.get(key) is None for key in FOREIGN_RECEIPTS), 'foreign root-opening qualification mode')
    resources = dict(memory_max_bytes=47 * GIB, memory_high_bytes=45 * GIB, fresh_memavailable_required_bytes=49 * GIB)
    require(all(type(plan.get(key)) is int and plan[key] == value for key, value in resources.items())
            and plan.get('profile') == 'full' and plan.get('expect_tests') is True
            and plan.get('cpu_quota') == '800%' and plan.get('benchmark') is False
            and plan.get('performance_qualified') is False and plan.get('comparison_baseline') is False
            and plan.get('public_hash_kernel') == 'baseline' and plan.get('expect_result') is False
            and plan.get('expect_direct_result') is False and plan.get('correctness_label') is None
            and plan.get('record_artifacts') == [], 'root-opening GPU resource/profile contract changed')
    require(type(plan.get('runtime_seconds')) is int and 1 <= plan['runtime_seconds'] <= 86400,
            'root-opening GPU runtime bound changed')
    require(type(sources) is dict and all(path in sources for path in REQUIRED_SOURCES),
            'root-opening GPU source manifest incomplete')
    require(all(type(path) is str and path and '\0' not in path and not PurePosixPath(path).is_absolute()
                and '..' not in PurePosixPath(path).parts and str(PurePosixPath(path)) == path and digest(value) for path, value in sources.items()),
            'malformed root-opening GPU source manifest')
    label = plan.get('build_label')
    require(type(label) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,55}', label),
            'root-opening GPU recorded build absent')
    require(type(executable) is dict and executable.get('path') == plan['command'][0]
            and absolute(executable.get('resolved_path')) and digest(executable.get('sha256'))
            and executable.get('build_record') == root + '/.tools/pq-opencl-opt/runs/' + label + '.json'
            and digest(executable.get('build_record_sha256')), 'root-opening GPU executable binding differs')
    return dict(schema='ringct-root-opening-gpu-binding-v1', mode='root-opening', selector=SELECTOR, source_root=root,
                resolved_executable=executable['resolved_path'],
                source_manifest_sha256=sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest(),
                executable_sha256=executable['sha256'], build_record_sha256=executable['build_record_sha256'],
                environment_sha256=plan[ENV_KEY]['sha256_sorted_name_equals_value_nul'],
                selected_physical_device_uuid=environment['LATTICA_GPU_DEVICE_UUID'],
                requires_terminal_reaping_and_unchanged_sources=True, requires_independent_physical_device_audit=True,
                dispatch_authority=False, complete_ringct_workflow=False, performance_qualified=False)


def valid_header_payload(payload):
    if payload == '' or payload.startswith(ROOT_CLAIMS + ' '):
        return True
    number = r'(0|[1-9][0-9]{0,19})'
    growth = re.fullmatch(r'bounded_proof_input_growth old_values=' + number + r' new_values=' + number
                         + r' live_bytes=' + number + r' value_limit=' + number, payload)
    if growth is None:
        return False
    old, new, live, limit = map(int, growth.groups())
    return (0 < limit <= 1 << 20 and 0 <= old < new <= limit
            and new == min(max(old * 2, 4), limit) and live == (old + new) * 8)


def validate_claims(root, source):
    """Two independently reserved owners, included in the same source snapshot."""
    require(0 < source['host_bytes'] <= HOST and source['device_bytes'] == 0,
            'root-opening original source claims differ')
    require(root['probe_verifier_host_bytes'] > 0
            and root['probe_caller_host_bytes'] > (64 << 10)
            and root['driver_host_bytes'] > (64 << 10)
            and root['probe_host_bytes'] == root['probe_verifier_host_bytes'] + root['probe_caller_host_bytes']
            and root['total_host_bytes'] == root['probe_host_bytes'] + root['driver_host_bytes']
            and root['total_host_bytes'] <= source['host_bytes'],
            'root-opening independent probe and complete driver claims are incomplete or unbacked')


def validate_log(content, plan):
    binding = plan.get(BINDING_KEY)
    require(type(binding) is dict and absolute(binding.get('source_root')), 'root-opening GPU binding absent')
    require(exact(binding, bind_execution(plan, plan.get('input_sha256'), plan.get('executable_provenance'),
                                         binding['source_root'])), 'root-opening GPU original binding changed')
    observation = plan.get('observation_before_validation_ns')
    require(type(observation) is int and 0 < observation <= U128_MAX, 'root-opening runner observation absent')
    require(type(content) is str and len(content) <= 16 << 20, 'root-opening log text/bound differs')
    require(not any(token in content for token in ('panicked at', 'FAILED', 'OPENCL_OPT_RESULT',
            'DIRECT_SPEND_RESULT', 'DIRECT_RING_RESULT', 'NATIVE_EXECUTION_RECEIPT', 'PUBLIC_HASH_EXECUTION',
            'fallback=true', 'retry=true', 'transport_schema_case', 'opening_schema_case', 'bounded_decoded_proof_storage',
            'retained_output_immutable')),
            'root-opening log contains foreign, synthetic or failed evidence')
    headers = list(re.finditer(r'^test (\S+) \.\.\. ([^\n]*)$', content, re.M))
    completions = list(re.finditer(r'^ok$', content, re.M))
    footers = list(re.finditer(r'^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; '
                             r'(?:0|[1-9][0-9]*) filtered out; finished in [0-9]+\.[0-9]+s$', content, re.M))
    require(len(headers) == len(completions) == len(footers) == 1 and headers[0].group(1) == SELECTOR
            and valid_header_payload(headers[0].group(2)) and content.count('test result:') == 1,
            'root-opening requires its exact passing isolated test/footer')
    header_prefix = 'test ' + SELECTOR + ' ... '
    require(content.count(header_prefix) == 1, 'duplicate root-opening invocation')
    events = []
    observer_bytes = 0
    for line_number, line in enumerate(content.splitlines()):
        if line.startswith(header_prefix):
            line = line[len(header_prefix):]
        if line.startswith('proving_stage_report '):
            events.append(('receipt', decode_report(line.removeprefix('proving_stage_report ')), line_number))
            continue
        require('proving_stage_report' not in line, 'misplaced root-opening receipt')
        names = re.findall(r'\bringct_[A-Za-z0-9_]+', line)
        if names or 'ringct_' in line:
            require(len(names) == 1 and names[0] in MARKERS and line.startswith(names[0] + ' '),
                    'foreign or malformed root-opening marker')
            name, body = line.split(' ', 1)
            if name in (COMPLETE, TERMINAL):
                require(line.isascii(), 'root-opening observer event must be ASCII')
                observer_bytes += len(line) + 1
            events.append((name, body, line_number))
    expected_order = [ROOT_CLAIMS, SOURCE_CLAIMS] + ['receipt'] * 28 + [LEAF] * 5 + [PARENT] * 4
    expected_order += [ACCEPTANCE, ROOT_SCOPE, COMPLETE, TERMINAL]
    require([name for name, _, _ in events] == expected_order,
            'missing, duplicate or reordered root-opening events')
    require(observer_bytes <= OBSERVER_EVENT_LIMIT, 'root-opening terminal observer event bound')
    header_line = content[:headers[0].start()].count('\n')
    completion_line = content[:completions[0].start()].count('\n')
    require(header_line <= events[0][2] and events[-1][2] < completion_line
            and completions[0].start() < footers[0].start(), 'root-opening events outside invocation/completion')

    root = fields(events[0][1], ROOT_FIXED, ROOT_NUMBERS)
    source = fields(events[1][1], SOURCE_FIXED, ('host_bytes', 'device_bytes'))
    validate_claims(root, source)

    receipt_check = helper('native_sequence_report').receipt
    elapsed = [receipt_check(event[1], entry) for event, entry in zip(events[2:30], ENTRIES)]
    metrics = ('active_rows', 'padded_rows', 'wires', 'input_values', 'compiler_ns', 'source_cpu_verification_ns')
    leaves, parents = [], []
    for ordinal, (first, units) in enumerate(LEAF_SPANS):
        fixed = dict(PROVISIONAL, ordinal=str(ordinal), first_segment=str(2 * ordinal), segment_count='2',
                     first_unit=str(first), units=str(units))
        record = fields(events[30 + ordinal][1], fixed, metrics)
        geometry(record)
        leaves.append(dict(record, ordinal=ordinal, first_segment=2 * ordinal, segment_count=2,
                           first_unit=first, units=units))
    for ordinal, (first, units, level) in enumerate(PARENT_SPANS):
        fixed = dict(PROVISIONAL, ordinal=str(ordinal), first_unit=str(first), units=str(units), level=str(level))
        record = fields(events[35 + ordinal][1], fixed, metrics)
        geometry(record)
        parents.append(dict(record, ordinal=ordinal, first_unit=first, units=units, level=level))
    acceptance = fields(events[39][1], dict(PROVISIONAL, first_unit='0', units='122', level='3',
                        mutation_checks_complete='false', artifact_roundtrip_complete='false'),
                        ('preparation_through_acceptance_ns',))
    opening = fields(events[40][1], ROOT_SCOPE_FIXED, SCOPE_NUMBERS)
    complete = fields(events[41][1], COMPLETE_FIXED,
                      ('component_through_destruction_ns', 'terminal_observer_fixed_host_bytes'))
    terminal = fields(events[42][1], TERMINAL_FIXED,
                      ('peak_host_bytes', 'peak_device_bytes', 'component_through_destruction_ns',
                       'terminal_observer_fixed_host_bytes'))
    require(source['host_bytes'] + DEVICE <= terminal['peak_host_bytes'] <= HOST
            and terminal['peak_device_bytes'] == DEVICE, 'root-opening terminal memory peaks disagree')
    require(0 < complete['terminal_observer_fixed_host_bytes']
            == terminal['terminal_observer_fixed_host_bytes'] <= OBSERVER_HOST_LIMIT,
            'root-opening process-only terminal observer census differs')
    require(opening['positive_verification_ns'] > 0 and opening['mutation_verification_ns'] > 0
            and opening['positive_verification_ns'] + opening['mutation_verification_ns'] <= opening['opening_action_ns'],
            'root-opening positive and typed-negative timings exceed enclosing action')
    preparation = acceptance['preparation_through_acceptance_ns']
    # These pinned phases are serialized. Nested device and inclusive timings
    # are never summed. The opening action excludes preparation/destruction.
    serialized = sum(elapsed) + sum(item['compiler_ns'] + item['source_cpu_verification_ns']
                                  for item in leaves + parents)
    require(preparation >= serialized and complete['component_through_destruction_ns']
            == terminal['component_through_destruction_ns'] <= observation
            and terminal['component_through_destruction_ns'] >= preparation + opening['opening_action_ns'],
            'root-opening timers do not enclose serialized work and destruction')
    # JSON receipts do not carry cryptographic ordinals. Only pinned driver
    # order maps these positions to the nine recursive phase summaries.
    phases = [dict((leaves if kind == 'leaf' else parents)[ordinal], kind=kind,
                   setup_ns=elapsed[10 + 2 * position], proving_ns=elapsed[11 + 2 * position])
              for position, (kind, ordinal) in enumerate(ORDER)]
    return dict(schema='ringct-root-opening-gpu-qualification-v1',
                scope='single-root-first-local-permutation-opening',
                native_proofs=10, recursive_proofs=9, recursive_leaf_proofs=5, recursive_parent_proofs=4,
                stage_receipts=28, cpu_heights=18, numerical_positive_checks=2,
                typed_opening_relation_rejections=1, actual_opening_probes=1,
                root_opening_claims=root, source_claims=source, native_receipt_elapsed_ns=elapsed[:10],
                recursive_phases=phases, acceptance=acceptance, root_opening=opening, terminal=terminal,
                root_opening_probe_complete=True, retained_output_restored=True, source_key_authenticated=True,
                original_quota_released=True, owner_quota_cleanup_complete=True, fresh_only=True, gpu_required=True,
                original_startup_pcs_reused=True, fresh_native_proof_receipts=10,
                fresh_outer_preprocessing_receipts=9, fresh_outer_proof_receipts=9,
                receipt_phase_identity='pinned-source-order-only',
                terminal_observer_scope='process-audit-only', terminal_observer_event_bytes=observer_bytes,
                released_claims_cover_terminal_observer=False, terminal_observer_census_is_physical_measurement=False,
                process_engine_device_audit_complete=False, transaction_context_authenticated=False,
                raw_proof_mutation_checks_complete=False, interior_mutation_checks_complete=False,
                mutation_checks_complete=False, disk_artifact_roundtrip_complete=False,
                artifact_roundtrip_complete=False, complete_ringct_workflow=False, performance_qualified=False)
