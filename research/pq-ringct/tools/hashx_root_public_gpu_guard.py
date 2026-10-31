"""Exact B065 GPU component/root-public evidence, never full RingCT evidence."""
from hashlib import sha256
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re

GIB = 1 << 30
HOST, DEVICE = 32 * GIB, 8 * GIB
U64_MAX, U128_MAX = (1 << 64) - 1, (1 << 128) - 1
SELECTOR = ('component_tree::owned_shake::request_merge::source::capture::acceptance::'
            'parent::production::sequence::qualification::gpu_original_hashx_sequence_root_public_recheck')
FLAG = 'LATTICA_OWNED_HASHX_ROOT_PUBLIC_QUALIFICATION'
ENV_KEY = 'owned_hashx_root_public_environment'
BINDING_KEY = 'owned_hashx_root_public_binding'
EXCLUSIVE = ('owned_hashx_interior_opening_test', 'owned_hashx_root_opening_test', 'owned_hashx_root_transport_test', 'note_owned_proof', 'note_workflow_cpu', 'owned_runtime_test', 'direct_ring_screen',
             'direct_ring_identity_test', 'owned_source_shape_test', 'active_hashx_preflight',
             'owned_request_source_test', 'direct_ring_recursion_test', 'owned_native_hashx_test',
             'owned_hashx_leaf_test', 'owned_hashx_sequence_test', 'owned_hashx_sequence_refusal_test',
             'expect_result', 'expect_direct_result',
             'benchmark', 'correctness_label', 'record_artifact', 'direct_ring_recursion_census_label')
FOREIGN_RECEIPTS = ('owned_hashx_interior_opening_environment', 'owned_hashx_root_opening_environment', 'owned_hashx_root_transport_environment', 'note_startup_environment', 'note_cpu_environment', 'owned_runtime_environment',
                    'direct_ring_screen_environment', 'direct_ring_identity_environment',
                    'direct_ring_recursion_environment', 'owned_source_shape_environment',
                    'active_hashx_preflight_environment', 'owned_request_source_environment',
                    'owned_native_hashx_environment', 'owned_hashx_leaf_environment',
                    'owned_hashx_sequence_environment', 'owned_hashx_sequence_refusal_environment')
SEQUENCE = ('research/pq-ringct/src/component_tree/owned_shake/request_merge/source/'
            'capture/acceptance/parent/production/sequence')
REQUIRED_SOURCES = (
    SEQUENCE + '.rs', SEQUENCE + '/claims.rs', SEQUENCE + '/qualification.rs',
    SEQUENCE + '/qualification/claims.rs', SEQUENCE + '/root_recheck.rs',
    SEQUENCE + '/root_recheck/claims.rs', SEQUENCE + '/root_recheck/tests.rs',
    'research/pq-ringct/src/component_tree/owned_shake.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/children.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/bank.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production.rs',
    'research/pq-ringct/src/component_tree/owned_shake/output/authenticated/parent.rs',
    'research/pq-ringct/src/component_tree/owned_shake/outer_producer/production.rs',
    'research/pq-ringct/src/component_tree/owned_shake/outer_producer/production/preissued/hashx_leaf.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace/outer/succession.rs',
    'research/pq-ringct/src/opencl/session/retained_runtime.rs',
    'lattica-prover-p3/src/proving.rs',
    'lattica-prover-p3/src/block_v2/machine/backend/verification_outcome.rs',
    'lattica-prover-p3/src/block_v2/machine/program.rs',
    'lattica-prover-p3/src/block_v2/machine/program/proof_inputs.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake/retirement/hashx/outer.rs',
    'research/pq-ringct/tools/hashx_first_leaf_guard.py',
    'research/pq-ringct/tools/hashx_sequence_preissue_guard.py',
    'research/pq-ringct/tools/note_startup_environment.py',
    'research/pq-ringct/tools/native_sequence_report.py',
    'research/pq-ringct/tools/native_sequence_source_pins.json',
    'research/pq-ringct/tools/opencl_private_spend_validate.py',
    'research/pq-ringct/tools/opencl_qualify.py',
    'research/pq-ringct/tools/hashx_root_public_gpu_guard.py',
    'research/pq-ringct/tools/test_hashx_root_public_gpu_guard.py',
)
ROOT_CLAIMS = 'ringct_hashx_root_public_recheck_claims'
SOURCE_CLAIMS = 'ringct_hashx_sequence_source_claims'
LEAF = 'ringct_hashx_sequence_leaf'
PARENT = 'ringct_hashx_sequence_parent'
ACCEPTANCE = 'ringct_hashx_sequence_acceptance_scope'
ROOT_SCOPE = 'ringct_hashx_root_public_recheck_scope'
COMPLETE = 'ringct_hashx_root_public_recheck_complete'
TERMINAL = 'ringct_hashx_sequence_terminal'
MARKERS = (ROOT_CLAIMS, SOURCE_CLAIMS, LEAF, PARENT, ACCEPTANCE, ROOT_SCOPE, COMPLETE, TERMINAL)
LEAF_SPANS = ((0, 32), (32, 32), (64, 32), (96, 24), (120, 2))
PARENT_SPANS = ((0, 64, 1), (64, 56, 1), (0, 120, 2), (0, 122, 3))
ORDER = (('leaf', 0), ('leaf', 1), ('parent', 0), ('leaf', 2), ('leaf', 3),
         ('parent', 1), ('parent', 2), ('leaf', 4), ('parent', 3))
ENTRIES = ('ringct_owned_native_shake',) * 10 + ('block_v2_preprocessing', 'block_v2_registered_program') * 9
ROOT_FIXED = dict(cpu_heights='18', planned_public_probes='46', mode='root-public',
                  actual_root_public_probes='0', native_dispatch_started='false', complete_ringct_workflow='false')
SOURCE_FIXED = dict(native_outputs='10', native_attachments='10', retained_leaf_sources='5',
                    retained_parent_sources='4', original_compiler_bank='1', leaf_output_claims='5',
                    parent_output_claims='4', source_acceptance_claims='9', original_outer_sequence='true',
                    mode='root-public', native_dispatch_started='false', complete_ringct_workflow='false')
PROVISIONAL = dict(source_key_authenticated='true', transaction_context_authenticated='false',
                   provisional='true', terminal_cleanup_complete='false', complete_ringct_workflow='false')
NO_WIDER_CHECKS = dict(raw_proof_mutation_checks_complete='false', interior_mutation_checks_complete='false',
                       mutation_checks_complete='false', artifact_roundtrip_complete='false',
                       complete_ringct_workflow='false')
ROOT_SCOPE_FIXED = dict(NO_WIDER_CHECKS, cpu_heights='18', positive_checks='2', public_probes='46',
                        provisional='true', terminal_cleanup_complete='false', retained_output_immutable='true',
                        source_key_authenticated='true', transaction_context_authenticated='false')
COMPLETE_FIXED = dict(NO_WIDER_CHECKS, native_proofs='10', recursive_proofs='9', compiler_reclamations='9',
                      first_unit='0', units='122', level='3', cpu_heights='18', positive_checks='2', public_probes='46',
                      root_public_recheck_complete='true', retained_output_immutable='true',
                      source_key_authenticated='true', transaction_context_authenticated='false',
                      original_quota_released='true', owner_quota_cleanup_complete='true',
                      process_engine_device_audit_complete='false')
TERMINAL_FIXED = dict(original_quota_released='true', current_host_bytes='0', current_device_bytes='0',
                      component_success='true', mode='root-public', mutation_checks_complete='false',
                      artifact_roundtrip_complete='false', complete_ringct_workflow='false')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def helper(name):
    path = Path(__file__).with_name(name + '.py')
    spec = importlib.util.spec_from_file_location('root_public_gpu_' + name, path)
    require(spec is not None and spec.loader is not None, 'missing maintained root-public helper')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def absolute(value):
    return (type(value) is str and '\0' not in value and PurePosixPath(value).is_absolute()
            and '..' not in PurePosixPath(value).parts)


def expected_environment(root, uuid):
    environment = helper('hashx_sequence_preissue_guard').expected_environment(root, uuid)
    require(environment.get('LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION') == '1',
            'maintained full sequence environment changed')
    environment[FLAG] = '1'
    return environment


def receipt(environment):
    require(type(environment) is dict and all(type(k) is str and type(v) is str and k
            and '=' not in k and '\0' not in k + v for k, v in environment.items()),
            'malformed root-public GPU environment')
    encoded = b''.join((key + '=' + environment[key] + '\0').encode() for key in sorted(environment))
    require(len(environment) <= 64 and len(encoded) <= 8192, 'root-public GPU environment bound')
    return dict(schema='ringct-root-public-gpu-environment-v1', mode='root-public', selector=SELECTOR,
                entry_count=len(environment), serialized_bytes=len(encoded),
                sha256_sorted_name_equals_value_nul=sha256(encoded).hexdigest(),
                requires_env_clear_before_exec=True, requires_immutable_environment_after_exec=True,
                dispatch_authority=False, complete_ringct_workflow=False, performance_qualified=False)


def exact_command(command):
    require(type(command) is list and len(command) == 6 and absolute(command[0])
            and PurePosixPath(command[0]).name.startswith('lattica_pq_ringct_research-')
            and command[1:] == [SELECTOR, '--exact', '--ignored', '--test-threads=1', '--nocapture'],
            'root-public GPU requires its exact recorded isolated test')


def build_environment(args, base, root, kernel, tree_storage):
    require(getattr(args, 'owned_hashx_root_public_test', None) == 'gpu', 'unknown root-public GPU mode')
    command = list(args.command)
    if command[:1] == ['--']:
        command.pop(0)
    exact_command(command)
    require(args.profile == 'full' and args.expect_tests is True and args.build_label,
            'root-public GPU requires recorded full profile')
    require(not any(bool(getattr(args, key, False)) for key in EXCLUSIVE), 'root-public GPU mode is exclusive')
    require(kernel == 'baseline' and tree_storage == 'host', 'root-public GPU hash/tree mode changed')
    environment = expected_environment(root, getattr(args, 'device_uuid', None))
    expected_base = dict(environment)
    for flag in (FLAG, 'LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION', 'LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'):
        expected_base.pop(flag)
    expected_base['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'device'
    require(base == expected_base, 'root-public GPU fixed startup base changed')
    return environment, receipt(environment)


def bind_execution(plan, sources, executable, root):
    require(absolute(root), 'root-public GPU source root is not absolute')
    exact_command(plan.get('command'))
    environment = plan.get('environment')
    require(type(environment) is dict, 'root-public GPU environment absent')
    expected = expected_environment(root, environment.get('LATTICA_GPU_DEVICE_UUID'))
    require(environment == expected and plan.get(ENV_KEY) == receipt(expected),
            'root-public GPU environment or receipt changed')
    require(all(plan.get(key) is None for key in FOREIGN_RECEIPTS), 'foreign root-public qualification mode')
    resources = dict(memory_max_bytes=47 * GIB, memory_high_bytes=45 * GIB, fresh_memavailable_required_bytes=49 * GIB)
    require(all(type(plan.get(key)) is int and plan[key] == value for key, value in resources.items())
            and plan.get('profile') == 'full' and plan.get('expect_tests') is True
            and plan.get('cpu_quota') == '800%' and plan.get('benchmark') is False
            and plan.get('performance_qualified') is False and plan.get('comparison_baseline') is False
            and plan.get('public_hash_kernel') == 'baseline' and plan.get('expect_result') is False
            and plan.get('expect_direct_result') is False and plan.get('correctness_label') is None
            and plan.get('record_artifacts') == [], 'root-public GPU resource/profile contract changed')
    require(type(plan.get('runtime_seconds')) is int and 1 <= plan['runtime_seconds'] <= 86400,
            'root-public GPU runtime bound changed')
    require(type(sources) is dict and all(path in sources for path in REQUIRED_SOURCES),
            'root-public GPU source manifest incomplete')
    require(all(type(path) is str and path and '\0' not in path and not PurePosixPath(path).is_absolute()
                and '..' not in PurePosixPath(path).parts and digest(value) for path, value in sources.items()),
            'malformed root-public GPU source manifest')
    label = plan.get('build_label')
    require(type(label) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,55}', label),
            'root-public GPU recorded build absent')
    require(type(executable) is dict and executable.get('path') == plan['command'][0]
            and absolute(executable.get('resolved_path')) and digest(executable.get('sha256'))
            and executable.get('build_record') == root + '/.tools/pq-opencl-opt/runs/' + label + '.json'
            and digest(executable.get('build_record_sha256')), 'root-public GPU executable binding differs')
    return dict(schema='ringct-root-public-gpu-binding-v1', mode='root-public', selector=SELECTOR, source_root=root,
                source_manifest_sha256=sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest(),
                executable_sha256=executable['sha256'], build_record_sha256=executable['build_record_sha256'],
                environment_sha256=plan[ENV_KEY]['sha256_sorted_name_equals_value_nul'],
                selected_physical_device_uuid=environment['LATTICA_GPU_DEVICE_UUID'],
                requires_terminal_reaping_and_unchanged_sources=True, requires_independent_physical_device_audit=True,
                dispatch_authority=False, complete_ringct_workflow=False, performance_qualified=False)


def fields(body, fixed, numbers):
    pairs = body.split(' ')
    require(all(re.fullmatch(r'[a-z_]+=[a-z0-9-]+', item) for item in pairs), 'malformed root-public fields')
    found = dict(item.split('=') for item in pairs)
    require(len(found) == len(pairs) and set(found) == set(fixed) | set(numbers),
            'duplicate, missing or extra root-public fields')
    require(all(found[key] == value for key, value in fixed.items()), 'root-public fixed flags/counts differ')
    values = {}
    for key in numbers:
        require(re.fullmatch(r'0|[1-9][0-9]{0,38}', found[key]), 'noncanonical root-public number')
        value = int(found[key])
        require(value <= (U128_MAX if key.endswith('_ns') else U64_MAX), 'root-public integer overflow')
        values[key] = value
    return values


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


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate root-public receipt JSON key')
        result[key] = value
    return result


def reject_json_number(_):
    raise ValueError('root-public receipt requires finite integer numbers')


def decode_report(body):
    require(len(body) <= 65536, 'root-public receipt serialized bound')
    report = json.loads(body, object_pairs_hook=unique, parse_float=reject_json_number,
                        parse_constant=reject_json_number)
    require(type(report) is dict and set(report) == set('schema entry_point policy capabilities elapsed_ns '
            'succeeded stage_coverage_complete completion_rejected observation_errors observations components'.split()),
            'root-public receipt report schema differs')
    caps = report['capabilities']
    require(type(caps) is dict and set(caps) == {'scope', 'profile', 'max_log_fri_arity', 'stages'},
            'root-public receipt capability schema differs')
    require(type(caps['stages']) is list and all(type(item) is dict and set(item) == {'stage', 'backend'}
            and type(item['stage']) is str and type(item['backend']) is str
            for item in caps['stages']), 'root-public receipt stage schema differs')
    require(type(report['observations']) is list and all(type(item) is dict and set(item) == set(
            'stage backend calls completed_calls device_calls inclusive_ns device_ns'.split())
            and type(item['stage']) is str and type(item['backend']) is str
            for item in report['observations']), 'root-public receipt observation schema differs')
    for item in report['observations']:
        require(all(type(item[key]) is int and 0 <= item[key] <= U64_MAX
                    for key in ('calls', 'completed_calls', 'device_calls')), 'root-public receipt counter overflow')
    return report


def geometry(record):
    active, padded = record['active_rows'], record['padded_rows']
    require(0 < active <= padded <= 1 << 20 and padded >= 8 and padded & (padded - 1) == 0,
            'root-public compiler row geometry differs')
    require(0 < record['wires'] <= 1 << 26 and 0 < record['input_values'] <= 1 << 20,
            'root-public compiler wire/input bound differs')
    require(record['compiler_ns'] > 0 and record['source_cpu_verification_ns'] > 0,
            'root-public compiler/source-verifier timing absent')


def validate_log(content, plan):
    binding = plan.get(BINDING_KEY)
    require(type(binding) is dict and absolute(binding.get('source_root')), 'root-public GPU binding absent')
    require(binding == bind_execution(plan, plan.get('input_sha256'), plan.get('executable_provenance'),
                                      binding['source_root']), 'root-public GPU original binding changed')
    observation = plan.get('observation_before_validation_ns')
    require(type(observation) is int and 0 < observation <= U128_MAX, 'root-public runner observation absent')
    require(type(content) is str and len(content) <= 16 << 20, 'root-public log text/bound differs')
    require(not any(token in content for token in ('panicked at', 'FAILED', 'OPENCL_OPT_RESULT',
            'DIRECT_SPEND_RESULT', 'DIRECT_RING_RESULT', 'NATIVE_EXECUTION_RECEIPT', 'PUBLIC_HASH_EXECUTION',
            'fallback=true', 'retry=true')), 'root-public log contains foreign workflow/failure evidence')
    headers = list(re.finditer(r'^test (\S+) \.\.\. ([^\n]*)$', content, re.M))
    completions = list(re.finditer(r'^ok$', content, re.M))
    footers = list(re.finditer(r'^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; '
                             r'(?:0|[1-9][0-9]*) filtered out; finished in [0-9]+\.[0-9]+s$', content, re.M))
    require(len(headers) == len(completions) == len(footers) == 1 and headers[0].group(1) == SELECTOR
            and valid_header_payload(headers[0].group(2)) and content.count('test result:') == 1,
            'root-public requires its exact passing isolated test/footer')
    header_prefix = 'test ' + SELECTOR + ' ... '
    require(content.count(header_prefix) == 1, 'duplicate root-public invocation')
    events = []
    for line_number, line in enumerate(content.splitlines()):
        if line.startswith(header_prefix):
            line = line[len(header_prefix):]
        if line.startswith('proving_stage_report '):
            events.append(('receipt', decode_report(line.removeprefix('proving_stage_report ')), line_number))
            continue
        require('proving_stage_report' not in line, 'misplaced root-public receipt')
        names = re.findall(r'\bringct_[A-Za-z0-9_]+', line)
        if names:
            require(len(names) == 1 and names[0] in MARKERS and line.startswith(names[0] + ' '),
                    'foreign or malformed root-public marker')
            name, body = line.split(' ', 1)
            events.append((name, body, line_number))
    expected_order = [ROOT_CLAIMS, SOURCE_CLAIMS] + ['receipt'] * 28 + [LEAF] * 5 + [PARENT] * 4
    expected_order += [ACCEPTANCE, ROOT_SCOPE, COMPLETE, TERMINAL]
    require([name for name, _, _ in events] == expected_order, 'missing, duplicate or reordered root-public events')
    header_line = content[:headers[0].start()].count('\n')
    completion_line = content[:completions[0].start()].count('\n')
    require(header_line <= events[0][2] and events[-1][2] < completion_line
            and completions[0].start() < footers[0].start(), 'root-public events outside invocation/completion')
    root = fields(events[0][1], ROOT_FIXED, ('verifier_host_bytes', 'caller_host_bytes', 'total_host_bytes'))
    source = fields(events[1][1], SOURCE_FIXED, ('host_bytes', 'device_bytes'))
    require(0 < source['host_bytes'] <= HOST and source['device_bytes'] == 0,
            'root-public original source claims differ')
    require(root['verifier_host_bytes'] > 0 and root['caller_host_bytes'] > (64 << 10)
            and root['verifier_host_bytes'] + root['caller_host_bytes'] == root['total_host_bytes']
            and root['total_host_bytes'] <= source['host_bytes'], 'root-public preclaim is incomplete or not backed')
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
    recheck = fields(events[40][1], ROOT_SCOPE_FIXED,
                     ('positive_verification_ns', 'mutation_verification_ns', 'root_recheck_ns'))
    complete = fields(events[41][1], COMPLETE_FIXED, ('component_through_destruction_ns',))
    terminal = fields(events[42][1], TERMINAL_FIXED,
                      ('peak_host_bytes', 'peak_device_bytes', 'component_through_destruction_ns'))
    require(source['host_bytes'] + 8 * GIB <= terminal['peak_host_bytes'] <= HOST
            and terminal['peak_device_bytes'] == DEVICE, 'root-public terminal memory peaks disagree')
    require(recheck['positive_verification_ns'] > 0 and recheck['mutation_verification_ns'] > 0
            and recheck['root_recheck_ns'] >= recheck['positive_verification_ns'] + recheck['mutation_verification_ns'],
            'root-public numerical checks exceed their enclosing interval')
    preparation = acceptance['preparation_through_acceptance_ns']
    # Pinned producers finish native Runs before post-retirement CPU checks;
    # outer setup/proof Runs, compilers and source CPU checks are sequential.
    # These are disjoint lower bounds, not a full timing decomposition. Never
    # add nested observation intervals or the parent's aliased output CPU time.
    serialized = sum(elapsed) + sum(item['compiler_ns'] + item['source_cpu_verification_ns'] for item in leaves + parents)
    require(preparation >= serialized and complete['component_through_destruction_ns']
            == terminal['component_through_destruction_ns'] <= observation
            and terminal['component_through_destruction_ns'] >= preparation + recheck['root_recheck_ns'],
            'root-public timers do not enclose serialized work and destruction')
    # Report pair positions from pinned State::ORDER, not cryptographic ordinal
    # labels: stage JSON itself contains entry kind but no phase ordinal.
    phases = [dict((leaves if kind == 'leaf' else parents)[ordinal], kind=kind,
                   setup_ns=elapsed[10 + 2 * position], proving_ns=elapsed[11 + 2 * position])
              for position, (kind, ordinal) in enumerate(ORDER)]
    return dict(schema='ringct-root-public-gpu-qualification-v1', scope='final-root-public-binding-only',
                native_proofs=10, recursive_proofs=9, recursive_leaf_proofs=5, recursive_parent_proofs=4,
                stage_receipts=28, cpu_heights=18, positive_checks=2, public_probes=46,
                root_recheck_claims=root, source_claims=source, native_receipt_elapsed_ns=elapsed[:10],
                recursive_phases=phases, acceptance=acceptance, root_recheck=recheck, terminal=terminal,
                root_public_recheck_complete=True, retained_output_immutable=True, source_key_authenticated=True,
                original_quota_released=True, owner_quota_cleanup_complete=True, fresh_only=True, gpu_required=True,
                original_startup_pcs_reused=True, fresh_native_proof_receipts=10,
                fresh_outer_preprocessing_receipts=9, fresh_outer_proof_receipts=9,
                receipt_phase_identity='pinned-source-order-only',
                process_engine_device_audit_complete=False, transaction_context_authenticated=False,
                raw_proof_mutation_checks_complete=False, interior_mutation_checks_complete=False,
                mutation_checks_complete=False, artifact_roundtrip_complete=False,
                complete_ringct_workflow=False, performance_qualified=False)
