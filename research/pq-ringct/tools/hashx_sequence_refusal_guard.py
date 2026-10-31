"""Exact B064 ordinary returned refusals; never component/workflow success."""
from hashlib import sha256
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re

GIB = 1 << 30
HOST, DEVICE = 32 * GIB, 8 * GIB
U64_MAX, U128_MAX = (1 << 64) - 1, (1 << 128) - 1
SELECTOR_PREFIX = ('component_tree::owned_shake::request_merge::source::capture::acceptance::'
                   'parent::production::sequence::qualification::gpu_original_hashx_sequence_refusal_')
COUNTS = {'after-preissue': (0, 0, 0), 'before-first-start': (10, 0, 0),
          'after-first-producer': (10, 1, 0), 'after-first-acceptance': (10, 1, 1)}
FLAG = 'LATTICA_OWNED_HASHX_SEQUENCE_REFUSAL_QUALIFICATION'
ENV_KEY = 'owned_hashx_sequence_refusal_environment'
BINDING_KEY = 'owned_hashx_sequence_refusal_binding'
EXCLUSIVE = ('owned_hashx_interior_opening_test', 'owned_hashx_root_opening_test', 'owned_hashx_root_transport_test', 'note_owned_proof', 'note_workflow_cpu', 'owned_runtime_test', 'direct_ring_screen',
             'direct_ring_identity_test', 'owned_source_shape_test', 'active_hashx_preflight',
             'owned_request_source_test', 'direct_ring_recursion_test', 'owned_native_hashx_test',
             'owned_hashx_leaf_test', 'owned_hashx_sequence_test', 'owned_hashx_root_public_test',
             'expect_result', 'expect_direct_result', 'benchmark', 'correctness_label',
             'record_artifact', 'direct_ring_recursion_census_label')
FOREIGN_RECEIPTS = ('owned_hashx_interior_opening_environment', 'owned_hashx_root_opening_environment', 'owned_hashx_root_transport_environment', 'note_startup_environment', 'note_cpu_environment', 'owned_runtime_environment',
                    'direct_ring_screen_environment', 'direct_ring_identity_environment',
                    'direct_ring_recursion_environment', 'owned_source_shape_environment',
                    'active_hashx_preflight_environment', 'owned_request_source_environment',
                    'owned_native_hashx_environment', 'owned_hashx_leaf_environment',
                    'owned_hashx_sequence_environment', 'owned_hashx_root_public_environment')
SEQUENCE = ('research/pq-ringct/src/component_tree/owned_shake/request_merge/source/'
            'capture/acceptance/parent/production/sequence')
REQUIRED_SOURCES = (
    SEQUENCE + '.rs', SEQUENCE + '/claims.rs', SEQUENCE + '/refusal.rs',
    SEQUENCE + '/qualification.rs', SEQUENCE + '/qualification/claims.rs',
    'research/pq-ringct/src/component_tree/owned_shake.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/children.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/bank.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/bank/claims.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production.rs',
    'research/pq-ringct/src/component_tree/owned_shake/outer_producer/production.rs',
    'research/pq-ringct/src/component_tree/owned_shake/outer_producer/production/preissued/hashx_leaf.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace/quota_projection.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace/outer/succession.rs',
    'research/pq-ringct/src/opencl/session/retained_runtime.rs',
    'lattica-prover-p3/src/proving.rs',
    'lattica-prover-p3/src/block_v2/gpu_hash/engine/device/ringct_runtime.rs',
    'lattica-prover-p3/src/block_v2/machine/program/proof_inputs.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake/retirement/hashx/outer.rs',
    'research/pq-ringct/tools/hashx_first_leaf_guard.py',
    'research/pq-ringct/tools/hashx_sequence_preissue_guard.py',
    'research/pq-ringct/tools/note_startup_environment.py',
    'research/pq-ringct/tools/native_sequence_report.py',
    'research/pq-ringct/tools/native_sequence_source_pins.json',
    'research/pq-ringct/tools/opencl_private_spend_validate.py',
    'research/pq-ringct/tools/opencl_qualify.py',
    'research/pq-ringct/tools/hashx_sequence_refusal_guard.py',
    'research/pq-ringct/tools/test_hashx_sequence_refusal_guard.py',
)
SOURCE = 'ringct_hashx_sequence_source_claims'
REACHED = 'ringct_hashx_sequence_returned_refusal_reached'
COMPLETE = 'ringct_hashx_sequence_returned_refusal_complete'
TERMINAL = 'ringct_hashx_sequence_terminal'
MARKERS = (SOURCE, REACHED, COMPLETE, TERMINAL)
SOURCE_FIXED = dict(native_outputs='10', native_attachments='10', retained_leaf_sources='5',
                    retained_parent_sources='4', original_compiler_bank='1', leaf_output_claims='5',
                    parent_output_claims='4', source_acceptance_claims='9', original_outer_sequence='true',
                    native_dispatch_started='false', complete_ringct_workflow='false')
NARROW = dict(ordinary_returned_refusal_only='true', asynchronous_failure_checked='false',
              unwind_checked='false', mutation_checks_complete='false', artifact_roundtrip_complete='false',
              complete_ringct_workflow='false')
REACHED_FIXED = dict(NARROW, expected_returned_refusal='true', provisional='true',
                     terminal_cleanup_complete='false', compiler_reclamation_complete='false')
COMPLETE_FIXED = dict(NARROW, expected_returned_refusal='true', compiler_reclamations='0',
                      original_quota_released='true', owner_quota_cleanup_complete='true',
                      process_engine_device_audit_complete='false', component_success='false')
TERMINAL_FIXED = dict(original_quota_released='true', current_host_bytes='0', current_device_bytes='0',
                      component_success='false', mutation_checks_complete='false',
                      artifact_roundtrip_complete='false', complete_ringct_workflow='false')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def helper(name):
    path = Path(__file__).with_name(name + '.py')
    spec = importlib.util.spec_from_file_location('sequence_refusal_' + name, path)
    require(spec is not None and spec.loader is not None, 'missing maintained returned-refusal helper')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def absolute(value):
    return (type(value) is str and '\0' not in value and PurePosixPath(value).is_absolute()
            and '..' not in PurePosixPath(value).parts)


def selector(mode):
    require(type(mode) is str and mode in COUNTS, 'unknown returned-refusal mode')
    return SELECTOR_PREFIX + mode.replace('-', '_')


def probe(mode):
    selector(mode)
    return 'returned-refusal-' + mode


def expected_environment(root, uuid):
    environment = helper('hashx_sequence_preissue_guard').expected_environment(root, uuid)
    require(environment.get('LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION') == '1',
            'maintained full sequence environment changed')
    environment[FLAG] = '1'
    return environment


def receipt(mode, environment):
    selected = selector(mode)
    require(type(environment) is dict and all(type(k) is str and type(v) is str and k
            and '=' not in k and '\0' not in k + v for k, v in environment.items()),
            'malformed returned-refusal environment')
    encoded = b''.join((key + '=' + environment[key] + '\0').encode() for key in sorted(environment))
    require(len(environment) <= 64 and len(encoded) <= 8192, 'returned-refusal environment bound')
    return dict(schema='ringct-sequence-refusal-environment-v1', mode=mode, probe=probe(mode), selector=selected,
                entry_count=len(environment), serialized_bytes=len(encoded),
                sha256_sorted_name_equals_value_nul=sha256(encoded).hexdigest(),
                requires_env_clear_before_exec=True, requires_immutable_environment_after_exec=True,
                dispatch_authority=False, component_success=False, complete_ringct_workflow=False,
                performance_qualified=False)


def exact_command(command):
    require(type(command) is list and len(command) == 6 and absolute(command[0])
            and PurePosixPath(command[0]).name.startswith('lattica_pq_ringct_research-')
            and command[2:] == ['--exact', '--ignored', '--test-threads=1', '--nocapture'],
            'returned-refusal requires an exact recorded isolated test')
    modes = [mode for mode in COUNTS if command[1] == selector(mode)]
    require(len(modes) == 1, 'unknown returned-refusal selector')
    return modes[0]


def build_environment(args, base, root, kernel, tree_storage):
    mode = getattr(args, 'owned_hashx_sequence_refusal_test', None)
    selector(mode)
    command = list(args.command)
    if command[:1] == ['--']:
        command.pop(0)
    require(exact_command(command) == mode, 'returned-refusal option and selector differ')
    require(args.profile == 'full' and args.expect_tests is True and args.build_label,
            'returned-refusal requires a recorded full profile')
    require(not any(bool(getattr(args, key, False)) for key in EXCLUSIVE), 'returned-refusal mode is exclusive')
    require(kernel == 'baseline' and tree_storage == 'host', 'returned-refusal hash/tree mode changed')
    environment = expected_environment(root, getattr(args, 'device_uuid', None))
    expected_base = dict(environment)
    for flag in (FLAG, 'LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION', 'LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'):
        expected_base.pop(flag)
    expected_base['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'device'
    require(base == expected_base, 'returned-refusal fixed startup base changed')
    return environment, receipt(mode, environment)


def bind_execution(plan, sources, executable, root):
    require(absolute(root), 'returned-refusal source root is not absolute')
    mode = exact_command(plan.get('command'))
    environment = plan.get('environment')
    require(type(environment) is dict, 'returned-refusal environment absent')
    expected = expected_environment(root, environment.get('LATTICA_GPU_DEVICE_UUID'))
    require(environment == expected and plan.get(ENV_KEY) == receipt(mode, expected),
            'returned-refusal environment or receipt changed')
    require(all(plan.get(key) is None for key in FOREIGN_RECEIPTS), 'foreign returned-refusal qualification mode')
    resources = dict(memory_max_bytes=47 * GIB, memory_high_bytes=45 * GIB, fresh_memavailable_required_bytes=49 * GIB)
    require(all(type(plan.get(key)) is int and plan[key] == value for key, value in resources.items())
            and plan.get('profile') == 'full' and plan.get('expect_tests') is True
            and plan.get('cpu_quota') == '800%' and plan.get('benchmark') is False
            and plan.get('performance_qualified') is False and plan.get('comparison_baseline') is False
            and plan.get('public_hash_kernel') == 'baseline' and plan.get('expect_result') is False
            and plan.get('expect_direct_result') is False and plan.get('correctness_label') is None
            and plan.get('record_artifacts') == [], 'returned-refusal resource/profile contract changed')
    require(type(plan.get('runtime_seconds')) is int and 1 <= plan['runtime_seconds'] <= 86400,
            'returned-refusal runtime bound changed')
    require(type(sources) is dict and all(path in sources for path in REQUIRED_SOURCES),
            'returned-refusal source manifest incomplete')
    require(all(type(path) is str and path and '\0' not in path and not PurePosixPath(path).is_absolute()
                and '..' not in PurePosixPath(path).parts and digest(value) for path, value in sources.items()),
            'malformed returned-refusal source manifest')
    label = plan.get('build_label')
    require(type(label) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,55}', label),
            'returned-refusal recorded build absent')
    require(type(executable) is dict and executable.get('path') == plan['command'][0]
            and absolute(executable.get('resolved_path')) and digest(executable.get('sha256'))
            and executable.get('build_record') == root + '/.tools/pq-opencl-opt/runs/' + label + '.json'
            and digest(executable.get('build_record_sha256')), 'returned-refusal executable binding differs')
    return dict(schema='ringct-sequence-refusal-binding-v1', mode=mode, probe=probe(mode), selector=selector(mode),
                source_root=root, source_manifest_sha256=sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest(),
                executable_sha256=executable['sha256'], build_record_sha256=executable['build_record_sha256'],
                environment_sha256=plan[ENV_KEY]['sha256_sorted_name_equals_value_nul'],
                selected_physical_device_uuid=environment['LATTICA_GPU_DEVICE_UUID'],
                requires_terminal_reaping_and_unchanged_sources=True, requires_independent_physical_device_audit=True,
                dispatch_authority=False, component_success=False, complete_ringct_workflow=False,
                performance_qualified=False)


def fields(body, fixed, numbers):
    pairs = body.split(' ')
    require(all(re.fullmatch(r'[a-z_]+=[a-z0-9-]+', item) for item in pairs), 'malformed returned-refusal fields')
    found = dict(item.split('=') for item in pairs)
    require(len(found) == len(pairs) and set(found) == set(fixed) | set(numbers),
            'duplicate, missing or extra returned-refusal fields')
    require(all(found[key] == value for key, value in fixed.items()), 'returned-refusal fixed flags/counts differ')
    values = {}
    for key in numbers:
        require(re.fullmatch(r'0|[1-9][0-9]{0,38}', found[key]), 'noncanonical returned-refusal number')
        value = int(found[key])
        require(value <= (U128_MAX if key.endswith('_ns') else U64_MAX), 'returned-refusal integer overflow')
        values[key] = value
    return values


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate returned-refusal receipt JSON key')
        result[key] = value
    return result


def reject_json_number(_):
    raise ValueError('returned-refusal receipt requires finite integer numbers')


def decode_report(body):
    require(len(body) <= 65536, 'returned-refusal receipt serialized bound')
    report = json.loads(body, object_pairs_hook=unique, parse_float=reject_json_number,
                        parse_constant=reject_json_number)
    require(type(report) is dict and set(report) == set('schema entry_point policy capabilities elapsed_ns '
            'succeeded stage_coverage_complete completion_rejected observation_errors observations components'.split()),
            'returned-refusal receipt report schema differs')
    caps = report['capabilities']
    require(type(caps) is dict and set(caps) == {'scope', 'profile', 'max_log_fri_arity', 'stages'},
            'returned-refusal receipt capability schema differs')
    require(type(caps['stages']) is list and all(type(item) is dict and set(item) == {'stage', 'backend'}
            and type(item['stage']) is str and type(item['backend']) is str
            for item in caps['stages']), 'returned-refusal receipt stage schema differs')
    require(type(report['observations']) is list and all(type(item) is dict and set(item) == set(
            'stage backend calls completed_calls device_calls inclusive_ns device_ns'.split())
            and type(item['stage']) is str and type(item['backend']) is str
            for item in report['observations']), 'returned-refusal receipt observation schema differs')
    for item in report['observations']:
        require(all(type(item[key]) is int and 0 <= item[key] <= U64_MAX
                    for key in ('calls', 'completed_calls', 'device_calls')), 'returned-refusal receipt counter overflow')
    return report


def valid_header_payload(payload):
    if payload == '' or payload.startswith(SOURCE + ' '):
        return True
    number = r'(0|[1-9][0-9]{0,19})'
    growth = re.fullmatch(r'bounded_proof_input_growth old_values=' + number + r' new_values=' + number
                         + r' live_bytes=' + number + r' value_limit=' + number, payload)
    if growth is None:
        return False
    old, new, live, limit = map(int, growth.groups())
    return (0 < limit <= 1 << 20 and 0 <= old < new <= limit
            and new == min(max(old * 2, 4), limit) and live == (old + new) * 8)


def validate_log(content, plan):
    binding = plan.get(BINDING_KEY)
    require(type(binding) is dict and absolute(binding.get('source_root')), 'returned-refusal binding absent')
    require(binding == bind_execution(plan, plan.get('input_sha256'), plan.get('executable_provenance'),
                                      binding['source_root']), 'returned-refusal original binding changed')
    mode = binding['mode']
    selected, requested = selector(mode), probe(mode)
    native, recursive, installed = COUNTS[mode]
    entries = ('ringct_owned_native_shake',) * native
    entries += ('block_v2_preprocessing', 'block_v2_registered_program') * recursive
    observation = plan.get('observation_before_validation_ns')
    require(type(observation) is int and 0 < observation <= U128_MAX, 'returned-refusal runner observation absent')
    require(type(content) is str and len(content) <= 16 << 20, 'returned-refusal log text/bound differs')
    require(not any(token in content for token in ('panicked at', 'FAILED', 'OPENCL_OPT_RESULT',
            'DIRECT_SPEND_RESULT', 'DIRECT_RING_RESULT', 'NATIVE_EXECUTION_RECEIPT', 'PUBLIC_HASH_EXECUTION',
            'fallback=true', 'retry=true')), 'returned-refusal log contains foreign workflow/failure evidence')
    headers = list(re.finditer(r'^test (\S+) \.\.\. ([^\n]*)$', content, re.M))
    completions = list(re.finditer(r'^ok$', content, re.M))
    footers = list(re.finditer(r'^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; '
                             r'(?:0|[1-9][0-9]*) filtered out; finished in [0-9]+\.[0-9]+s$', content, re.M))
    require(len(headers) == len(completions) == len(footers) == 1 and headers[0].group(1) == selected
            and valid_header_payload(headers[0].group(2)) and content.count('test result:') == 1,
            'returned-refusal requires its exact passing isolated test/footer')
    header_prefix = 'test ' + selected + ' ... '
    require(content.count(header_prefix) == 1, 'duplicate returned-refusal invocation')
    events = []
    for line_number, line in enumerate(content.splitlines()):
        if line.startswith(header_prefix):
            line = line[len(header_prefix):]
        if line.startswith('proving_stage_report '):
            events.append(('receipt', decode_report(line.removeprefix('proving_stage_report ')), line_number))
            continue
        require('proving_stage_report' not in line, 'misplaced returned-refusal receipt')
        names = re.findall(r'\bringct_[A-Za-z0-9_]+', line)
        if names:
            require(len(names) == 1 and names[0] in MARKERS and line.startswith(names[0] + ' '),
                    'foreign or malformed returned-refusal marker')
            name, body = line.split(' ', 1)
            events.append((name, body, line_number))
    require([name for name, _, _ in events] == [SOURCE] + ['receipt'] * len(entries) + [REACHED, COMPLETE, TERMINAL],
            'missing, duplicate or reordered returned-refusal events')
    header_line = content[:headers[0].start()].count('\n')
    completion_line = content[:completions[0].start()].count('\n')
    require(header_line <= events[0][2] and events[-1][2] < completion_line
            and completions[0].start() < footers[0].start(), 'returned-refusal events outside invocation/completion')
    source = fields(events[0][1], dict(SOURCE_FIXED, mode=requested), ('host_bytes', 'device_bytes'))
    require(0 < source['host_bytes'] <= HOST and source['device_bytes'] == 0,
            'returned-refusal original source claims differ')
    receipt_check = helper('native_sequence_report').receipt
    elapsed = [receipt_check(event[1], entry) for event, entry in zip(events[1:1 + len(entries)], entries)]
    fields(events[-3][1], dict(REACHED_FIXED, probe=requested), ())
    complete = fields(events[-2][1], dict(COMPLETE_FIXED, probe=requested,
        native_proofs_before_refusal=str(native), recursive_proofs_before_refusal=str(recursive),
        installed_leaf_outputs_before_refusal=str(installed)), ('component_through_destruction_ns',))
    terminal = fields(events[-1][1], dict(TERMINAL_FIXED, mode=requested),
                      ('peak_host_bytes', 'peak_device_bytes', 'component_through_destruction_ns'))
    require(source['host_bytes'] + 8 * GIB <= terminal['peak_host_bytes'] <= HOST
            and terminal['peak_device_bytes'] == DEVICE, 'returned-refusal terminal memory peaks disagree')
    total = complete['component_through_destruction_ns']
    # Receipt Runs are sequential; nested inclusive/device stage timers are not
    # added. These refusal paths publish no compiler/source-CPU summaries.
    require(0 < total == terminal['component_through_destruction_ns'] <= observation
            and sum(elapsed) <= total, 'returned-refusal timers do not enclose serialized work and destruction')
    return dict(schema='ringct-sequence-refusal-qualification-v1', scope='ordinary-returned-refusal-only',
                mode=mode, probe=requested, selector=selected, stage_receipts=len(entries),
                native_proofs_before_refusal=native, recursive_proofs_before_refusal=recursive,
                installed_leaf_outputs_before_refusal=installed, compiler_reclamations=0,
                fresh_native_proof_receipts=native, fresh_outer_preprocessing_receipts=recursive,
                fresh_outer_proof_receipts=recursive, fresh_only_requested=True, gpu_required=True,
                source_preissue_complete=True, physical_runtime_preissued=True,
                native_proof_dispatch_started=bool(native),
                recursive_proof_dispatch_started=bool(recursive),
                native_receipt_elapsed_ns=elapsed[:native],
                outer_preprocessing_receipt_elapsed_ns=elapsed[native:native + recursive],
                outer_proof_receipt_elapsed_ns=elapsed[native + recursive:], receipt_phase_identity='pinned-source-order-only',
                source_claims=source, terminal=terminal, expected_returned_refusal=True,
                ordinary_returned_refusal_only=True, original_quota_released=True, owner_quota_cleanup_complete=True,
                component_success=False, process_engine_device_audit_complete=False,
                asynchronous_failure_checked=False, unwind_checked=False, complete_component_fit_qualified=False,
                original_startup_pcs_reused_for_outer_proof=bool(recursive),
                transaction_context_authenticated=False, mutation_checks_complete=False,
                artifact_roundtrip_complete=False, complete_ringct_workflow=False, performance_qualified=False)
