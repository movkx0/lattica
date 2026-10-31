"""Exact physical source preissue only; no proof or workflow qualification."""
from hashlib import sha256
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re

GIB = 1 << 30
HOST = 32 * GIB
DEVICE = 8 * GIB
U128_MAX = (1 << 128) - 1
SELECTOR = ('component_tree::owned_shake::request_merge::source::capture::acceptance::'
            'parent::production::sequence::qualification::gpu_original_hashx_sequence_preissue')
FLAG = 'LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION'
PREFIX = 'ringct_hashx_sequence_'
EXCLUSIVE = ('owned_hashx_interior_opening_test', 'owned_hashx_root_opening_test', 'owned_hashx_root_transport_test', 'note_owned_proof', 'note_workflow_cpu', 'owned_runtime_test',
             'direct_ring_screen', 'direct_ring_identity_test', 'owned_source_shape_test',
             'active_hashx_preflight', 'owned_request_source_test', 'direct_ring_recursion_test',
             'owned_native_hashx_test', 'owned_hashx_leaf_test', 'expect_result',
             'expect_direct_result', 'benchmark', 'correctness_label', 'record_artifact',
             'direct_ring_recursion_census_label')
FOREIGN_RECEIPTS = ('owned_hashx_interior_opening_environment', 'owned_hashx_root_opening_environment', 'owned_hashx_root_transport_environment', 'note_startup_environment', 'note_cpu_environment',
                   'owned_runtime_environment', 'direct_ring_screen_environment',
                   'direct_ring_identity_environment', 'direct_ring_recursion_environment',
                   'owned_source_shape_environment', 'active_hashx_preflight_environment',
                   'owned_request_source_environment', 'owned_native_hashx_environment',
                   'owned_hashx_leaf_environment')
SEQUENCE = ('research/pq-ringct/src/component_tree/owned_shake/request_merge/source/'
            'capture/acceptance/parent/production/sequence')
REQUIRED_SOURCES = (
    SEQUENCE + '.rs', SEQUENCE + '/claims.rs', SEQUENCE + '/qualification.rs',
    SEQUENCE + '/qualification/claims.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/bank.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/bank/claims.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/children.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace/quota_projection.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace/outer/succession.rs',
    'research/pq-ringct/src/opencl/session/retained_runtime.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake/quota_projection.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake/retirement/hashx/outer.rs',
    'lattica-prover-p3/src/block_v2/gpu_hash/engine/device/ringct_runtime.rs',
    'lattica-prover-p3/src/block_v2/machine/program/proof_inputs.rs',
    'research/pq-ringct/tools/hashx_first_leaf_guard.py',
    'research/pq-ringct/tools/note_startup_environment.py',
    'research/pq-ringct/tools/opencl_private_spend_validate.py',
    'research/pq-ringct/tools/opencl_qualify.py',
    'research/pq-ringct/tools/native_sequence_source_pins.json',
    'research/pq-ringct/tools/hashx_sequence_preissue_guard.py',
    'research/pq-ringct/tools/test_hashx_sequence_preissue_guard.py',
)
SOURCE_FIXED = dict(native_outputs='10', native_attachments='10', retained_leaf_sources='5',
                    retained_parent_sources='4', original_compiler_bank='1', leaf_output_claims='5',
                    parent_output_claims='4', source_acceptance_claims='9', original_outer_sequence='true',
                    mode='preissue', native_dispatch_started='false', complete_ringct_workflow='false')
PREISSUE_FIXED = dict(native_proofs='0', recursive_proofs='0', outer_source_backends='9',
                      original_successor_backends='8', source_backend_preissue_complete='true',
                      actual_proving_fit='false', native_dispatch_started='false',
                      complete_ringct_workflow='false')
TERMINAL_FIXED = dict(original_quota_released='true', current_host_bytes='0', current_device_bytes='0',
                      component_success='true', mode='preissue', mutation_checks_complete='false',
                      artifact_roundtrip_complete='false', complete_ringct_workflow='false')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def absolute(value):
    return (type(value) is str and '\0' not in value and PurePosixPath(value).is_absolute()
            and '..' not in PurePosixPath(value).parts)


def expected_environment(root, uuid):
    # Load the maintained pure helper by location, including when this module is
    # itself loaded by the coordinator using importlib rather than sys.path.
    path = Path(__file__).with_name('hashx_first_leaf_guard.py')
    spec = importlib.util.spec_from_file_location('sequence_preissue_first_leaf_environment', path)
    require(spec is not None and spec.loader is not None, 'missing maintained environment helper')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    environment = helper.expected_environment('gpu', root, uuid)
    require(environment.pop(helper.FLAG, None) == '1', 'maintained first-leaf environment changed')
    environment[FLAG] = '1'
    return environment


def receipt(environment):
    require(type(environment) is dict and all(type(k) is str and type(v) is str
            and k and '=' not in k and '\0' not in k + v for k, v in environment.items()),
            'malformed sequence preissue environment')
    encoded = b''.join((key + '=' + environment[key] + '\0').encode()
                       for key in sorted(environment))
    require(len(environment) <= 64 and len(encoded) <= 8192, 'sequence preissue environment bound')
    return dict(schema='ringct-sequence-preissue-environment-v1', mode='preissue', selector=SELECTOR,
                entry_count=len(environment), serialized_bytes=len(encoded),
                sha256_sorted_name_equals_value_nul=sha256(encoded).hexdigest(),
                requires_env_clear_before_exec=True, requires_immutable_environment_after_exec=True,
                dispatch_authority=False, native_dispatch_started=False, actual_proving_fit=False,
                complete_ringct_workflow=False, performance_qualified=False)


def exact_command(command):
    require(type(command) is list and len(command) == 6 and absolute(command[0])
            and PurePosixPath(command[0]).name.startswith('lattica_pq_ringct_research-')
            and command[1:] == [SELECTOR, '--exact', '--ignored', '--test-threads=1', '--nocapture'],
            'sequence preissue requires its exact recorded isolated test')


def build_environment(args, base, root, kernel, tree_storage):
    require(getattr(args, 'owned_hashx_sequence_test', None) == 'preissue', 'unknown sequence mode')
    command = list(args.command)
    if command[:1] == ['--']:
        command.pop(0)
    exact_command(command)
    require(args.profile == 'full' and args.expect_tests is True and args.build_label,
            'sequence preissue requires its recorded full profile')
    require(not any(bool(getattr(args, key, False)) for key in EXCLUSIVE),
            'sequence preissue mode is exclusive')
    require(kernel == 'baseline' and tree_storage == 'host', 'sequence preissue hash/tree mode changed')
    environment = expected_environment(root, getattr(args, 'device_uuid', None))
    expected_base = dict(environment)
    expected_base.pop(FLAG)
    expected_base.pop('LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES')
    expected_base['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'device'
    require(base == expected_base, 'sequence preissue fixed base environment changed')
    return environment, receipt(environment)


def bind_execution(plan, sources, executable, root):
    require(absolute(root), 'sequence preissue source root is not absolute')
    exact_command(plan.get('command'))
    environment = plan.get('environment')
    require(type(environment) is dict, 'sequence preissue environment absent')
    expected = expected_environment(root, environment.get('LATTICA_GPU_DEVICE_UUID'))
    require(environment == expected and plan.get('owned_hashx_sequence_environment') == receipt(expected),
            'sequence preissue environment or receipt changed')
    require(all(plan.get(key) is None for key in FOREIGN_RECEIPTS), 'foreign qualification mode present')
    resources = dict(memory_max_bytes=47 * GIB, memory_high_bytes=45 * GIB,
                     fresh_memavailable_required_bytes=49 * GIB)
    require(all(type(plan.get(key)) is int and plan[key] == value for key, value in resources.items())
            and plan.get('profile') == 'full' and plan.get('expect_tests') is True
            and plan.get('cpu_quota') == '800%' and plan.get('benchmark') is False
            and plan.get('public_hash_kernel') == 'baseline' and plan.get('expect_result') is False
            and plan.get('expect_direct_result') is False and plan.get('correctness_label') is None
            and plan.get('record_artifacts') == [], 'sequence preissue resource/profile contract changed')
    require(type(plan.get('runtime_seconds')) is int and 1 <= plan['runtime_seconds'] <= 86400,
            'sequence preissue runtime bound changed')
    require(type(sources) is dict and all(path in sources for path in REQUIRED_SOURCES),
            'sequence preissue source manifest incomplete')
    require(all(type(path) is str and path and '\0' not in path
                and not PurePosixPath(path).is_absolute() and '..' not in PurePosixPath(path).parts
                and digest(value) for path, value in sources.items()), 'malformed sequence source manifest')
    label = plan.get('build_label')
    require(type(label) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,55}', label),
            'sequence preissue recorded build absent')
    require(type(executable) is dict and executable.get('path') == plan['command'][0]
            and absolute(executable.get('resolved_path')) and digest(executable.get('sha256'))
            and executable.get('build_record') == root + '/.tools/pq-opencl-opt/runs/' + label + '.json'
            and digest(executable.get('build_record_sha256')), 'sequence preissue executable binding differs')
    return dict(schema='ringct-sequence-preissue-binding-v1', mode='preissue', selector=SELECTOR,
                source_root=root, source_manifest_sha256=sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest(),
                executable_sha256=executable['sha256'], build_record_sha256=executable['build_record_sha256'],
                environment_sha256=plan['owned_hashx_sequence_environment']['sha256_sorted_name_equals_value_nul'],
                selected_physical_device_uuid=environment['LATTICA_GPU_DEVICE_UUID'],
                requires_terminal_reaping_and_unchanged_sources=True,
                requires_independent_physical_device_audit=True, dispatch_authority=False,
                native_dispatch_started=False, actual_proving_fit=False,
                complete_ringct_workflow=False, performance_qualified=False)


def marker(content, suffix, fixed, numbers):
    name = PREFIX + suffix
    header = r'(?:test ' + re.escape(SELECTOR) + r' \.\.\. )?' if suffix == 'source_claims' else ''
    matches = list(re.finditer(r'^' + header + r'(?P<marker>' + name + r') (?P<fields>[^\n]+)$', content, re.M))
    require(content.count(name) == 1 and len(matches) == 1, 'missing or malformed ' + name)
    found = matches[0]
    pairs = found.group('fields').split(' ')
    require(all(re.fullmatch(r'[a-z_]+=[a-z0-9]+', item) for item in pairs), 'invalid preissue marker fields')
    fields = dict(item.split('=') for item in pairs)
    require(len(fields) == len(pairs) and set(fields) == set(fixed) | set(numbers),
            'duplicate, missing or additional preissue marker fields')
    require(all(fields[key] == value for key, value in fixed.items()), 'contradictory preissue marker flags/counts')
    values = {}
    for key in numbers:
        require(re.fullmatch(r'0|[1-9][0-9]{0,38}', fields[key]), 'noncanonical preissue marker integer')
        value = int(fields[key])
        require(value <= (U128_MAX if key.endswith('_ns') else (1 << 64) - 1), 'preissue marker integer overflow')
        values[key] = value
    return found.start('marker'), values


def valid_header_payload(payload):
    if payload == '' or payload.startswith(PREFIX + 'source_claims '):
        return True
    # libtest leaves its prefix unterminated. The maintained source compiler
    # may print its first bounded input-growth diagnostic on that same line.
    # Accept only that diagnostic's exact grammar and allocation arithmetic.
    number = r'(0|[1-9][0-9]{0,19})'
    growth = re.fullmatch(r'bounded_proof_input_growth old_values=' + number
                         + r' new_values=' + number + r' live_bytes=' + number
                         + r' value_limit=' + number, payload)
    if growth is None:
        return False
    old, new, live, limit = map(int, growth.groups())
    return (0 < limit <= 1 << 20 and 0 <= old < new <= limit
            and new == min(max(old * 2, 4), limit) and live == (old + new) * 8)


def validate_log(content, plan):
    binding = plan.get('owned_hashx_sequence_binding')
    require(type(binding) is dict and absolute(binding.get('source_root')), 'sequence preissue binding absent')
    require(binding == bind_execution(plan, plan.get('input_sha256'), plan.get('executable_provenance'),
                                      binding['source_root']), 'sequence preissue original binding changed')
    observation = plan.get('observation_before_validation_ns')
    require(type(observation) is int and 0 < observation <= U128_MAX, 'runner-owned observation absent')
    require(type(content) is str and content.count(PREFIX) == 3, 'unexpected combined-sequence evidence')
    allowed_markers = {PREFIX + suffix for suffix in ('source_claims', 'preissue_complete', 'terminal')}
    require(all(name in allowed_markers for name in re.findall(r'\bringct_[A-Za-z0-9_]+', content)),
            'foreign RingCT diagnostic family in preissue evidence')
    require(not any(value in content for value in (
        'proving_stage_report', 'NATIVE_EXECUTION_RECEIPT', 'PUBLIC_HASH_EXECUTION',
        'OPENCL_OPT_RESULT', 'DIRECT_SPEND_RESULT', 'DIRECT_RING_RESULT', 'panicked at', 'FAILED')),
        'preissue emitted proving/workflow/failure evidence')
    headers = list(re.finditer(r'^test (\S+) \.\.\. ([^\n]*)$', content, re.M))
    completions = list(re.finditer(r'^ok$', content, re.M))
    footers = list(re.finditer(
        r'^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; '
        r'(?:0|[1-9][0-9]*) filtered out; finished in [0-9]+\.[0-9]+s$', content, re.M))
    require(len(headers) == len(footers) == len(completions) == 1 and headers[0].group(1) == SELECTOR
            and valid_header_payload(headers[0].group(2))
            and content.count('test result:') == 1, 'preissue requires the exact passing test and footer')
    source_pos, source = marker(content, 'source_claims', SOURCE_FIXED, ('host_bytes', 'device_bytes'))
    preissue_pos, preissue = marker(content, 'preissue_complete', PREISSUE_FIXED, ('host_bytes', 'device_bytes'))
    terminal_pos, terminal = marker(content, 'terminal', TERMINAL_FIXED,
                                    ('peak_host_bytes', 'peak_device_bytes', 'component_through_destruction_ns'))
    require(headers[0].start() < source_pos < preissue_pos < terminal_pos
            < completions[0].start() < footers[0].start(), 'preissue evidence out of order')
    require(0 < source['host_bytes'] <= HOST and source['device_bytes'] == 0,
            'preissue source claims exceed unchanged limits')
    # State::prepare retains the original source claims and PreparedNative's
    # original runtime with its additional 8GiB host-tree reservation. Neither
    # owner is dropped before the preissue marker. This is a lower bound, not
    # a substitute for the source-bound startup/PCS planner or physical audit.
    require(source['host_bytes'] + 8 * GIB <= preissue['host_bytes'] <= HOST
            and preissue['device_bytes'] == DEVICE,
            'preissue original quota or device allowance changed')
    require(preissue['host_bytes'] <= terminal['peak_host_bytes'] <= HOST
            and terminal['peak_device_bytes'] == DEVICE, 'preissue terminal peaks disagree with claims')
    elapsed = terminal['component_through_destruction_ns']
    require(0 < elapsed <= observation, 'preissue destruction timer exceeds runner observation')
    return dict(scope='physical-source-preissue-only', source_backend_preissue_complete=True,
                native_proofs=0, recursive_proofs=0, stage_receipts=0,
                source_claims=source, preissue=preissue, terminal=terminal,
                original_quota_released=True, owner_quota_cleanup_complete=True,
                process_engine_device_audit_complete=False, native_dispatch_started=False,
                actual_proving_fit=False, mutation_checks_complete=False, artifact_roundtrip_complete=False,
                complete_ringct_workflow=False, performance_qualified=False)
