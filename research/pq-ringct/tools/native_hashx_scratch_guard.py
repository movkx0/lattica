"""Pure policy and evidence checks for the two original-scratch HashX tests.

No subprocess, device, environment mutation, project import or file read occurs
here. The coordinator supplies the existing audited build/source/executable
identities and owns exclusive launch, live resource checks and terminal reaping.
Neither a helper return value nor a log marker is an execution capability.
"""
from hashlib import sha256
import json
from pathlib import PurePosixPath
import re

GIB = 1 << 30
FLAG = 'LATTICA_OWNED_NATIVE_HASHX_SCRATCH_QUALIFICATION'
PREFIX = 'graph_crypto::retention::owned::preparation::production::workspace::tests::'
SELECTORS = {
    'sequence': PREFIX + 'genuine_hashx_sequence_reuses_original_scratch_for_distinct_inputs_and_retains_children',
    'reordered': PREFIX + 'genuine_retirement_reordered_successor_preserves_complete_owners_until_terminal_drop',
}
SWITCHES = (
    'HASH', 'RETAIN_TREES', 'QUERY_GATHER', 'RESIDENT_LDE', 'OPENINGS',
    'QUOTIENT_LDE', 'QUOTIENT_EVAL', 'QUOTIENT_RESIDENT', 'LOOKUP',
    'OPENING_EVAL', 'FRI_RESIDENT', 'PCS_DEVICE_ONLY', 'WITNESS',
    'RANDOMNESS', 'TRANSCRIPT', 'FRI_FOLD',
)
EXCLUSIVE_MODES = (
    'owned_hashx_interior_opening_test',
    'owned_hashx_root_opening_test',
    'owned_hashx_root_transport_test',
    'note_owned_proof', 'note_workflow_cpu', 'owned_runtime_test',
    'direct_ring_screen', 'direct_ring_identity_test', 'owned_source_shape_test',
    'active_hashx_preflight', 'owned_request_source_test', 'direct_ring_recursion_test',
)
REQUIRED_SOURCES = (
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake/retirement/hashx.rs',
    'lattica-prover-p3/src/block_v2/machine/gpu_backend/resources/admission/shake_pcs.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace/attachment.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace/tests.rs',
    'research/pq-ringct/src/opencl/session/retained_runtime/continuity/hashx.rs',
    'research/pq-ringct/src/component_tree/shake_verification_memory.rs',
    'research/pq-ringct/tools/native_hashx_scratch_guard.py',
    'research/pq-ringct/tools/test_native_hashx_scratch_guard.py',
    'research/pq-ringct/tools/note_startup_environment.py',
    'research/pq-ringct/tools/opencl_private_spend_validate.py',
)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def absolute(value):
    return (type(value) is str and '\0' not in value
            and PurePosixPath(value).is_absolute() and '..' not in PurePosixPath(value).parts)


def expected_base(root, device_uuid):
    """Match the existing fixed note/runtime environment before host selection."""
    require(absolute(root), 'HashX source root must be absolute')
    require(type(device_uuid) is str and re.fullmatch(
        r'GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', device_uuid),
        'HashX requires an explicit physical device UUID')
    root = str(PurePosixPath(root))
    result = {'LATTICA_V2_GPU_' + switch: '1' for switch in SWITCHES}
    result.update({
        'LATTICA_V2_QUOTIENT_FUSION': '1', 'LATTICA_PROVING_REPORT': '1',
        'LATTICA_PROVING_POLICY': 'gpu-required', 'LATTICA_V2_GPU_PUBLIC_HASH': 'baseline',
        'LATTICA_V2_GPU_RETAINED_TREE_STORAGE': 'device', 'LATTICA_V2_GPU_PIPELINE': '0',
        'LATTICA_V2_GPU_MANAGED_BYTES': str(8 * GIB),
        'LATTICA_V2_GPU_CONTEXT_BYTES': str(4 * GIB),
        'LATTICA_V2_HOST_OUTPUT_BYTES': str(24 * GIB), 'RAYON_NUM_THREADS': '8',
        'PATH': '/home/access/code/lattica/.tools/rust-1.96.0/bin:/usr/bin:/bin',
        'HOME': '/home/access', 'CARGO_HOME': root + '/.tools/cargo-opencl',
        'CARGO_TARGET_DIR': root + '/.tools/target-opencl', 'CARGO_BUILD_JOBS': '2',
        'LATTICA_V2_GPU_DEVICE': '0', 'LATTICA_GPU_DEVICE_UUID': device_uuid,
    })
    return result


def environment_receipt(environment, mode):
    require(mode in SELECTORS, 'unknown HashX scratch mode')
    require(type(environment) is dict and len(environment) <= 64, 'HashX environment count')
    for name, value in environment.items():
        require(type(name) is str and type(value) is str and name and '=' not in name
                and '\0' not in name + value and len(name.encode('utf-8')) <= 96
                and len(value.encode('utf-8')) <= 1024, 'HashX bounded environment entry')
    encoded = b''.join((key + '=' + environment[key] + '\0').encode('utf-8')
                       for key in sorted(environment))
    require(len(encoded) <= 8192, 'HashX environment bytes')
    return {
        'schema': 'ringct-native-hashx-scratch-environment-v1', 'mode': mode,
        'selector': SELECTORS[mode], 'entry_count': len(environment),
        'serialized_bytes': len(encoded),
        'sha256_sorted_name_equals_value_nul': sha256(encoded).hexdigest(),
        'requires_env_clear_before_exec': True,
        'requires_immutable_environment_after_exec': True,
        'physical_identity_verified': False, 'dispatch_authority': False,
        'proof_generation': 'fresh-only', 'prepared_artifact_reuse': False,
        'performance_qualified': False, 'complete_faithful_ringct_workflow': False,
    }


def exact_command(argv, mode):
    require(mode in SELECTORS, 'unknown HashX scratch mode')
    require(type(argv) is list and len(argv) == 6 and absolute(argv[0])
            and PurePosixPath(argv[0]).name.startswith('lattica_pq_ringct_research-')
            and argv[1:] == [SELECTORS[mode], '--exact', '--ignored', '--test-threads=1', '--nocapture'],
            'HashX scratch requires its exact isolated recorded test executable')


def build_environment(args, argv, tree_storage, public_hash_kernel, base, root):
    mode = getattr(args, 'owned_native_hashx_test', None)
    require(getattr(args, 'profile', None) == 'full' and getattr(args, 'expect_tests', False),
            'HashX scratch requires the unchanged full test profile')
    label = getattr(args, 'build_label', None)
    require(type(label) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,55}', label),
            'HashX scratch requires a recorded build label')
    require(not any(bool(getattr(args, key, False)) for key in EXCLUSIVE_MODES),
            'HashX scratch cannot mix qualification modes')
    require(not any(bool(getattr(args, key, False)) for key in (
        'expect_result', 'expect_direct_result', 'benchmark', 'correctness_label',
        'record_artifact', 'direct_ring_recursion_census_label')),
        'HashX scratch cannot qualify a workflow, benchmark or build')
    require(tree_storage == 'host' and public_hash_kernel == 'baseline',
            'HashX scratch requires baseline hash and retained host trees')
    exact_command(argv, mode)
    expected = expected_base(root, getattr(args, 'device_uuid', None))
    require(base == expected, 'HashX fixed runtime base differs')
    environment = dict(base)
    environment.update({FLAG: '1', 'LATTICA_V2_GPU_RETAINED_TREE_STORAGE': 'host',
                        'LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES': str(8 * GIB)})
    return environment, environment_receipt(environment, mode)


def bind_execution(plan, sources, executable, root):
    """Bind already audited identities; caller must first run executable_provenance."""
    require(plan.get('owned_hashx_interior_opening_environment') is None,
            'interior-opening qualification cannot mix with this mode')
    require(plan.get('owned_hashx_root_opening_environment') is None,
            'root-opening qualification cannot mix with this mode')
    require(plan.get('owned_hashx_root_transport_environment') is None,
            'root-transport qualification cannot mix with this mode')
    receipt = plan.get('owned_native_hashx_environment')
    require(type(receipt) is dict, 'missing HashX environment receipt')
    mode = receipt.get('mode')
    exact_command(plan.get('command'), mode)
    environment = plan.get('environment')
    require(type(environment) is dict, 'missing HashX environment')
    expected = expected_base(root, environment.get('LATTICA_GPU_DEVICE_UUID'))
    expected.update({FLAG: '1', 'LATTICA_V2_GPU_RETAINED_TREE_STORAGE': 'host',
                     'LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES': str(8 * GIB)})
    require(environment == expected and receipt == environment_receipt(environment, mode),
            'HashX launch environment or receipt changed')
    require(plan.get('profile') == 'full' and plan.get('expect_tests') is True
            and plan.get('memory_max_bytes') == 47 * GIB
            and plan.get('memory_high_bytes') == 45 * GIB
            and plan.get('fresh_memavailable_required_bytes') == 49 * GIB
            and plan.get('cpu_quota') == '800%' and plan.get('benchmark') is False
            and plan.get('public_hash_kernel') == 'baseline'
            and not plan.get('expect_result') and not plan.get('expect_direct_result'),
            'HashX launch profile or resource envelope changed')
    require(type(sources) is dict and all(path in sources for path in REQUIRED_SOURCES),
            'HashX build manifest omits required source')
    require(all(type(path) is str and path and not PurePosixPath(path).is_absolute()
                and '..' not in PurePosixPath(path).parts and '\0' not in path and digest(value)
                for path, value in sources.items()), 'HashX malformed source manifest')
    label = plan.get('build_label')
    require(type(label) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,55}', label),
            'HashX build identity missing')
    require(type(executable) is dict and executable.get('path') == plan['command'][0]
            and absolute(executable.get('resolved_path')) and digest(executable.get('sha256'))
            and executable.get('build_record') == str(PurePosixPath(root) / '.tools/pq-opencl-opt/runs' / (label + '.json'))
            and digest(executable.get('build_record_sha256')), 'HashX executable/build binding missing')
    return {
        'schema': 'ringct-native-hashx-scratch-binding-v1', 'mode': mode,
        'selector': SELECTORS[mode], 'source_count': len(sources),
        'source_manifest_sha256': sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest(),
        'executable_sha256': executable['sha256'],
        'resolved_executable': executable['resolved_path'],
        'build_record_sha256': executable['build_record_sha256'],
        'environment_sha256': receipt['sha256_sorted_name_equals_value_nul'],
        'selected_physical_device_uuid': environment['LATTICA_GPU_DEVICE_UUID'],
        'physical_identity_verified': False, 'dispatch_authority': False,
        'requires_existing_exclusive_launch_and_zero_swap': True,
        'requires_terminal_reaping_and_unchanged_sources': True,
        'performance_qualified': False, 'complete_faithful_ringct_workflow': False,
    }


def validate_log(content, plan):
    receipt = plan.get('owned_native_hashx_environment')
    require(type(receipt) is dict and receipt.get('mode') in SELECTORS, 'missing HashX mode')
    mode = receipt['mode']
    require(receipt.get('selector') == SELECTORS[mode], 'HashX selector receipt changed')
    binding = plan.get('owned_native_hashx_binding')
    require(type(binding) is dict and binding.get('mode') == mode
            and binding.get('selector') == SELECTORS[mode]
            and binding.get('environment_sha256') == receipt.get('sha256_sorted_name_equals_value_nul')
            and digest(binding.get('source_manifest_sha256')) and digest(binding.get('executable_sha256')),
            'HashX log lacks the source/executable launch binding')
    require(type(content) is str and not any(marker in content for marker in (
        'OPENCL_OPT_RESULT', 'DIRECT_SPEND_RESULT', 'DIRECT_RING_RESULT',
        'hashx_original_scratch_failure', 'test result: FAILED', 'panicked at')),
        'HashX emitted failure or unrelated workflow evidence')
    # libtest prints the exact name before the first nocapture diagnostic.
    prefix = 'test ' + SELECTORS[mode] + ' ... '
    require(content.count(prefix) == 1, 'HashX exact test invocation missing or duplicated')
    content = content.replace(prefix, '', 1)
    footers = list(re.finditer(
        r'^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in [0-9.]+s$',
        content, re.M))
    require(len(footers) == 1 and len(re.findall(r'^test result:', content, re.M)) == 1,
            'HashX must execute exactly one passing ignored test')
    records = [(match.start(), match.group()) for match in re.finditer(
        r'^hashx_original_scratch_[^\r\n]*$', content, re.M)]
    count = 2 if mode == 'sequence' else 1
    require(len(records) == 2 * count, 'HashX missing, duplicate or unknown component markers')
    capacities = []
    for case in range(count):
        _, component = records[2 * case]
        if mode == 'sequence':
            matched = re.fullmatch(
                r'hashx_original_scratch_component case=' + str(case)
                + r' native=10 cpu_verified=20 original_pcs_host=([1-9][0-9]*)'
                + r' peak_retained_children=10 retained_children=0 original_snapshots_equal=true whole_workflow=false',
                component)
            require(matched is not None, 'HashX complete distinct-witness component evidence differs')
            capacity = int(matched.group(1))
            require(capacity <= 24 * GIB, 'HashX original PCS capacity exceeds native allowance')
            capacities.append(capacity)
        else:
            require(component == 'hashx_original_scratch_rejection native=1 cpu_verified=1 rejected_next=2 '
                    'original_snapshots_equal=true whole_workflow=false', 'HashX reordered rejection evidence differs')
        require(records[2 * case + 1][1] == 'hashx_original_scratch_terminal case=' + str(case)
                + ' current_host=0 current_device=0 categories_zero=8', 'HashX terminal claims are not all zero')
    require(records[-1][0] < footers[0].start(), 'HashX terminal evidence follows test completion')
    require(len(set(capacities)) <= 1, 'HashX original capacities differ between witness fixtures')
    return {
        'schema': 'ringct-native-hashx-scratch-qualification-v1', 'mode': mode,
        'native_proofs': 20 if mode == 'sequence' else 1,
        'independent_cpu_verifications': 40 if mode == 'sequence' else 1,
        'distinct_witnesses': count, 'terminal_zero_claims': True,
        'original_pcs_host_bytes': capacities[0] if capacities else None,
        'fresh_only': True, 'gpu_required': True, 'prepared_artifact_reuse': False,
        'recursive_proofs': 0, 'complete_request_dispatch': False,
        'performance_qualified': False, 'complete_faithful_ringct_workflow': False,
    }
