#!/usr/bin/env python3
"""Bounded v2 GPU private-spend and STARK correctness jobs. Historical v1 audits use opencl_opt_validate.py. Never runs comparison baselines.

Planning is the default. Execution requires a coordinator-owned exclusive
window; all subprocesses run in a transient, swap-free systemd user service.
"""
import argparse
import csv
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
from host_memory_profiles import HOST_PROFILES, selected_host_profile

GIB = 1 << 30
PROFILES = {
    'build': (8, 6, 10, 2, 7200),
    # Exact source planner only: no context, queue, runtime, or proof creation.
    # Modeled native/worker/device allowances stay unchanged. This lower real
    # process envelope cannot admit a proving or benchmarking command.
    'source-preflight': (8, 6, 10, 8, 7200),
    # Explicit CPU research envelope for the opt-in larger ring compiler.
    # This changes neither faithful GPU worker limits nor benchmark admission.
    'research-compile': (16, 14, 20, 2, 7200),
    'research-compile-large': (32, 30, 36, 2, 7200),
    'smoke': (16, 14, 20, 4, 7200),
    'full': (47, 45, 49, 8, 86400),
    # Separate direct-relation research profile: a lower process ceiling keeps
    # the same 2 GiB fresh admission margin on this machine. Worker/native/GPU
    # allowances are unchanged, and this cannot qualify faithful RingCT results.
    'direct-full': (45, 43, 47, 8, 86400),
}
RESEARCH_CPU_PROFILES = frozenset(('research-compile', 'research-compile-large'))
CPU_PROFILES = RESEARCH_CPU_PROFILES | frozenset(('build',))
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


def full_workflow_device_identity(environment):
    """Bind owned-case timing evidence to the physical GPU and driver."""
    uuid = environment.get('LATTICA_GPU_DEVICE_UUID')
    require(type(uuid) is str and re.fullmatch(
        r'GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', uuid),
        'owned workflow device UUID is missing or malformed')
    result = command(['nvidia-smi', '--id=' + uuid,
                      '--query-gpu=uuid,name,driver_version,memory.total',
                      '--format=csv,noheader,nounits'])
    require(result.returncode == 0, 'cannot identify owned workflow GPU: ' + result.stderr)
    rows = list(csv.reader(result.stdout.splitlines(), skipinitialspace=True))
    require(len(rows) == 1 and len(rows[0]) == 4, 'ambiguous owned workflow GPU inventory')
    actual, name, driver, memory = (value.strip() for value in rows[0])
    require(actual.lower() == uuid.lower() and name and driver and memory.isdecimal()
            and int(memory) > 0, 'owned workflow GPU inventory differs from requested UUID')
    return dict(uuid=uuid, name=name, driver_version=driver, memory_total_mib=int(memory))


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
    for name in ['Cargo.toml', 'Cargo.lock', 'build.rs', 'metadata_sources.rs']:
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


NOTE_OWNED_TEST = ('block_v2::legacy_wallet::note_admission::runtime::tests::'
                   'gpu_fixed_note_original_owners_prove_fresh_and_retire_exact_runtime')
NOTE_HANDOFF_TEST = ('note_gpu::proving::qualification::tests::'
                     'gpu_owned_note_handoff_verifies_fresh_proofs_and_rejects_mutations')
NOTE_WORKFLOW_TEST = ('note_gpu::workflow::tests::'
                      'gpu_seven_distinct_note_workflow_verifies_roundtrips_and_cleans_up')
NOTE_CPU_WORKFLOW_TEST = ('note_gpu::workflow::tests::'
                          'cpu_seven_distinct_note_workflow_verifies_roundtrips_and_cleans_up')
DIRECT_RING_SCREEN_TEST = ('ring_screen::tests::'
                           'gpu_seven_distinct_ring_workflows_verify_roundtrips_and_retire')
OWNED_RUNTIME_TESTS = {
    'runtime': 'opencl::session::retained_runtime::tests::gpu_reserved_runtime_rechecks_original_ledger_and_retires_startup',
    'raw-error': 'execution::preparation::owned::gpu_tests::gpu_reserved_session_raw_negation_and_overflow_cleanup',
    'raw-graph': 'execution::preparation::owned::gpu_tests::gpu_reserved_session_genuine_source_graph_original_owners',
    'raw-differential': 'rust_verify::committed_backend::source_graph::owned::differential::qualification::gpu_reserved_source_graph_matches_independent_cpu_and_rejects_mutations',
    'outer': 'component_tree::owned_shake::outer_producer::production::tests::qualification::actual_owned_gpu_singleton_pair_and_odd_tail_verify_and_release',
    'native-shake': 'graph_crypto::retention::owned::preparation::production::tests::gpu_owned_singletons_prove_fresh_verify_mutation_and_retire_original_owners',
    'native-shake-rejection': 'block_v2::native_gpu::research::owned_shake::tests::runtime::gpu_fixed_native_rejection_retires_exact_runtime',
    'native-shake-host': 'graph_crypto::retention::owned::preparation::production::host::tests::gpu_owned_host_singletons_prove_fresh_verify_mutation_and_retire_original_owners',
    'native-shake-continuation': 'graph_crypto::retention::owned::preparation::production::continuity::tests::gpu_owned_host_continuations_preserve_originals_verify_mutations_and_retire',
    'native-shake-continuation-rejection': 'graph_crypto::retention::owned::preparation::production::continuity::rejection::gpu_owned_host_continuation_normalization_rejection_retires_originals',
    'native-to-outer': 'component_tree::owned_shake::outer_producer::production::preissued::tests::gpu_native_to_outer_singleton_uses_original_preclaims',
    'outer-continuation': 'component_tree::owned_shake::outer_producer::production::preissued::outer_continuation::tests::gpu_outer_retirement_restores_original_startup_without_dispatch',
    'native-pair-sequence': 'component_tree::owned_shake::outer_producer::production::preissued::sequence::gpu_two_native_segments_pair_original_successors',
    'native-odd-tail-sequence': 'component_tree::owned_shake::outer_producer::production::preissued::sequence::gpu_three_native_segments_pair_and_tail_original_successors',
}


def exact_owned_test(argv, prefix, selector):
    return Path(argv[0]).name.startswith(prefix) and argv[1:] == [
        selector, '--exact', '--ignored', '--test-threads=1', '--nocapture']


def note_owned_environment(args, argv, tree_storage, public_hash_kernel):
    """Exact test-only parent environment; the Rust owners perform admission."""
    require(args.profile in ('full', 'direct-full') and args.expect_tests and args.build_label,
            'owned note test requires a full recorded-test profile')
    require(tree_storage == 'device' and public_hash_kernel == 'baseline',
            'owned note test requires its fixed storage and hashing profile')
    require(exact_owned_test(argv, 'lattica_prover_p3-', NOTE_OWNED_TEST)
            or exact_owned_test(argv, 'lattica_pq_direct_spend_research-', NOTE_HANDOFF_TEST)
            or exact_owned_test(argv, 'lattica_pq_direct_spend_research-', NOTE_WORKFLOW_TEST),
        'owned note environment requires the exact isolated qualification test')
    path = Path(__file__).with_name('note_startup_environment.py')
    spec = importlib.util.spec_from_file_location('fixed_note_environment', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_environment(0, getattr(args, 'device_uuid', None))


def note_cpu_environment(args, argv, tree_storage, public_hash_kernel):
    """Same process/thread envelope, explicit CPU proving and no GPU selectors."""
    require(args.profile in ('full', 'direct-full') and args.expect_tests and args.build_label,
            'CPU note workflow requires a full recorded-test profile')
    require(not getattr(args, 'note_owned_proof', False)
            and getattr(args, 'owned_runtime_test', None) is None,
            'CPU note workflow cannot combine owned GPU modes')
    require(getattr(args, 'device_uuid', None) is None
            and tree_storage == 'device' and public_hash_kernel == 'baseline',
            'CPU note workflow does not accept GPU device or storage selectors')
    require(exact_owned_test(argv, 'lattica_pq_direct_spend_research-', NOTE_CPU_WORKFLOW_TEST),
            'CPU note environment requires its exact isolated workflow test')
    path = Path(__file__).with_name('note_startup_environment.py')
    spec = importlib.util.spec_from_file_location('fixed_note_cpu_environment', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    environment = dict(module.BASE)
    environment.update(RAYON_NUM_THREADS='8', LATTICA_PROVING_POLICY='cpu-required',
                       LATTICA_PROVING_REPORT='1')
    serialized = b''.join((name + '=' + environment[name] + '\0').encode('utf-8')
                          for name in sorted(environment))
    return environment, {
        'schema': 'private-note-cpu-workflow-environment-v1',
        'entry_count': len(environment), 'serialized_bytes': len(serialized),
        'sha256_sorted_name_equals_value_nul': hashlib.sha256(serialized).hexdigest(),
        'requires_env_clear_before_exec': True,
        'requires_immutable_environment_after_exec': True,
        'physical_identity_verified': False, 'complete_external_admission': False,
        'dispatch_authority': False,
    }


def owned_runtime_environment(args, argv, tree_storage, public_hash_kernel):
    selector = getattr(args, 'owned_runtime_test', None)
    require(not getattr(args, 'note_owned_proof', False), 'owned test modes are exclusive')
    require(selector in OWNED_RUNTIME_TESTS, 'unknown owned runtime qualification')
    require(args.profile in ('full', 'direct-full') and args.expect_tests and args.build_label,
            'owned runtime test requires a full recorded-test profile')
    expected_storage = 'host' if selector in ('outer', 'native-shake-host', 'native-shake-continuation', 'native-shake-continuation-rejection', 'native-to-outer', 'outer-continuation', 'native-pair-sequence', 'native-odd-tail-sequence') else 'device'
    require(tree_storage == expected_storage and public_hash_kernel == 'baseline',
            'owned runtime test requires its exact storage and hashing profile')
    binary_prefix = ('lattica_prover_p3-' if selector == 'native-shake-rejection'
                     else 'lattica_pq_ringct_research-')
    require(exact_owned_test(argv, binary_prefix, OWNED_RUNTIME_TESTS[selector]),
            'owned runtime environment requires its exact isolated test')
    path = Path(__file__).with_name('note_startup_environment.py')
    spec = importlib.util.spec_from_file_location('fixed_runtime_environment', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    environment, base = module.build_environment(0, getattr(args, 'device_uuid', None))
    if selector == 'outer':
        environment['LATTICA_OWNED_OUTER_QUALIFICATION'] = '1'
        environment['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'host'
        environment['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'] = str(8 * GIB)
    if selector == 'native-shake-host':
        environment['LATTICA_OWNED_NATIVE_SHAKE_HOST_QUALIFICATION'] = '1'
        environment['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'host'
        environment['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'] = str(8 * GIB)
    if selector == 'native-shake-continuation':
        environment['LATTICA_OWNED_NATIVE_SHAKE_CONTINUATION_QUALIFICATION'] = '1'
        environment['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'host'
        environment['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'] = str(8 * GIB)
    if selector == 'native-shake-continuation-rejection':
        environment['LATTICA_OWNED_NATIVE_SHAKE_CONTINUATION_REJECTION_QUALIFICATION'] = '1'
        environment['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'host'
        environment['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'] = str(8 * GIB)
    sequence_flags = {
        'native-pair-sequence': 'LATTICA_OWNED_SHAKE_PAIR_SEQUENCE_QUALIFICATION',
        'native-odd-tail-sequence': 'LATTICA_OWNED_SHAKE_ODD_TAIL_SEQUENCE_QUALIFICATION',
    }
    if selector in sequence_flags:
        require(getattr(args, 'device_uuid', None) is not None,
                'native sequence requires the physical GPU pin')
        environment[sequence_flags[selector]] = '1'
        environment['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'host'
        environment['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'] = str(8 * GIB)
    if selector == 'outer-continuation':
        environment['LATTICA_OWNED_SHAKE_OUTER_RETIREMENT_QUALIFICATION'] = '1'
        environment['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'host'
        environment['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'] = str(8 * GIB)
    if selector == 'native-to-outer':
        environment['LATTICA_OWNED_SHAKE_OUTER_CONTINUATION_QUALIFICATION'] = '1'
        environment['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'host'
        environment['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'] = str(8 * GIB)
    if selector == 'native-shake':
        environment['LATTICA_OWNED_NATIVE_SHAKE_QUALIFICATION'] = '1'
    if selector == 'native-shake-rejection':
        environment['LATTICA_OWNED_NATIVE_SHAKE_REJECTION_QUALIFICATION'] = '1'
    serialized = b''.join((name + '=' + environment[name] + '\0').encode('utf-8')
                          for name in sorted(environment))
    return environment, {**base, 'schema': 'ringct-owned-runtime-test-environment-v1',
                         'selector': selector, 'entry_count': len(environment),
                         'serialized_bytes': len(serialized),
                         'sha256_sorted_name_equals_value_nul': hashlib.sha256(serialized).hexdigest()}


def direct_ring_screen_environment(args, argv, tree_storage, public_hash_kernel, environment):
    """Seven fresh research relations under the existing direct-full envelope."""
    require(args.profile == 'direct-full' and args.expect_tests and args.build_label,
            'direct ring screen requires its full recorded-test profile')
    require(tree_storage == 'host' and public_hash_kernel == 'baseline',
            'direct ring screen requires baseline hashing and host trees')
    require(getattr(args, 'device_uuid', None) is not None,
            'direct ring screen requires the physical GPU pin')
    require(exact_owned_test(argv, 'lattica_pq_direct_spend_research-', DIRECT_RING_SCREEN_TEST),
            'direct ring screen requires its exact isolated qualification test')
    requested = STATE / 'artifacts' / args.label
    require(not requested.exists() and not requested.is_symlink(),
            'direct ring screen output must be fresh')
    output = requested.resolve()
    encoded = str(output).encode('utf-8')
    require(len(encoded) <= 1024, 'direct ring screen output exceeds its source path bound')
    environment = dict(environment)
    environment.update(LATTICA_DIRECT_RING_SCREEN_QUALIFICATION='1',
                       LATTICA_DIRECT_RING_SCREEN_OUTPUT_DIR=str(output))
    serialized = b''.join((name + '=' + environment[name] + '\0').encode('utf-8')
                          for name in sorted(environment))
    return environment, {
        'schema': 'direct-ring-seven-case-screen-environment-v1',
        'selector': DIRECT_RING_SCREEN_TEST, 'output_directory': str(output),
        'entry_count': len(environment), 'serialized_bytes': len(serialized),
        'sha256_sorted_name_equals_value_nul': hashlib.sha256(serialized).hexdigest(),
        'requires_env_clear_before_exec': True,
        'requires_immutable_environment_after_exec': True,
        'complete_faithful_ringct_workflow': False,
        'n3_n4_aggregate_qualification': False, 'performance_qualified': False,
        'dispatch_authority': False,
    }


DIRECT_RING_IDENTITY_TESTS = {
    'baseline': 'ring_screen::identity_experiment::tests::gpu_direct_ring_identity_cold_baseline',
    'receipt-v1': 'ring_screen::identity_experiment::tests::gpu_direct_ring_identity_receipt_cross_session',
}


def direct_ring_identity_environment(args, argv, tree_storage, public_hash_kernel, environment):
    """Exact single-case fresh research workflow with explicit receipt provenance."""
    mode = getattr(args, 'direct_ring_identity_test', None)
    require(mode in DIRECT_RING_IDENTITY_TESTS, 'unknown direct-ring identity experiment')
    require(args.profile == 'direct-full' and args.expect_tests and args.build_label,
            'identity experiment requires its full recorded-test profile')
    require(not args.expect_result and not getattr(args, 'expect_direct_result', False)
            and not getattr(args, 'benchmark', False), 'identity experiment is a separate research screen')
    require(tree_storage == 'host' and public_hash_kernel == 'baseline',
            'identity experiment requires baseline hashing and host trees')
    require(getattr(args, 'device_uuid', None) is not None,
            'identity experiment requires the physical GPU pin')
    require(exact_owned_test(argv, 'lattica_pq_direct_spend_research-', DIRECT_RING_IDENTITY_TESTS[mode]),
            'identity experiment requires its exact isolated qualification test')
    requested = STATE / 'artifacts' / args.label
    require(not requested.exists() and not requested.is_symlink(),
            'identity experiment output must be fresh')
    output = requested.resolve()
    require(len(str(output).encode('utf-8')) <= 1024, 'identity output exceeds its source path bound')
    environment = dict(environment)
    environment.update(LATTICA_DIRECT_RING_IDENTITY_QUALIFICATION='1',
                       LATTICA_DIRECT_RING_IDENTITY_OUTPUT_DIR=str(output),
                       LATTICA_DIRECT_RING_IDENTITY_MODE=mode)
    serialized = b''.join((name + '=' + environment[name] + '\0').encode('utf-8')
                          for name in sorted(environment))
    return environment, {
        'schema': 'direct-ring-identity-experiment-environment-v1',
        'mode': mode, 'selector': DIRECT_RING_IDENTITY_TESTS[mode], 'output_directory': str(output),
        'entry_count': len(environment), 'serialized_bytes': len(serialized),
        'sha256_sorted_name_equals_value_nul': hashlib.sha256(serialized).hexdigest(),
        'requires_env_clear_before_exec': True, 'requires_immutable_environment_after_exec': True,
        'complete_faithful_ringct_workflow': False, 'n3_n4_aggregate_qualification': False,
        'performance_qualified': False, 'dispatch_authority': False,
    }


DIRECT_RING_RECURSION_TESTS = {
    'caller-census': ('ring_circuit::verification::recursive_child::tests::'
                      'recursive_inline_owners_fit_inside_existing_verifier_caller_allowance'),
    'child': ('ring_circuit::recursion::tests::'
              'genuine_direct_ring_child_closes_recursive_constraints_and_rejects_public_mutations'),
    'outer': ('ring_circuit::recursion::outer::tests::'
              'genuine_direct_ring_child_has_fresh_outer_proof_and_independent_cpu_verification'),
}
DIRECT_RING_RECURSION_FLAGS = {
    'child': 'LATTICA_DIRECT_RING_RECURSIVE_QUALIFICATION',
    'outer': 'LATTICA_DIRECT_RING_OUTER_QUALIFICATION',
}


def direct_ring_recursion_environment(args, argv, tree_storage, public_hash_kernel, environment):
    """One source-bound component; CPU caller admission precedes any GPU child."""
    mode = getattr(args, 'direct_ring_recursion_test', None)
    census = getattr(args, 'direct_ring_recursion_census_label', None)
    require(mode in DIRECT_RING_RECURSION_TESTS, 'unknown direct-ring recursion qualifier')
    require(args.expect_tests and args.build_label and not args.record_artifact
            and not args.expect_result and not getattr(args, 'expect_direct_result', False)
            and not getattr(args, 'benchmark', False),
            'recursion qualification requires a recorded isolated test executable')
    selector = DIRECT_RING_RECURSION_TESTS[mode]
    require(public_hash_kernel == 'baseline', 'recursion qualification requires baseline hashing')
    if mode == 'caller-census':
        require(args.profile == 'research-compile-large' and tree_storage == 'device'
                and getattr(args, 'device_uuid', None) is None and census is None,
                'caller census requires its CPU-only profile without GPU or prior-census selection')
        require(Path(argv[0]).name.startswith('lattica_pq_direct_spend_research-')
                and argv[1:] == [selector, '--exact', '--test-threads=1', '--nocapture'],
                'caller census requires its exact nonignored single test')
    else:
        require(args.profile == 'direct-full' and tree_storage == 'host'
                and getattr(args, 'device_uuid', None) is not None,
                'recursive GPU component requires direct-full, host trees and physical device pin')
        require(type(census) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,55}', census)
                and census != args.label,
                'recursive GPU component requires a distinct prior caller-census label')
        require(exact_owned_test(argv, 'lattica_pq_direct_spend_research-', selector),
                'recursive GPU component requires its exact ignored single test')
        environment = dict(environment, **{DIRECT_RING_RECURSION_FLAGS[mode]: '1'})
    serialized = b''.join((name + '=' + environment[name] + '\0').encode('utf-8')
                          for name in sorted(environment))
    return environment, {
        'schema': 'direct-ring-recursion-component-environment-v1',
        'mode': mode, 'selector': selector, 'prior_caller_census_label': census,
        'caller_allowance_bytes': 1 << 20, 'recursive_caller_subceiling_bytes': 192 << 10,
        'requires_same_source_build_and_executable_census': mode != 'caller-census',
        'entry_count': len(environment), 'serialized_bytes': len(serialized),
        'sha256_sorted_name_equals_value_nul': hashlib.sha256(serialized).hexdigest(),
        'requires_env_clear_before_exec': True, 'requires_immutable_environment_after_exec': True,
        'complete_faithful_ringct_workflow': False, 'n3_n4_aggregate_qualification': False,
        'performance_qualified': False, 'dispatch_authority': False,
    }


def require_direct_ring_recursion_build(plan, executable):
    """The normal provenance path already checked sources and Cargo inventory."""
    selected = plan.get('direct_ring_recursion_environment')
    if selected is None:
        return
    build_path = Path(executable['build_record'])
    require(sha(build_path) == executable['build_record_sha256'], 'recursive build record changed')
    build = json.loads(build_path.read_text())
    argv = build.get('command', [])
    require(argv and Path(argv[0]).name == 'cargo' and argv[1:2] == ['test']
            and '--no-run' in argv and '--release' in argv
            and not any(arg == '--profile' or arg.startswith('--profile=') for arg in argv),
            'recursive qualifier requires a release Cargo test --no-run build')
    features, manifests = set(), []
    for index, arg in enumerate(argv):
        if arg == '--features':
            require(index + 1 < len(argv), 'missing recursive build features')
            features.update(re.split(r'[,\s]+', argv[index + 1]))
        elif arg.startswith('--features='):
            features.update(re.split(r'[,\s]+', arg.split('=', 1)[1]))
        elif arg == '--manifest-path':
            require(index + 1 < len(argv), 'missing recursive build manifest')
            manifests.append(argv[index + 1])
        elif arg.startswith('--manifest-path='):
            manifests.append(arg.split('=', 1)[1])
    require(len(manifests) == 1, 'recursive build requires its exact research manifest')
    manifest = Path(manifests[0])
    require((manifest if manifest.is_absolute() else ROOT / manifest).resolve()
            == (ROOT / 'research/pq-direct-spend/Cargo.toml').resolve(),
            'recursive build targets another manifest')
    accepted = {'ring-recursive-outer-experiment'} if selected['mode'] == 'outer' else {
        'ring-recursion-experiment', 'ring-recursive-outer-experiment'}
    require(bool(features & accepted), 'recursive build lacks its explicit opt-in feature')


def recursive_single_test(content, selector):
    normalized = re.sub(r'^test ' + re.escape(selector) + r' \.\.\. ', '', content, flags=re.M)
    footers = list(re.finditer(r'^test result: ok\. 1 passed; 0 failed; 0 ignored;.*$', normalized, re.M))
    require(len(footers) == 1 and len(re.findall(r'^test result:', normalized, re.M)) == 1,
            'recursive qualifier requires exactly one passing, nonignored test')
    require(not any(marker in normalized for marker in (
        'OPENCL_OPT_RESULT', 'DIRECT_SPEND_RESULT', 'DIRECT_RING_RESULT',
        'direct_ring_recursive_constraint_failure', 'direct_ring_recursive_outer_failure')),
        'recursive component emitted failure or unrelated workflow evidence')
    return normalized, footers[0].start()


def recursive_timing_guard():
    path = Path(__file__).with_name('direct_ring_component_timing_guard.py')
    spec = importlib.util.spec_from_file_location('direct_ring_component_timing_guard', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_direct_ring_caller_census(content):
    content, footer = recursive_single_test(content, DIRECT_RING_RECURSION_TESTS['caller-census'])
    require(not any(marker in content for marker in (
        'PUBLIC_HASH_EXECUTION', 'proving_stage_report', 'NATIVE_EXECUTION_RECEIPT',
        'direct_ring_recursive_child_proving_report', 'direct_ring_recursive_constraint_report',
        'direct_ring_recursive_outer_child_proving_report', 'direct_ring_recursive_outer_report')),
        'CPU caller census emitted proving evidence')
    marker = 'direct_ring_recursive_caller_bytes '
    matches = list(re.finditer(r'^' + marker + r'actual=([1-9][0-9]*) allowance=1048576 remaining=(0|[1-9][0-9]*)$', content, re.M))
    require(content.count(marker) == 1 and len(matches) == 1 and matches[0].start() < footer,
            'missing, duplicated or malformed recursive caller census')
    actual, remaining = map(int, matches[0].groups())
    require(0 < actual <= 1 << 20 and actual + remaining == 1 << 20,
            'recursive caller census exceeds original allowance')
    orchestration = recursive_timing_guard().orchestration(content, matches[0].start())
    return {'scope': 'caller_census_only', 'caller_requested_bytes': actual,
            'outer_orchestration': orchestration,
            'caller_allowance_bytes': 1 << 20, 'caller_remaining_bytes': remaining,
            'recursive_caller_subceiling_bytes': 192 << 10,
            'cryptographic_proof_started': False, 'performance_qualified': False}


def prior_direct_ring_caller_census(plan, sources, executable, runs):
    selected = plan['direct_ring_recursion_environment']
    label = selected['prior_caller_census_label']
    require(selected['mode'] in ('child', 'outer') and type(label) is str
            and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,55}', label), 'invalid prior caller census')
    record_path, log_path = runs / (label + '.json'), runs / (label + '.log')
    record = json.loads(record_path.read_text())
    require(record.get('status') == 'passed' and record.get('profile') == 'research-compile-large'
            and record.get('source_inputs_unchanged') is True
            and record.get('executable_unchanged') is True
            and record.get('all_subprocesses_terminal_and_reaped') is True
            and record.get('service_stop_completed') is True,
            'recursive GPU component requires a terminal CPU caller-census pass')
    require(record.get('input_sha256') == sources
            and record.get('executable_provenance') == executable
            and record.get('build_label') == plan['build_label'],
            'caller census source, executable or build differs')
    require(record.get('command') == [plan['command'][0], DIRECT_RING_RECURSION_TESTS['caller-census'],
                                     '--exact', '--test-threads=1', '--nocapture']
            and record.get('expect_tests') is True and record.get('expect_result') is False
            and record.get('expect_direct_result') is False and record.get('benchmark') is False,
            'prior record is not the exact isolated caller census')
    expected = build_plan(argparse.Namespace(
        profile='research-compile-large', label=label, seconds=record.get('runtime_seconds', 0),
        command=record['command'], expect_tests=True, expect_result=False, expect_direct_result=False,
        build_label=plan['build_label'], record_artifact=[], retained_tree_storage='device',
        public_hash_kernel='baseline', device_uuid=None, direct_ring_recursion_test='caller-census'))
    for key in ('environment', 'direct_ring_recursion_environment', 'memory_max_bytes',
                'memory_high_bytes', 'fresh_memavailable_required_bytes', 'cpu_quota',
                'public_hash_kernel', 'performance_qualified', 'record_artifacts'):
        require(record.get(key) == expected[key], 'prior caller-census policy changed: ' + key)
    require(record.get('raw_log') == str(log_path) and log_path.is_file()
            and sha(log_path) == record.get('raw_log_sha256'), 'prior caller-census log changed')
    accepted = validate_direct_ring_caller_census(log_path.read_text(errors='replace'))
    if selected['mode'] == 'outer':
        require(accepted['outer_orchestration'] is not None,
                'outer qualifier requires its original-allowance orchestration census')
    require(record.get('direct_ring_recursion_acceptance') == accepted,
            'prior caller-census acceptance differs from log')
    require_direct_ring_recursion_build(plan, executable)
    return {'record': str(record_path), 'record_sha256': sha(record_path),
            'log': str(log_path), 'log_sha256': sha(log_path),
            'build_record_sha256': executable['build_record_sha256'],
            'executable_sha256': executable['sha256'],
            'source_manifest_sha256': hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest(),
            'acceptance': accepted}


def recursive_report(content, marker):
    lines = [line[len(marker):] for line in content.splitlines() if line.startswith(marker)]
    require(len(lines) == 1 and content.count(marker) == 1,
            'missing or duplicate recursive component report: ' + marker)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate recursive component report field')
            result[key] = value
        return result
    report = json.loads(lines[0], object_pairs_hook=unique)
    require(type(report) is dict, 'recursive component report must be an object')
    return report


def recursive_phase_receipts(report, plan, proof, worker_host):
    from opencl_direct_spend_audit import native, terminal, integer
    from public_hash_evidence import require_requested
    native(report.get('registration', {}), False)
    if proof:
        native(report.get('proving', {}), True)
    terminal(report.get('terminal', {}), proof)
    require_requested(report.get('public_hash'), 'baseline', plan['environment']['LATTICA_V2_GPU_PUBLIC_HASH'])
    footprint = report.get('footprint', {})
    require(type(footprint) is dict, 'missing recursive GPU phase footprint')
    expected_uuid = list(bytes.fromhex(plan['environment']['LATTICA_GPU_DEVICE_UUID'][4:].replace('-', '')))
    for field, value in (('managed_limit_bytes', 8 * GIB), ('context_reserve_bytes', 4 * GIB),
                         ('worker_host_limit_bytes', worker_host), ('host_tree_quota_bytes', 8 * GIB),
                         ('caller_reserved_host_bytes', 1 << 20), ('physical_device_uuid', expected_uuid)):
        require(footprint.get(field) == value, 'recursive phase changed original limit/device: ' + field)
    integer(footprint.get('backend_host_budget_bytes'), 'recursive native allowance', 1, 24 * GIB)
    integer(footprint.get('host_phase_peak_bytes'), 'recursive worker peak', 1, worker_host)
    integer(footprint.get('device_phase_peak_bytes'), 'recursive managed peak', 1, 8 * GIB)
    require(footprint.get('tree_storage_mode') == 'host_backing'
            and footprint.get('requires_consuming_registration') is True
            and footprint.get('witness_instructions_retired_before_quotient_required') is True,
            'recursive phase changed storage or registration lifetime')


def direct_ring_outer_artifact_report(result):
    path = Path(__file__).with_name('direct_ring_outer_artifact_guard.py')
    spec = importlib.util.spec_from_file_location('direct_ring_outer_artifact_guard', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.validate(result)


def validate_direct_ring_recursion(content, plan):
    selected = plan['direct_ring_recursion_environment']
    mode = selected['mode']
    if mode == 'caller-census':
        return validate_direct_ring_caller_census(content)
    content, footer = recursive_single_test(content, selected['selector'])
    child_marker = ('direct_ring_recursive_child_proving_report ' if mode == 'child'
                    else 'direct_ring_recursive_outer_child_proving_report ')
    result_marker = ('direct_ring_recursive_constraint_report ' if mode == 'child'
                     else 'direct_ring_recursive_outer_report ')
    child = recursive_report(content, child_marker)
    result = recursive_report(content, result_marker)
    require(content.index(child_marker) < content.index(result_marker) < footer,
            'recursive report order changed')
    require(child.get('schema') == 'lattica-research-direct-ring-gpu-proof-v1'
            and child.get('proof_generation') == 'fresh-only' and child.get('policy') == 'gpu_required'
            and child.get('registration_lifetime') == 'consumed-once'
            and child.get('witness_instructions_retired_before_quotient') is True
            and child.get('independent_verification_required') is True,
            'recursive child lacks fresh consuming GPU generation')
    recursive_phase_receipts(child, plan, True, 32 * GIB)
    verified = result.get('child_verification', {})
    require(verified.get('schema') == 'lattica-research-direct-ring-independent-verification-v1'
            and verified.get('verified') is True and verified.get('reused_prover_state') is False
            and verified.get('synthetic_hints_evaluated') is False
            and verified.get('public_reconstruction') == 'complete-program-and-fresh-preprocessing-cap'
            and verified.get('verifier_preprocessing_policy') == 'gpu_required'
            and verified.get('proof_verification_backend') == 'cpu' and verified.get('mutation_checks') == 2
            and 'identity_reuse' not in verified,
            'recursive child lacks fresh independent verification and negative probes')
    recursive_phase_receipts(verified, plan, False, 32 * GIB)
    require(type(result.get('independently_verified_children')) is int
            and result.get('independently_verified_children') == 1
            and result.get('complete_transaction_aggregate') is False
            and result.get('final_aggregate') is False, 'recursive result scope changed')
    timing = {}
    if mode == 'child':
        recursive_timing_guard().child_only(content)
        require(result.get('schema') == 'lattica-research-direct-ring-recursive-constraints-v1'
                and result.get('scope') == 'one-full-direct-ring-child-recursive-constraints-only'
                and result.get('recursive_proofs_generated') == 0
                and result.get('all_recursive_constraints_satisfied') is True
                and result.get('public_binding_mutation_rejections') == 4,
                'recursive constraint-only qualification incomplete')
    else:
        require(result.get('schema') == 'lattica-research-direct-ring-single-child-recursive-proof-v1'
                and result.get('scope') == 'one-direct-ring-child-one-outer-proof'
                and result.get('proof_generation') == 'fresh-only'
                and type(result.get('outer_recursive_proofs_generated')) is int
                and result.get('outer_recursive_proofs_generated') == 1
                and type(result.get('independently_verified_outer_proofs')) is int
                and result.get('independently_verified_outer_proofs') == 1
                and result.get('artifact_roundtrip') is True
                and result.get('source_cap_provenance') == 'private-expected-public-independent-child-reconstruction',
                'recursive outer qualification scope or cap provenance changed')
        outer = result.get('independent_verification', {})
        require(outer.get('cpu_verified') is True and outer.get('source_manifest_matches') is True
                and outer.get('synthetic_hints_evaluated') is False
                and outer.get('public_mutation_rejections') == 4
                and outer.get('opening_mutation_rejections') == 1,
                'recursive outer independent verification or negative probes incomplete')
        recursive_phase_receipts(result.get('proving', {}), plan, True, 32 * GIB)
        recursive_phase_receipts(outer, plan, False, 32 * GIB - (64 << 20))
        require(result.get('proving', {}).get('descriptor') == outer.get('descriptor')
                and type(outer.get('descriptor')) is dict, 'outer verifier descriptor changed')
        storage = result.get('storage', {})
        require(storage.get('independent_registration_host_partition_bytes') == 32 * GIB - (64 << 20)
                and storage.get('retained_outer_proof_allowance_bytes') == 64 << 20
                and storage.get('caller_reserved_bytes') == 1 << 20,
                'outer retained proof escaped the original worker/caller partition')
        direct_ring_outer_artifact_report(result)
        timing = recursive_timing_guard().component(
            content, footer, child, result, plan.get('observation_before_validation_ns'))
    return {'scope': 'single_child_constraints_only' if mode == 'child' else 'single_child_outer_proof_only',
            'fresh_child_proofs': 1, 'fresh_outer_proofs': 0 if mode == 'child' else 1,
            'independent_cpu_verifications': 1 if mode == 'child' else 2,
            'complete_faithful_ringct_workflow': False, 'artifact_roundtrip': mode == 'outer',
            'artifact_transport_scope': 'in-memory-encode-decode' if mode == 'outer' else None,
            'archived_artifact_qualified': False,
            'complete_transaction_aggregate': False, 'final_aggregate': False,
            'performance_qualified': False, 'child_proving_report': child, 'component_report': result, **timing}


OWNED_SOURCE_SHAPE_TEST = ('component_tree::owned_shake::source_shape::tests::'
                           'source_bound_precedes_genuine_single_pair_and_odd_tail_compilation')

PARENT_SOURCE_INPUT_TEST = ('block_v2::machine::gpu_backend::resources::admission::'
                            'outer_producer::source::tests::'
                            'parent_upper_bound_still_requires_actual_program_public_and_witness_lengths')


ORIGINAL_COMPILER_BANK_SOURCE_TEST = 'component_tree::owned_shake::request_merge::source::capture::acceptance::parent::bank::tests::exact_hashx_compiler_bank_admits_original_maximum_and_refuses_short_capacity'

ORIGINAL_HASHX_SEQUENCE_SOURCE_TEST = 'component_tree::owned_shake::request_merge::source::capture::acceptance::parent::production::sequence::qualification::cpu_original_hashx_sequence_capacity'

ORIGINAL_HASHX_ROOT_PUBLIC_SOURCE_TEST = 'component_tree::owned_shake::request_merge::source::capture::acceptance::parent::production::sequence::qualification::cpu_original_hashx_sequence_root_public_capacity'
ORIGINAL_HASHX_ROOT_TRANSPORT_SOURCE_TEST = 'component_tree::owned_shake::request_merge::source::capture::acceptance::parent::production::sequence::qualification::transport::cpu_original_hashx_sequence_root_transport_capacity'
ORIGINAL_HASHX_ROOT_OPENING_SOURCE_TEST = 'component_tree::owned_shake::request_merge::source::capture::acceptance::parent::production::sequence::qualification::opening::cpu_original_hashx_sequence_root_opening_capacity'
ORIGINAL_HASHX_INTERIOR_OPENING_SOURCE_TEST = 'component_tree::owned_shake::request_merge::source::capture::acceptance::parent::production::sequence::qualification::interior::cpu_original_hashx_sequence_leaf0_opening_capacity'

REQUEST_SOURCE_TESTS = {
    'parent-sources': ('component_tree::owned_shake::request_merge::source::tests::'
                       'exact_hashx_parent_sources_close_before_dispatch_and_keep_request_refusal',
                       'LATTICA_OWNED_SHAKE_PARENT_SOURCE_QUALIFICATION'),
    'existing-batches': ('component_tree::owned_shake::source_shape::tests::'
                         'active_hashx_existing_batches_have_admitted_pair_source_bounds',
                         'LATTICA_OWNED_SHAKE_BATCH_SOURCE_QUALIFICATION'),
    'request-closure': ('component_tree::owned_shake::request_merge::tests::'
                        'five_original_leaf_sources_still_refuse_complete_request_and_release_all_owners',
                        'LATTICA_OWNED_SHAKE_REQUEST_CLOSURE_QUALIFICATION'),
}


def request_source_environment(args, argv, tree_storage, public_hash_kernel, environment):
    mode = getattr(args, 'owned_request_source_test', None)
    require(mode in REQUEST_SOURCE_TESTS, 'unknown request source qualification')
    selector, flag = REQUEST_SOURCE_TESTS[mode]
    require(args.profile == 'research-compile-large' and args.expect_tests and args.build_label,
            'request source qualifier requires its recorded CPU research profile')
    require(not args.expect_result and not getattr(args, 'expect_direct_result', False)
            and not getattr(args, 'benchmark', False), 'request source qualifier cannot qualify proving')
    require(tree_storage == 'device' and public_hash_kernel == 'baseline'
            and getattr(args, 'device_uuid', None) is None,
            'request source qualifier cannot select GPU storage, kernels or devices')
    require(exact_owned_test(argv, 'lattica_pq_ringct_research-', selector),
            'request source qualifier requires its exact isolated CPU test')
    require(environment.get('LATTICA_PROVING_POLICY') == 'cpu-required'
            and not any('GPU' in key for key in environment),
            'request source qualifier must have a CPU-only environment')
    environment = dict(environment)
    environment[flag] = '1'
    serialized = b''.join((name + '=' + environment[name] + '\0').encode('utf-8')
                          for name in sorted(environment))
    return environment, {
        'schema': 'ringct-request-source-test-environment-v1', 'mode': mode, 'selector': selector,
        'entry_count': len(environment), 'serialized_bytes': len(serialized),
        'sha256_sorted_name_equals_value_nul': hashlib.sha256(serialized).hexdigest(),
        'requires_env_clear_before_exec': True, 'requires_immutable_environment_after_exec': True,
        'scope': 'source_planning_only', 'gpu_dispatch': False, 'dispatch_authority': False,
        'complete_request_admission': False, 'complete_faithful_ringct_workflow': False,
        'performance_qualified': False,
    }

ACTIVE_HASHX_PREFLIGHT_TEST = ('block_v2::native_gpu::research::owned_shake::tests::'
                             'active_hashx_preflight::active_hashx_native_shapes_have_bounded_source_preflight')


def active_hashx_preflight_environment(args, argv, tree_storage, public_hash_kernel):
    require(args.profile == 'source-preflight' and args.expect_tests and args.build_label,
            'HashX preflight requires its recorded source-only profile')
    require(not args.expect_result and not getattr(args, 'expect_direct_result', False)
            and not getattr(args, 'benchmark', False), 'HashX preflight cannot qualify proving')
    require(tree_storage == 'host' and public_hash_kernel == 'baseline'
            and getattr(args, 'device_uuid', None) is not None,
            'HashX preflight requires host trees, baseline hashing and a physical GPU pin')
    require(exact_owned_test(argv, 'lattica_prover_p3-', ACTIVE_HASHX_PREFLIGHT_TEST),
            'HashX preflight requires its exact isolated source-only test')
    path = Path(__file__).with_name('note_startup_environment.py')
    spec = importlib.util.spec_from_file_location('fixed_preflight_environment', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    environment, base = module.build_environment(0, args.device_uuid)
    environment.update(LATTICA_OWNED_NATIVE_SHAKE_SHAPE_PREFLIGHT='1',
                       LATTICA_V2_GPU_RETAINED_TREE_STORAGE='host',
                       LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES=str(8 * GIB))
    serialized = b''.join((name + '=' + environment[name] + '\0').encode('utf-8')
                          for name in sorted(environment))
    return environment, {**base, 'schema': 'active-hashx-source-preflight-environment-v1',
                         'selector': ACTIVE_HASHX_PREFLIGHT_TEST,
                         'entry_count': len(environment), 'serialized_bytes': len(serialized),
                         'sha256_sorted_name_equals_value_nul': hashlib.sha256(serialized).hexdigest(),
                         'gpu_dispatch': False, 'performance_qualified': False,
                         'complete_faithful_ringct_workflow': False,
                         'complete_request_admission': False,
                         'scope': 'source_phase_only'}


def source_shape_environment(args, argv, tree_storage, public_hash_kernel, environment):
    require(args.profile == 'research-compile-large' and args.expect_tests and args.build_label,
            'source-shape qualifier requires its recorded CPU research profile')
    require(not args.expect_result and not getattr(args, 'expect_direct_result', False)
            and not getattr(args, 'benchmark', False), 'source-shape qualifier is correctness only')
    require(tree_storage == 'device' and public_hash_kernel == 'baseline'
            and getattr(args, 'device_uuid', None) is None,
            'source-shape qualifier does not select a GPU runtime')
    if exact_owned_test(argv, 'lattica_pq_ringct_research-', ORIGINAL_HASHX_ROOT_TRANSPORT_SOURCE_TEST):
        return first_leaf_module('hashx_root_transport_capacity_guard').build_environment(
            args, environment, str(ROOT), public_hash_kernel, tree_storage)
    if exact_owned_test(argv, 'lattica_pq_ringct_research-', ORIGINAL_HASHX_ROOT_OPENING_SOURCE_TEST):
        return first_leaf_module('hashx_root_opening_capacity_guard').build_environment(
            args, environment, str(ROOT), public_hash_kernel, tree_storage)
    if exact_owned_test(argv, 'lattica_pq_ringct_research-', ORIGINAL_HASHX_INTERIOR_OPENING_SOURCE_TEST):
        return first_leaf_module('hashx_interior_opening_capacity_guard').build_environment(
            args, environment, str(ROOT), public_hash_kernel, tree_storage)
    choices = [('lattica_pq_ringct_research-', OWNED_SOURCE_SHAPE_TEST),
               ('lattica_prover_p3-', PARENT_SOURCE_INPUT_TEST),
               ('lattica_pq_ringct_research-', ORIGINAL_COMPILER_BANK_SOURCE_TEST),
               ('lattica_pq_ringct_research-', ORIGINAL_HASHX_SEQUENCE_SOURCE_TEST),
               ('lattica_pq_ringct_research-', ORIGINAL_HASHX_ROOT_PUBLIC_SOURCE_TEST)]
    selected = [selector for stem, selector in choices if exact_owned_test(argv, stem, selector)]
    require(len(selected) == 1, 'source-shape qualifier requires its exact isolated CPU test')
    require(environment.get('LATTICA_PROVING_POLICY') == 'cpu-required'
            and not any('GPU' in key for key in environment), 'source-shape environment must be CPU-only')
    environment = dict(environment)
    qualification = {
        ORIGINAL_COMPILER_BANK_SOURCE_TEST: 'LATTICA_OWNED_SHAKE_BANK_SOURCE_QUALIFICATION',
        ORIGINAL_HASHX_SEQUENCE_SOURCE_TEST: 'LATTICA_OWNED_HASHX_SEQUENCE_SOURCE_QUALIFICATION',
        ORIGINAL_HASHX_ROOT_PUBLIC_SOURCE_TEST: 'LATTICA_OWNED_HASHX_SEQUENCE_SOURCE_QUALIFICATION',
    }.get(selected[0], 'LATTICA_OWNED_SHAKE_QUALIFICATION')
    environment[qualification] = '1'
    if selected[0] == ORIGINAL_HASHX_ROOT_PUBLIC_SOURCE_TEST:
        environment['LATTICA_OWNED_HASHX_ROOT_PUBLIC_SOURCE_QUALIFICATION'] = '1'
    serialized = b''.join((key + '=' + environment[key] + '\0').encode()
                          for key in sorted(environment))
    return environment, {'schema': 'ringct-owned-source-shape-test-environment-v1',
                         'selector': selected[0], 'entry_count': len(environment),
                         'serialized_bytes': len(serialized),
                         'sha256_sorted_name_equals_value_nul': hashlib.sha256(serialized).hexdigest(),
                         'gpu_dispatch': False, 'performance_qualified': False,
                         'complete_faithful_ringct_workflow': False}


def native_hashx_guard():
    path = Path(__file__).with_name('native_hashx_scratch_guard.py')
    spec = importlib.util.spec_from_file_location('native_hashx_scratch_guard', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def native_hashx_environment(args, argv, tree_storage, public_hash_kernel):
    path = Path(__file__).with_name('note_startup_environment.py')
    spec = importlib.util.spec_from_file_location('fixed_native_hashx_environment', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    base, _ = module.build_environment(0, getattr(args, 'device_uuid', None))
    return native_hashx_guard().build_environment(
        args, argv, tree_storage, public_hash_kernel, base, str(ROOT))


def first_leaf_module(name):
    path = Path(__file__).with_name(name + '.py')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def first_leaf_environment(args, argv, tree_storage, public_hash_kernel, environment):
    if args.owned_hashx_leaf_test == 'gpu':
        environment, _ = first_leaf_module('note_startup_environment').build_environment(
            0, getattr(args, 'device_uuid', None))
    return first_leaf_module('hashx_first_leaf_guard').build_environment(
        args, argv, tree_storage, public_hash_kernel, environment, str(ROOT))


def sequence_preissue_environment(args, tree_storage, public_hash_kernel):
    environment, _ = first_leaf_module('note_startup_environment').build_environment(
        0, getattr(args, 'device_uuid', None))
    return first_leaf_module('hashx_sequence_preissue_guard').build_environment(
        args, environment, str(ROOT), public_hash_kernel, tree_storage)


def root_public_gpu_environment(args, tree_storage, public_hash_kernel):
    environment, _ = first_leaf_module('note_startup_environment').build_environment(
        0, getattr(args, 'device_uuid', None))
    return first_leaf_module('hashx_root_public_gpu_guard').build_environment(
        args, environment, str(ROOT), public_hash_kernel, tree_storage)


def root_transport_gpu_environment(args, tree_storage, public_hash_kernel):
    environment, _ = first_leaf_module('note_startup_environment').build_environment(
        0, getattr(args, 'device_uuid', None))
    return first_leaf_module('hashx_root_transport_gpu_guard').build_environment(
        args, environment, str(ROOT), public_hash_kernel, tree_storage)


def root_opening_gpu_environment(args, tree_storage, public_hash_kernel):
    environment, _ = first_leaf_module('note_startup_environment').build_environment(
        0, getattr(args, 'device_uuid', None))
    return first_leaf_module('hashx_root_opening_gpu_guard').build_environment(
        args, environment, str(ROOT), public_hash_kernel, tree_storage)


def interior_opening_gpu_environment(args, tree_storage, public_hash_kernel):
    environment, _ = first_leaf_module('note_startup_environment').build_environment(
        0, getattr(args, 'device_uuid', None))
    return first_leaf_module('hashx_interior_opening_gpu_guard').build_environment(
        args, environment, str(ROOT), public_hash_kernel, tree_storage)


def sequence_refusal_environment(args, tree_storage, public_hash_kernel):
    environment, _ = first_leaf_module('note_startup_environment').build_environment(
        0, getattr(args, 'device_uuid', None))
    return first_leaf_module('hashx_sequence_refusal_guard').build_environment(
        args, environment, str(ROOT), public_hash_kernel, tree_storage)


def build_plan(args):
    require(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,55}', args.label), 'unsafe run label')
    maximum, high, admission, threads, runtime = PROFILES[args.profile]
    require(1 <= args.seconds <= runtime, 'runtime exceeds selected correctness profile')
    argv = list(args.command)
    if argv and argv[0] == '--':
        argv.pop(0)
    require(argv and Path(argv[0]).is_absolute(), 'command needs an absolute executable path')
    complete_case = getattr(args, 'full_workflow_case', False)
    identity_qualification = getattr(args, 'identity_cpu_qualification', False)
    metadata_qualification = getattr(args, 'metadata_cpu_qualification', False)
    native_metadata_profile = getattr(args, 'native_metadata_profile', False)
    if native_metadata_profile:
        require(args.profile == 'research-compile-large' and args.expect_tests and args.build_label
                and not complete_case and not identity_qualification and not metadata_qualification,
                'native metadata profiling requires its dedicated recorded CPU test')
        require(len(argv) == 6 and argv[1] == 'component_tree::native_shape::profiling::tests::native_metadata_profile'
                and set(argv[2:]) == {'--exact', '--ignored', '--test-threads=1', '--nocapture'},
                'wrong native metadata profiling selector')
    if metadata_qualification:
        require(args.profile == 'research-compile-large' and args.expect_tests and args.build_label
                and not complete_case and not identity_qualification,
                'metadata qualification requires its dedicated recorded CPU test')
        require(len(argv) == 6 and argv[1] == 'block_v2::machine::verifier::batch::shape::metadata_planning::tests::metadata_cpu_worker_qualification'
                and set(argv[2:]) == {'--exact', '--ignored', '--test-threads=1', '--nocapture'},
                'wrong metadata CPU qualification selector')
    if identity_qualification:
        require(args.profile == 'full' and args.expect_tests and not complete_case,
                'CPU identity qualification requires its dedicated full-profile test')
        require(len(argv) == 6 and argv[1] == 'identity_preprocessing_screen::cpu_recursive_identity_worker_qualification'
                and set(argv[2:]) == {'--exact', '--ignored', '--test-threads=1', '--nocapture'},
                'wrong CPU identity qualification selector')
    identity_cpus = identity_physical_cpus() if complete_case or identity_qualification or metadata_qualification or native_metadata_profile else None
    if identity_qualification or metadata_qualification or native_metadata_profile:
        require(len(identity_cpus) == 16, '16-worker qualification requires sixteen physical cores')
    host_profile = selected_host_profile(getattr(args, 'host_profile', 'standard'))
    require(host_profile['name'] == 'standard' or (args.profile == 'full' and complete_case),
            'expanded host profiles require an explicit complete RingCT workflow')
    if complete_case:
        require(args.profile == 'full', 'complete workflow requires the full process profile')
        maximum = host_profile['memory_max_bytes'] // GIB
        high = host_profile['memory_high_bytes'] // GIB
        admission = host_profile['fresh_memavailable_required_bytes'] // GIB
    direct_result = getattr(args, 'expect_direct_result', False)
    direct_ring_screen = getattr(args, 'direct_ring_screen', False)
    require(sum((bool(complete_case), bool(getattr(args, 'note_owned_proof', False)),
                 bool(getattr(args, 'note_workflow_cpu', False)),
                 getattr(args, 'owned_runtime_test', None) is not None,
                 bool(direct_ring_screen), bool(metadata_qualification), bool(identity_qualification), bool(native_metadata_profile),
                 bool(getattr(args, 'direct_ring_aggregate', False)),
                 bool(getattr(args, 'owned_source_shape_test', False)),
                 bool(getattr(args, 'active_hashx_preflight', False)),
                 bool(getattr(args, 'direct_ring_source_plan', False)),
                 getattr(args, 'owned_request_source_test', None) is not None,
                 getattr(args, 'direct_ring_recursion_test', None) is not None,
                 getattr(args, 'owned_native_hashx_test', None) is not None,
                 getattr(args, 'owned_hashx_leaf_test', None) is not None,
                 getattr(args, 'owned_hashx_sequence_test', None) is not None,
                 getattr(args, 'owned_hashx_root_public_test', None) is not None,
                 getattr(args, 'owned_hashx_root_transport_test', None) is not None,
                 getattr(args, 'owned_hashx_root_opening_test', None) is not None,
                 getattr(args, 'owned_hashx_interior_opening_test', None) is not None,
                 getattr(args, 'owned_hashx_sequence_refusal_test', None) is not None,
                 getattr(args, 'direct_ring_identity_test', None) is not None)) <= 1,
            'isolated qualification modes are exclusive')
    require(getattr(args, 'direct_ring_recursion_census_label', None) is None
            or getattr(args, 'direct_ring_recursion_test', None) in ('child', 'outer'),
            'a prior recursive caller census is only valid for a recursive GPU component')
    require((args.profile == 'source-preflight') == (bool(getattr(args, 'active_hashx_preflight', False))
            or bool(getattr(args, 'direct_ring_source_plan', False))),
            'source-preflight profile requires an exact isolated source test')
    public_hash_kernel = getattr(args, 'public_hash_kernel', 'baseline')
    require(public_hash_kernel in ('baseline', 'sbox-pair-v1'), 'invalid public hash kernel')
    if public_hash_kernel != 'baseline':
        require(args.profile not in CPU_PROFILES,
                'public hash candidate requires a GPU execution profile')
        require(args.build_label and Path(argv[0]).name != 'cargo',
                'public hash candidate requires a recorded executable build')
        require(not args.expect_result or args.profile == 'full',
                'faithful public hash candidate requires the full GPU profile')
        require(args.expect_tests or direct_result or args.expect_result or complete_case,
                'public hash candidate requires execution evidence acceptance')
    require(sum((args.expect_tests, args.expect_result, direct_result, complete_case)) <= 1,
            'choose one acceptance output')
    require(args.profile != 'direct-full' or direct_result or args.expect_tests,
            'direct-full requires direct research result or correctness tests')
    require(not direct_result or (args.profile in ('direct-full', 'full') and args.build_label),
            'direct research result requires a full GPU profile and --build-label')
    require(not (args.expect_result and args.profile == 'direct-full'),
            'direct-full cannot qualify a faithful RingCT workflow')
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
    require(args.profile not in RESEARCH_CPU_PROFILES or not args.expect_result,
            'research compiler profiles are CPU-only and cannot qualify a GPU workflow result')
    require(not args.record_artifact or (args.profile == 'build' and Path(argv[0]).name == 'cargo'
            and (argv[1:2] == ['build'] or (argv[1:2] == ['test'] and '--no-run' in argv))),
            '--record-artifact requires a Cargo build or test --no-run build profile')
    if args.expect_result:
        experiment_selection({'command': argv})
    direct_output = None
    if direct_result:
        require(argv[1:3] == ['ring-direct', '--prove'] and argv.count('--output-dir') == 1,
                'direct research result requires one complete ring-direct --prove command')
        index = argv.index('--output-dir')
        require(index + 1 < len(argv), 'missing direct research output directory')
        selected = Path(argv[index + 1])
        expected = (STATE / 'artifacts' / args.label).resolve()
        require(selected.is_absolute() and selected.resolve() == expected,
                'direct output must be the fresh run-specific artifacts directory')
        require(not expected.exists(), 'direct research output already exists')
        direct_output = str(expected)
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
        'LATTICA_PROVING_POLICY': 'cpu-required' if args.profile in CPU_PROFILES else 'gpu-required',
    }
    device_uuid = getattr(args, 'device_uuid', None)
    if metadata_qualification:
        environment['LATTICA_METADATA_CPU_QUALIFICATION'] = '1'
    if device_uuid is not None:
        require(args.profile not in CPU_PROFILES, 'physical GPU pin requires a GPU profile')
        require(type(device_uuid) is str and re.fullmatch(
            r'GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', device_uuid),
            'invalid physical GPU UUID')
        # The consuming selector must verify this pin against the selected
        # OpenCL device; setting it alone is not identity qualification.
        environment['LATTICA_GPU_DEVICE_UUID'] = device_uuid
    if args.profile not in CPU_PROFILES:
        environment['LATTICA_V2_GPU_PUBLIC_HASH'] = public_hash_kernel
        for switch in GPU_SWITCHES:
            prefix = 'LATTICA_V2_' if switch == 'QUOTIENT_FUSION' else 'LATTICA_V2_GPU_'
            environment[prefix + switch] = '1'
        environment.update(LATTICA_V2_GPU_DEVICE='0',
                           LATTICA_V2_GPU_MANAGED_BYTES=str(8 * GIB),
                           LATTICA_V2_GPU_CONTEXT_BYTES=str(4 * GIB),
                           LATTICA_V2_HOST_OUTPUT_BYTES=str((32 if args.profile in ('full', 'direct-full') else 8) * GIB))
    tree_storage = getattr(args, 'retained_tree_storage', 'device')
    require(tree_storage in ('device', 'host'), 'invalid retained tree storage')
    if args.profile not in CPU_PROFILES or tree_storage == 'host':
        environment['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = tree_storage
    if tree_storage == 'host':
        environment['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'] = str(8 * GIB)
    if args.profile not in CPU_PROFILES and (direct_result or args.profile == 'direct-full' or tree_storage == 'host'):
        environment['LATTICA_V2_GPU_LDE_WORKSPACE_BYTES'] = '0'
    if args.expect_tests and args.profile not in CPU_PROFILES:
        environment['LATTICA_NATIVE_SPEND_QUALIFICATION'] = '1'
    note_environment = None
    if getattr(args, 'note_owned_proof', False):
        environment, note_environment = note_owned_environment(
            args, argv, tree_storage, public_hash_kernel)
    runtime_environment = None
    if getattr(args, 'owned_runtime_test', None) is not None:
        environment, runtime_environment = owned_runtime_environment(
            args, argv, tree_storage, public_hash_kernel)
    cpu_note_environment = None
    if getattr(args, 'note_workflow_cpu', False):
        environment, cpu_note_environment = note_cpu_environment(
            args, argv, tree_storage, public_hash_kernel)
    ring_screen_environment = None
    if direct_ring_screen:
        environment, ring_screen_environment = direct_ring_screen_environment(
            args, argv, tree_storage, public_hash_kernel, environment)
    aggregate_environment = None
    if getattr(args, 'direct_ring_aggregate', False):
        environment, aggregate_environment = first_leaf_module('direct_ring_aggregate_guard').environment(
            args, argv, tree_storage, public_hash_kernel, environment, STATE)
    identity_environment = None
    if getattr(args, 'direct_ring_identity_test', None) is not None:
        environment, identity_environment = direct_ring_identity_environment(
            args, argv, tree_storage, public_hash_kernel, environment)
    recursion_environment = None
    if getattr(args, 'direct_ring_recursion_test', None) is not None:
        environment, recursion_environment = direct_ring_recursion_environment(
            args, argv, tree_storage, public_hash_kernel, environment)
    source_environment = None
    if getattr(args, 'owned_source_shape_test', False):
        environment, source_environment = source_shape_environment(
            args, argv, tree_storage, public_hash_kernel, environment)
    hashx_environment = None
    if getattr(args, 'active_hashx_preflight', False):
        environment, hashx_environment = active_hashx_preflight_environment(
            args, argv, tree_storage, public_hash_kernel)
    direct_source_environment = None
    if getattr(args, 'direct_ring_source_plan', False):
        environment, direct_source_environment = first_leaf_module('direct_ring_source_plan_guard').environment(
            args, argv, tree_storage, public_hash_kernel)
    request_environment = None
    if getattr(args, 'owned_request_source_test', None) is not None:
        environment, request_environment = request_source_environment(
            args, argv, tree_storage, public_hash_kernel, environment)
    native_hashx_environment_receipt = None
    if getattr(args, 'owned_native_hashx_test', None) is not None:
        environment, native_hashx_environment_receipt = native_hashx_environment(
            args, argv, tree_storage, public_hash_kernel)
    first_leaf_environment_receipt = None
    if getattr(args, 'owned_hashx_leaf_test', None) is not None:
        environment, first_leaf_environment_receipt = first_leaf_environment(
            args, argv, tree_storage, public_hash_kernel, environment)
    sequence_preissue_receipt = None
    if getattr(args, 'owned_hashx_sequence_test', None) is not None:
        environment, sequence_preissue_receipt = sequence_preissue_environment(
            args, tree_storage, public_hash_kernel)
    root_public_gpu_receipt = None
    if getattr(args, 'owned_hashx_root_public_test', None) is not None:
        environment, root_public_gpu_receipt = root_public_gpu_environment(
            args, tree_storage, public_hash_kernel)
    root_transport_gpu_receipt = None
    if getattr(args, 'owned_hashx_root_transport_test', None) is not None:
        environment, root_transport_gpu_receipt = root_transport_gpu_environment(
            args, tree_storage, public_hash_kernel)
    root_opening_gpu_receipt = None
    if getattr(args, 'owned_hashx_root_opening_test', None) is not None:
        environment, root_opening_gpu_receipt = root_opening_gpu_environment(
            args, tree_storage, public_hash_kernel)
    interior_opening_gpu_receipt = None
    if getattr(args, 'owned_hashx_interior_opening_test', None) is not None:
        environment, interior_opening_gpu_receipt = interior_opening_gpu_environment(
            args, tree_storage, public_hash_kernel)
    sequence_refusal_receipt = None
    if getattr(args, 'owned_hashx_sequence_refusal_test', None) is not None:
        environment, sequence_refusal_receipt = sequence_refusal_environment(
            args, tree_storage, public_hash_kernel)
    full_case_environment = None
    if complete_case:
        full_case_environment = first_leaf_module('full_workflow_case_guard').configure(
            args, argv, environment, ROOT, STATE)
    return {'schema': 'pq-opencl-optimization-correctness-job-v2', 'label': args.label,
            'profile': args.profile, 'host_memory_profile': host_profile,
            'command': argv, 'environment': environment,
            'note_startup_environment': note_environment,
            'note_cpu_environment': cpu_note_environment,
            'owned_runtime_environment': runtime_environment,
            'direct_ring_screen_environment': ring_screen_environment,
            'direct_ring_aggregate_environment': aggregate_environment,
            'direct_ring_identity_environment': identity_environment,
            'direct_ring_recursion_environment': recursion_environment,
            'owned_source_shape_environment': source_environment,
            'active_hashx_preflight_environment': hashx_environment,
            'direct_ring_source_plan_environment': direct_source_environment,
            'owned_request_source_environment': request_environment,
            'owned_native_hashx_environment': native_hashx_environment_receipt,
            'owned_hashx_leaf_environment': first_leaf_environment_receipt,
            'owned_hashx_sequence_environment': sequence_preissue_receipt,
            'owned_hashx_root_public_environment': root_public_gpu_receipt,
            'owned_hashx_root_transport_environment': root_transport_gpu_receipt,
            'owned_hashx_root_opening_environment': root_opening_gpu_receipt,
            'owned_hashx_interior_opening_environment': interior_opening_gpu_receipt,
            'owned_hashx_sequence_refusal_environment': sequence_refusal_receipt,
            'public_hash_kernel': public_hash_kernel,
            'memory_max_bytes': maximum * GIB, 'memory_high_bytes': high * GIB,
            'fresh_memavailable_required_bytes': admission * GIB,
            'cpu_quota': '1600%' if identity_cpus is not None else str(threads * 100) + '%',
            'identity_physical_cpus': identity_cpus, 'identity_cpu_qualification': identity_qualification,
            'metadata_cpu_qualification': metadata_qualification, 'native_metadata_profile': native_metadata_profile,
            'runtime_seconds': args.seconds,
            'comparison_baseline': False, 'performance_qualified': False,
            'benchmark': benchmark, 'correctness_label': correctness_label,
            'expect_tests': args.expect_tests, 'expect_result': args.expect_result,
            'expect_direct_result': direct_result,
            'full_workflow_case_environment': full_case_environment, 'direct_output_directory': direct_output,
            'build_label': args.build_label, 'record_artifacts': args.record_artifact,
            'launch': False, 'status': 'planned'}


def require_cargo_test_artifacts(build, content, requested):
    argv = build.get('command', [])
    if not (argv and Path(argv[0]).name == 'cargo' and argv[1:2] == ['test']
            and '--no-run' in argv):
        return None
    # Cargo emits these lines for fresh and cached test executables. A path
    # copied from another worktree can still exist without being built here.
    # Bind the requested artifact to this build's output, not its existence.
    emitted = set()
    for value in re.findall(r'^[ \t]*Executable [^\r\n]+ \(([^\r\n]+)\)[ \t]*$',
                            content, re.M):
        path = Path(value)
        emitted.add(str((path if path.is_absolute() else ROOT / path).resolve()))
    require(emitted, 'Cargo test build emitted no executable inventory')
    require(all(str(Path(path).resolve()) in emitted for path in requested),
            'requested test artifact was not emitted by this Cargo build')
    return sorted(emitted)


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
        build_log = runs / (plan['build_label'] + '.log')
        require(record.get('raw_log') == str(build_log) and build_log.is_file()
                and sha(build_log) == record.get('raw_log_sha256'),
                'executable build log does not match its record')
        require_cargo_test_artifacts(record, build_log.read_text(errors='replace'), [executable])
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
        require(context.get('registration_telemetry', {}).get('enabled')
                is (actual['registration_telemetry'] == 'bounded'),
                'context registration telemetry differs from selection')
        require(context.get('prepared_reuse_mode') == actual['prepared_reuse'],
                'context prepared reuse differs from selection')
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
    require(record.get('public_hash_kernel') == plan['public_hash_kernel'],
            'prior correctness public hash selection differs')
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
    public_hash = validate_faithful_public_hash(result, record)
    from public_hash_evidence import require_requested
    cached_public_hash = require_requested(record.get('public_hash_acceptance'),
        record['public_hash_kernel'], record['environment'].get('LATTICA_V2_GPU_PUBLIC_HASH'))
    require(public_hash == cached_public_hash,
            'prior public hash acceptance differs')
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
            'device': result['context'].get('device'), 'receipt_acceptance': receipts,
            'public_hash_acceptance': public_hash}


def collect_gpu_receipts(content, *, native_entry_names=None):
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
    if native_entry_names is not None:
        native_entries = set(native_entry_names)
    by_entry = {}
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
        totals = by_entry.setdefault(entry, {'reports': 0, 'completed_calls': 0, 'device_calls': 0, 'elapsed_ns': 0, 'device_ns': 0})
        totals['reports'] += 1
        totals['elapsed_ns'] += report.get('elapsed_ns', 0)
        totals['device_ns'] += sum(o.get('device_ns', 0) for o in observations)
        totals['completed_calls'] += sum(o['completed_calls'] for o in observations)
        totals['device_calls'] += sum(o['device_calls'] for o in observations)
    return {'counts': counts, 'native_reports': native_reports, 'private_spend_reports': private_spend_reports, 'private_spend_completed': private_spend_completed, 'private_spend_devices': private_spend_devices, 'preparation_reports': preparation_reports, 'preparation_completed': preparation_completed, 'preparation_devices': preparation_devices, 'by_entry': by_entry}


def validate_receipts(content, result):
    cpu_identity = []
    if result.get('context', {}).get('identity_hashing') == 'cpu':
        from cpu_identity_receipts import stage
        filtered = []
        for line in content.splitlines():
            if line.startswith('proving_stage_report '):
                report = json.loads(line.removeprefix('proving_stage_report '))
                if report.get('entry_point') == 'block_v2_cpu_identity':
                    stage(report, 'block_v2_cpu_identity', 'cpu', 'cpu_required')
                    cpu_identity.append(report)
                    continue
            filtered.append(line)
        require(len(cpu_identity) == result['context'].get('registrations'),
                'CPU identity coverage does not match registrations')
        content = '\n'.join(filtered)
    receipts = collect_gpu_receipts(content)
    if cpu_identity:
        receipts['cpu_identity'] = dict(reports=len(cpu_identity), elapsed_ns=sum(r['elapsed_ns'] for r in cpu_identity))
    counts = receipts['counts']
    native_reports = receipts['native_reports']
    private_spend_reports = receipts['private_spend_reports']
    private_spend_completed = receipts['private_spend_completed']
    private_spend_devices = receipts['private_spend_devices']
    preparation_reports = receipts['preparation_reports']
    preparation_completed = receipts['preparation_completed']
    preparation_devices = receipts['preparation_devices']
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


def validate_faithful_public_hash(result, plan):
    from public_hash_evidence import require_requested
    requested = plan['public_hash_kernel']
    environment = plan['environment'].get('LATTICA_V2_GPU_PUBLIC_HASH')
    context = result.get('context')
    require(isinstance(context, dict), 'missing faithful context execution evidence')
    accepted = require_requested(context.get('public_hash'), requested, environment)
    cases = result.get('cases')
    require(isinstance(cases, list) and cases, 'missing faithful case execution evidence')
    for case in cases:
        require(isinstance(case, dict), 'invalid faithful case execution evidence')
        observed = require_requested(case.get('public_hash'), requested, environment)
        require(observed == accepted, 'faithful context and case public hash evidence disagree')
    return accepted


def validate_active_hashx_preflight(content):
    # libtest may put its test-name prefix on the first stderr marker line.
    content = content.replace('test ' + ACTIVE_HASHX_PREFLIGHT_TEST + ' ... ', '', 1)
    require(not any(marker in content for marker in (
        'PUBLIC_HASH_EXECUTION', 'proving_stage_report', 'OPENCL_OPT_RESULT',
        'DIRECT_SPEND_RESULT', 'DIRECT_RING_RESULT', 'NATIVE_EXECUTION_RECEIPT')),
        'source-only preflight emitted proving or workflow evidence')
    header = (r'^active_hashx_source_preflight schema=1 scope=source_phase_only '
              r'native_count=10 paired_group_count=5 input_bytes=16416 output_bytes=137 '
              r'operation_host_bytes=([1-9][0-9]*) worker_host_bytes=34359738368 '
              r'managed_device_bytes=8589934592 context_device_bytes=4294967296 '
              r'native_host_ceiling_bytes=25769803776 max_rows=1048576 '
              r'cryptographic_proof_started=false$')
    headers = list(re.finditer(header, content, re.M))
    require(len(headers) == 1, 'missing, changed or duplicate HashX source-only header')
    operation_host = int(headers[0].group(1))
    require(operation_host <= 24 * GIB, 'HashX source host budget exceeds native allowance')
    startups = list(re.finditer(r'^active_hashx_source_preflight_startup (.+)$', content, re.M))
    require(len(startups) == 1, 'missing or duplicate HashX source startup')
    baseline = re.findall(r'(?<![a-z_])managed_device_bytes: ([1-9][0-9]*)', startups[0].group(1))
    require(len(baseline) == 1 and int(baseline[0]) <= 8 * GIB,
            'missing or invalid source startup device baseline')
    shapes = list(re.finditer(r'^active_hashx_source_preflight_shape index=(\d+) first_permutation=(\d+) permutations=(\d+) (.*)$', content, re.M))
    require(len(shapes) == 10, 'HashX preflight must screen exactly ten shapes')
    firsts = (0, 16, 32, 48, 64, 80, 96, 112, 120, 121)
    permutations = (16,) * 7 + (8, 1, 1)
    numeric = ('rows main_width maximum_quotient_chunks maximum_matrices '
               'preopening_host_bytes opening_workspace_host_bytes retained_metadata_host_bytes '
               'opened_value_descriptors_host_bytes required_pcs_host_bytes operation_host_budget_bytes '
               'managed_phase_ceiling_bytes maintained_phase_peak_bytes fresh_runtime_baseline_bytes '
               'source_allocation_ceiling_bytes opening_device_peak_bytes fri_device_peak_bytes '
               'query_device_peak_bytes minimum_opening_device_bytes largest_opening_allocation_bytes '
               'selected_tree_host_quota_bytes required_tree_host_bytes').split()
    fields = set(numeric) | {'maintained_device_plan_complete', 'retained_tree_storage_mode',
                             'complete_native_dispatch_admission'}
    admitted = 0
    for index, shape in enumerate(shapes):
        seen, first, count, details = shape.groups()
        require((seen, first, count) == (str(index), str(firsts[index]), str(permutations[index])),
                'HashX source order or geometry changed')
        rows, width = 4096 * permutations[index], 517 if permutations[index] == 1 else 518
        accepted = re.fullmatch(r'admitted=true footprint=NativeShakePcsFootprint \{ (.+) \}', details)
        if accepted is not None:
            pairs = [part.split(': ', 1) for part in accepted.group(1).split(', ')]
            require(all(len(pair) == 2 for pair in pairs), 'malformed HashX footprint')
            data = dict(pairs)
            require(len(pairs) == len(fields) and set(data) == fields,
                    'missing, duplicate or unexpected HashX footprint field')
            require(all(re.fullmatch(r'0|[1-9][0-9]*', data[key]) for key in numeric),
                    'noncanonical HashX footprint number')
            data.update({key: int(data[key]) for key in numeric})
            fixed = dict(rows=rows, main_width=width, maximum_quotient_chunks=32,
                         maximum_matrices=34, operation_host_budget_bytes=operation_host,
                         maintained_device_plan_complete='true',
                         managed_phase_ceiling_bytes=8 * GIB,
                         fresh_runtime_baseline_bytes=int(baseline[0]),
                         retained_tree_storage_mode='HostBacking', selected_tree_host_quota_bytes=8 * GIB,
                         complete_native_dispatch_admission='false')
            require(all(data[key] == value for key, value in fixed.items()),
                    'HashX footprint changed geometry, phase ownership or fixed limits')
            require(0 < data['required_pcs_host_bytes'] <= operation_host
                    and 0 < data['maintained_phase_peak_bytes'] <= 8 * GIB
                    and 0 < data['required_tree_host_bytes'] <= 8 * GIB
                    and 0 < data['source_allocation_ceiling_bytes'] <= 8 * GIB
                    and data['largest_opening_allocation_bytes'] <= data['source_allocation_ceiling_bytes'],
                    'HashX footprint exceeds its phase allowance')
            require(all(0 <= data[key] <= data['required_pcs_host_bytes'] for key in (
                'preopening_host_bytes', 'opening_workspace_host_bytes',
                'retained_metadata_host_bytes', 'opened_value_descriptors_host_bytes')),
                'HashX footprint host components exceed total')
            require(all(0 <= data[key] <= data['maintained_phase_peak_bytes'] for key in (
                'fresh_runtime_baseline_bytes', 'opening_device_peak_bytes', 'fri_device_peak_bytes',
                'query_device_peak_bytes', 'minimum_opening_device_bytes')),
                'HashX footprint device components exceed phase peak')
            admitted += 1
        else:
            require(re.fullmatch(r'rows=' + str(rows) + r' width=' + str(width)
                                 + r' admitted=false refusal=.+', details) is not None,
                    'invalid HashX shape admission marker')
    terminals = list(re.finditer(r'^active_hashx_source_preflight_terminal screened=10 admitted=(\d+) refused=(\d+) phase_feasibility=(true|false) complete_request_admission=false cryptographic_proof_started=false terminal=(.+)$', content, re.M))
    require(len(terminals) == 1, 'missing or duplicate HashX terminal marker')
    accepted, refused, feasible, terminal = terminals[0].groups()
    require((accepted, refused, feasible) == (str(admitted), str(10 - admitted),
                                            'true' if admitted == 10 else 'false'),
            'HashX preflight summary contradicts its shapes')
    require(terminal.startswith('Snapshot { allowance: WorkerAllowance { host: 34359738368, device: 8589934592 }, '),
            'HashX terminal worker allowance changed')
    currents = re.findall(r'current: Bytes \{ host: (\d+), device: (\d+) \}', terminal)
    require(len(currents) == 9 and all(pair == ('0', '0') for pair in currents)
            and terminal.count('CategoryCounters {') == 8,
            'HashX source claims were not completely released')
    footers = list(re.finditer(r'^test result: ok\. 1 passed; 0 failed;.*$', content, re.M))
    require(len(footers) == 1, 'HashX preflight requires one passing test footer')
    positions = [headers[0].start(), startups[0].start(),
                 *(shape.start() for shape in shapes), terminals[0].start(), footers[0].start()]
    require(positions == sorted(set(positions)), 'HashX preflight markers are out of order')
    return dict(scope='source_phase_only', screened=10, admitted=admitted,
                refused=10 - admitted, phase_feasibility=admitted == 10,
                complete_request_admission=False, cryptographic_proof_started=False,
                performance_qualified=False)


def validate_output(log, plan):
    content = log.read_text(errors='replace')
    if plan['expect_tests']:
        require(re.search(r'test result: ok\. [1-9][0-9]* passed; 0 failed;', content),
                'no nonempty passing correctness tests')
        evidence = [json.loads(line.removeprefix('PUBLIC_HASH_EXECUTION '))
                    for line in content.splitlines() if line.startswith('PUBLIC_HASH_EXECUTION ')]
        if plan.get('public_hash_kernel', 'baseline') != 'baseline' or evidence:
            from public_hash_evidence import require_requested
            require(evidence, 'missing public hash execution evidence')
            accepted = [require_requested(record, plan['public_hash_kernel'],
                        plan['environment'].get('LATTICA_V2_GPU_PUBLIC_HASH')) for record in evidence]
            require(all(record == accepted[0] for record in accepted),
                    'inconsistent public hash test execution evidence')
            plan['public_hash_acceptance'] = accepted[0]
    if plan.get('identity_cpu_qualification'):
        from cpu_identity_qualification import validate
        plan['identity_cpu_qualification_acceptance'] = validate(content)
    if plan.get('native_metadata_profile'):
        from native_metadata_profile import validate
        plan['native_metadata_profile_acceptance'] = validate(content)
    if plan.get('metadata_cpu_qualification'):
        from metadata_cpu_qualification import validate
        plan['metadata_cpu_qualification_acceptance'] = validate(content)
    if plan.get('full_workflow_case_environment') is not None:
        plan['full_workflow_case_acceptance'] = first_leaf_module('full_workflow_case_guard').validate_log(
            content, plan, collect_gpu_receipts)
    if plan.get('direct_ring_aggregate_environment') is not None:
        plan['direct_ring_aggregate_acceptance'] = first_leaf_module(
            'direct_ring_aggregate_guard').validate(content, plan)
    if plan.get('direct_ring_recursion_environment') is not None:
        plan['direct_ring_recursion_acceptance'] = validate_direct_ring_recursion(content, plan)
    if plan.get('owned_native_hashx_environment') is not None:
        plan['owned_native_hashx_qualification'] = native_hashx_guard().validate_log(content, plan)
    if plan.get('owned_hashx_leaf_environment') is not None:
        plan['owned_hashx_leaf_qualification'] = first_leaf_module('hashx_first_leaf_guard').validate_log(
            content, plan, first_leaf_module('native_sequence_report').receipt)
    if plan.get('owned_hashx_sequence_environment') is not None:
        plan['owned_hashx_sequence_qualification'] = first_leaf_module('hashx_sequence_preissue_guard').validate_log(
            content, plan)
    if plan.get('owned_hashx_root_public_environment') is not None:
        plan['owned_hashx_root_public_qualification'] = first_leaf_module('hashx_root_public_gpu_guard').validate_log(
            content, plan)
    if plan.get('owned_hashx_root_transport_environment') is not None:
        plan['owned_hashx_root_transport_qualification'] = first_leaf_module('hashx_root_transport_gpu_guard').validate_log(
            content, plan)
    if plan.get('owned_hashx_root_opening_environment') is not None:
        plan['owned_hashx_root_opening_qualification'] = first_leaf_module('hashx_root_opening_gpu_guard').validate_log(
            content, plan)
    if plan.get('owned_hashx_interior_opening_environment') is not None:
        plan['owned_hashx_interior_opening_qualification'] = first_leaf_module('hashx_interior_opening_gpu_guard').validate_log(
            content, plan)

    if plan.get('owned_hashx_sequence_refusal_environment') is not None:
        plan['owned_hashx_sequence_refusal_qualification'] = first_leaf_module('hashx_sequence_refusal_guard').validate_log(
            content, plan)
    if (plan.get('owned_source_shape_environment') or {}).get('selector') == ORIGINAL_HASHX_SEQUENCE_SOURCE_TEST:
        plan['owned_hashx_sequence_capacity_qualification'] = first_leaf_module('hashx_sequence_capacity_guard').validate_log(
            content, plan.get('observation_before_validation_ns'))
    if (plan.get('owned_source_shape_environment') or {}).get('selector') == ORIGINAL_HASHX_ROOT_PUBLIC_SOURCE_TEST:
        plan['owned_hashx_root_public_capacity_qualification'] = first_leaf_module('hashx_root_public_capacity_guard').validate_log(
            content, plan.get('observation_before_validation_ns'))
    if (plan.get('owned_source_shape_environment') or {}).get('selector') == ORIGINAL_HASHX_ROOT_TRANSPORT_SOURCE_TEST:
        plan['owned_hashx_root_transport_capacity_qualification'] = first_leaf_module('hashx_root_transport_capacity_guard').validate_log(
            content, plan)
    if (plan.get('owned_source_shape_environment') or {}).get('selector') == ORIGINAL_HASHX_ROOT_OPENING_SOURCE_TEST:
        plan['owned_hashx_root_opening_capacity_qualification'] = first_leaf_module('hashx_root_opening_capacity_guard').validate_log(
            content, plan)
    if (plan.get('owned_source_shape_environment') or {}).get('selector') == ORIGINAL_HASHX_INTERIOR_OPENING_SOURCE_TEST:
        plan['owned_hashx_interior_opening_capacity_qualification'] = first_leaf_module('hashx_interior_opening_capacity_guard').validate_log(
            content, plan)
    if plan.get('direct_ring_source_plan_environment') is not None:
        plan['direct_ring_source_plan_audit'] = first_leaf_module('direct_ring_source_plan_guard').validate_log(content)
    if plan.get('active_hashx_preflight_environment') is not None:
        require(re.search(r'test result: ok\. 1 passed; 0 failed;', content),
                'HashX preflight must execute exactly one test')
        plan['active_hashx_source_preflight'] = validate_active_hashx_preflight(content)
    if plan.get('owned_request_source_environment') is not None:
        require(len(re.findall(r'^test result: ok\. 1 passed; 0 failed;.*$', content, re.M)) == 1,
                'request source qualifier must execute exactly one passing test')
        require(not any(marker in content for marker in (
            'PUBLIC_HASH_EXECUTION', 'proving_stage_report', 'OPENCL_OPT_RESULT',
            'DIRECT_SPEND_RESULT', 'DIRECT_RING_RESULT', 'NATIVE_EXECUTION_RECEIPT')),
            'request source qualifier emitted proving or workflow evidence')
    if plan['expect_result']:
        results = [json.loads(line.removeprefix('OPENCL_OPT_RESULT '))
                   for line in content.splitlines() if line.startswith('OPENCL_OPT_RESULT ')]
        require(len(results) == 1, 'expected exactly one correctness result')
        validate_result(results[0])
        plan['public_hash_acceptance'] = validate_faithful_public_hash(results[0], plan)
        validate_experiments(results[0], plan)
        plan['receipt_acceptance'] = validate_receipts(content, results[0])
        plan['correctness_result'] = results[0]
        plan['measurement_acceptance'] = validate_measurement(results[0], plan)
    if plan.get('expect_direct_result', False):
        from opencl_direct_spend_audit import validate_directory
        result = validate_directory(Path(plan['direct_output_directory']))
        from public_hash_evidence import require_requested
        plan['public_hash_acceptance'] = require_requested(result['public_hash'],
            plan['public_hash_kernel'], plan['environment'].get('LATTICA_V2_GPU_PUBLIC_HASH'))
        selected = plan['environment']['LATTICA_V2_GPU_RETAINED_TREE_STORAGE']
        require(result['tree_storage_mode'] == ('host_backing' if selected == 'host' else 'device'),
                'direct research storage mode differs from the requested experiment')
        reports = []
        for line in content.splitlines():
            if line.startswith('{'):
                try:
                    value = json.loads(line)
                except ValueError:
                    continue
                if value.get('schema') == 'lattica-research-direct-ring-complete-gpu-workflow-v1':
                    reports.append(value)
        require(reports == [result['workflow']], 'direct workflow stdout and artifact report differ')
        plan['direct_research_acceptance'] = result


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
        if plan.get('expect_direct_result', False):
            Path(plan['direct_output_directory']).parent.mkdir(parents=True, exist_ok=True)
        if plan.get('full_workflow_case_environment') is not None:
            first_leaf_module('full_workflow_case_guard').prepare_directory(plan)
        identity_screen = plan.get('direct_ring_identity_environment')
        if identity_screen is not None:
            Path(identity_screen['output_directory']).parent.mkdir(parents=True, exist_ok=True)
        aggregate = plan.get('direct_ring_aggregate_environment')
        if aggregate is not None:
            destination = Path(aggregate['output_directory'])
            require(not destination.exists() and not destination.is_symlink(),
                    'complete direct aggregate destination is no longer fresh')
            destination.parent.mkdir(parents=True, exist_ok=True)
        ring_screen = plan.get('direct_ring_screen_environment')
        if ring_screen is not None:
            Path(ring_screen['output_directory']).parent.mkdir(parents=True, exist_ok=True)
        runs = STATE / 'runs'
        runs.mkdir(exist_ok=True)
        record, log = runs / (args.label + '.json'), runs / (args.label + '.log')
        require(not record.exists() and not log.exists(), 'run label already used')
        unit = 'lattica-opencl-opt-' + args.label + '.service'
        require(systemd_state(unit).get('LoadState') == 'not-found', 'service name already exists')
        before = source_manifest()
        executable = executable_provenance(plan, before, runs)
        require_direct_ring_recursion_build(plan, executable)
        first_leaf_module('direct_ring_aggregate_guard').require_build(plan, executable, ROOT)
        recursion = plan.get('direct_ring_recursion_environment')
        if recursion is not None and recursion['mode'] != 'caller-census':
            plan['prior_direct_ring_caller_census'] = prior_direct_ring_caller_census(
                plan, before, executable, runs)
        if (plan.get('owned_source_shape_environment') or {}).get('selector') == ORIGINAL_HASHX_ROOT_TRANSPORT_SOURCE_TEST:
            plan['owned_hashx_root_transport_capacity_binding'] = first_leaf_module('hashx_root_transport_capacity_guard').bind_execution(
                plan, before, executable, str(ROOT))
        if (plan.get('owned_source_shape_environment') or {}).get('selector') == ORIGINAL_HASHX_ROOT_OPENING_SOURCE_TEST:
            plan['owned_hashx_root_opening_capacity_binding'] = first_leaf_module('hashx_root_opening_capacity_guard').bind_execution(
                plan, before, executable, str(ROOT))
        if (plan.get('owned_source_shape_environment') or {}).get('selector') == ORIGINAL_HASHX_INTERIOR_OPENING_SOURCE_TEST:
            plan['owned_hashx_interior_opening_capacity_binding'] = first_leaf_module('hashx_interior_opening_capacity_guard').bind_execution(
                plan, before, executable, str(ROOT))
        if plan.get('owned_native_hashx_environment') is not None:
            plan['owned_native_hashx_binding'] = native_hashx_guard().bind_execution(
                plan, before, executable, str(ROOT))
        if plan.get('owned_hashx_leaf_environment') is not None:
            plan['owned_hashx_leaf_binding'] = first_leaf_module('hashx_first_leaf_guard').bind_execution(
                plan, before, executable, str(ROOT))
        if plan.get('owned_hashx_sequence_environment') is not None:
            plan['owned_hashx_sequence_binding'] = first_leaf_module('hashx_sequence_preissue_guard').bind_execution(
                plan, before, executable, str(ROOT))
        if plan.get('owned_hashx_root_public_environment') is not None:
            plan['owned_hashx_root_public_binding'] = first_leaf_module('hashx_root_public_gpu_guard').bind_execution(
                plan, before, executable, str(ROOT))
        if plan.get('owned_hashx_root_transport_environment') is not None:
            plan['owned_hashx_root_transport_binding'] = first_leaf_module('hashx_root_transport_gpu_guard').bind_execution(
                plan, before, executable, str(ROOT))
        if plan.get('owned_hashx_root_opening_environment') is not None:
            plan['owned_hashx_root_opening_binding'] = first_leaf_module('hashx_root_opening_gpu_guard').bind_execution(
                plan, before, executable, str(ROOT))
        if plan.get('owned_hashx_interior_opening_environment') is not None:
            plan['owned_hashx_interior_opening_binding'] = first_leaf_module('hashx_interior_opening_gpu_guard').bind_execution(
                plan, before, executable, str(ROOT))

        if plan.get('owned_hashx_sequence_refusal_environment') is not None:
            plan['owned_hashx_sequence_refusal_binding'] = first_leaf_module('hashx_sequence_refusal_guard').bind_execution(
                plan, before, executable, str(ROOT))
        if plan.get('benchmark', False):
            plan['prior_correctness'] = prior_correctness(plan, before, executable, runs)
        if plan.get('full_workflow_case_environment') is not None:
            plan['full_workflow_device'] = full_workflow_device_identity(plan['environment'])
        properties = {'Type': 'exec', 'RemainAfterExit': 'yes', 'Restart': 'no',
                      'MemoryMax': str(plan['memory_max_bytes']),
                      'MemoryHigh': str(plan['memory_high_bytes']), 'MemorySwapMax': '0',
                      'CPUQuota': plan['cpu_quota'], 'TasksMax': '256',
                      'RuntimeMaxSec': str(args.seconds), 'TimeoutStopSec': '10',
                      'KillMode': 'control-group', 'WorkingDirectory': (plan.get('full_workflow_case_environment') or {}).get('output_directory', str(ROOT)),
                      'StandardOutput': 'append:' + str(log), 'StandardError': 'inherit'}
        if plan.get('identity_physical_cpus') is not None:
            properties['AllowedCPUs'] = ','.join(map(str, plan['identity_physical_cpus']))
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
        started_ns = time.monotonic_ns()
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
                if plan.get('identity_physical_cpus') is not None and int(state.get('MainPID', '0')) > 0:
                    try:
                        affinity = sorted(os.sched_getaffinity(int(state['MainPID'])))
                    except ProcessLookupError:
                        affinity = None
                    if affinity is not None:
                        require(affinity == plan['identity_physical_cpus'], 'identity physical CPU affinity changed')
                        plan['observed_identity_cpu_affinity'] = affinity
                        cpu_max = (Path('/sys/fs/cgroup') / state['ControlGroup'].lstrip('/') / 'cpu.max').read_text().split()
                        require(len(cpu_max) == 2 and cpu_max[0] != 'max'
                                and int(cpu_max[0]) == 16 * int(cpu_max[1]), 'identity CPU quota changed')
                        plan['observed_identity_cpu_max'] = cpu_max
                require(time.monotonic() - started <= args.seconds + 30, 'observation exceeded runtime limit')
                time.sleep(2)
            require(state.get('Result') == 'success' and state.get('ExecMainCode') == '1'
                    and state.get('ExecMainStatus') == '0', 'command failed: ' + json.dumps(state))
            # Runner-owned monotonic observation brackets launch through terminal
            # success. It is not a caller-supplied timeout or post-cleanup wall.
            plan['observation_before_validation_ns'] = time.monotonic_ns() - started_ns
            if plan.get('identity_physical_cpus') is not None:
                require(plan.get('observed_identity_cpu_affinity') == plan['identity_physical_cpus'],
                        'physical CPU affinity was not observed')
            validate_output(log, plan)
            if plan.get('full_workflow_case_environment') is not None:
                require(full_workflow_device_identity(plan['environment']) == plan['full_workflow_device'],
                        'owned workflow GPU/driver changed during execution')
            if recursion is not None and recursion['mode'] != 'caller-census':
                require(prior_direct_ring_caller_census(plan, before, executable, runs)
                        == plan['prior_direct_ring_caller_census'],
                        'prior caller-census provenance changed during recursive qualification')
            if plan.get('benchmark', False):
                require(prior_correctness(plan, before, executable, runs) == plan['prior_correctness'],
                        'prior correctness provenance changed during benchmark')
            artifacts = {}
            emitted = None
            test_build = (Path(plan['command'][0]).name == 'cargo'
                          and plan['command'][1:2] == ['test'] and '--no-run' in plan['command'])
            if plan['record_artifacts'] or test_build:
                emitted = require_cargo_test_artifacts(
                    plan, log.read_text(errors='replace'), plan['record_artifacts'])
                if emitted is not None:
                    plan['cargo_test_emitted_executables'] = emitted
            for path in sorted(set(plan['record_artifacts']) | set(emitted or [])):
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


def identity_physical_cpus(allowed=None, topology=Path('/sys/devices/system/cpu')):
    """Select one permitted logical CPU per physical core, at most sixteen."""
    allowed = sorted(os.sched_getaffinity(0) if allowed is None else allowed)
    cores = {}
    for cpu in allowed:
        base = topology / f'cpu{cpu}' / 'topology'
        pair = (int((base / 'physical_package_id').read_text()), int((base / 'core_id').read_text()))
        cores.setdefault(pair, cpu)
    result = sorted(cores.values())[:16]
    require(result, 'no allowed physical CPUs for identity hashing')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=PROFILES, required=True)
    parser.add_argument('--host-profile', choices=HOST_PROFILES, default='standard',
                        help='explicit complete-workflow host allowance; no automatic escalation')
    parser.add_argument('--label', required=True)
    parser.add_argument('--seconds', type=int, default=1800)
    parser.add_argument('--expect-tests', action='store_true')
    parser.add_argument('--expect-result', action='store_true')
    parser.add_argument('--expect-direct-result', action='store_true')
    parser.add_argument('--identity-cpu-qualification', action='store_true')
    parser.add_argument('--native-metadata-profile', action='store_true')
    parser.add_argument('--metadata-cpu-qualification', action='store_true')
    parser.add_argument('--full-workflow-case', action='store_true',
                        help='qualify exactly one fresh N3 or N4 complete RingCT case')
    parser.add_argument('--retained-tree-storage', choices=['device', 'host'], default='device')
    parser.add_argument('--public-hash-kernel', choices=['baseline', 'sbox-pair-v1'], default='baseline')
    parser.add_argument('--build-label')
    parser.add_argument('--device-uuid', help='exact physical UUID for selectors that verify the pin')
    parser.add_argument('--note-owned-proof', action='store_true',
                        help='use the fixed environment for the isolated owned-note GPU test')
    parser.add_argument('--note-workflow-cpu', action='store_true',
                        help='use the fixed CPU environment for the exact private-note baseline')
    parser.add_argument('--owned-runtime-test', choices=sorted(OWNED_RUNTIME_TESTS),
                        help='use the fixed environment for one exact owned-runtime test')
    parser.add_argument('--direct-ring-screen', action='store_true',
                        help='exact isolated seven-case direct-ring research qualification')
    parser.add_argument('--direct-ring-aggregate', action='store_true',
                        help='exact complete N3/N4 direct-ring research aggregate workflow')
    parser.add_argument('--direct-ring-identity-test', choices=sorted(DIRECT_RING_IDENTITY_TESTS),
                        help='exact single-case direct-ring identity receipt experiment')
    parser.add_argument('--direct-ring-recursion-test', choices=sorted(DIRECT_RING_RECURSION_TESTS),
                        help='exact CPU caller census or isolated fresh child/outer research component')
    parser.add_argument('--direct-ring-recursion-census-label',
                        help='terminal caller-census record from the identical source/build/executable')
    parser.add_argument('--owned-source-shape-test', action='store_true',
                        help='exact CPU-only source-envelope conformance qualifier')
    parser.add_argument('--direct-ring-source-plan', action='store_true',
                        help='exact allocation-only direct-ring memory-plan boundary test')
    parser.add_argument('--active-hashx-preflight', action='store_true',
                        help='exact HashX source-only planning test; cannot dispatch proving')
    parser.add_argument('--owned-request-source-test', choices=sorted(REQUEST_SOURCE_TESTS),
                        help='exact CPU-only existing-batch or request-refusal source qualifier')
    parser.add_argument('--owned-native-hashx-test', choices=('sequence', 'reordered'),
                        help='exact full-profile original-scratch HashX native qualifier')
    parser.add_argument('--owned-hashx-leaf-test', choices=['capacity', 'gpu'],
                        help='isolated first-leaf quota projection or full-profile component proof')
    parser.add_argument('--owned-hashx-sequence-test', choices=['preissue'],
                        help='exact full-profile original sequence backend preissue; zero proofs')
    parser.add_argument('--owned-hashx-root-public-test', choices=['gpu'],
                        help='isolated original HashX sequence and final-root public recheck')
    parser.add_argument('--owned-hashx-root-transport-test', choices=['gpu'],
                        help='isolated original HashX root transport and decoded-proof recheck')
    parser.add_argument('--owned-hashx-root-opening-test', choices=['gpu'],
                        help='isolated original HashX root opening mutation and restoration check')
    parser.add_argument('--owned-hashx-interior-opening-test', choices=['gpu'],
                        help='isolated original HashX Leaf0 opening check before Parent0 consumption')
    parser.add_argument('--owned-hashx-sequence-refusal-test',
                        choices=['after-preissue', 'before-first-start', 'after-first-producer', 'after-first-acceptance'],
                        help='isolated original HashX ordinary returned-refusal cleanup probes')
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
