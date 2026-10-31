"""Exact allocation-only direct-ring planner probe; never proof qualification."""
import hashlib
import importlib.util
import json
import re
from pathlib import Path

GIB = 1 << 30
SELECTOR = ('ring_circuit::aggregation::diagnostics::tests::'
            'flat_n4_padding_boundary_original_memory_plan_without_dispatch')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def environment(args, argv, tree_storage, public_hash_kernel):
    require(args.profile == 'source-preflight' and args.expect_tests and args.build_label,
            'direct source plan requires a recorded source-preflight test')
    require(not args.expect_result and not getattr(args, 'expect_direct_result', False)
            and not getattr(args, 'benchmark', False), 'source plan cannot qualify proving')
    require(tree_storage == 'host' and public_hash_kernel == 'baseline' and args.device_uuid,
            'source plan requires host trees, baseline hashing and a device pin')
    require(argv and Path(argv[0]).name.startswith('lattica_pq_direct_spend_research-')
            and argv[1:] == [SELECTOR, '--exact', '--ignored', '--test-threads=1', '--nocapture'],
            'source plan requires its exact isolated test')
    path = Path(__file__).with_name('note_startup_environment.py')
    spec = importlib.util.spec_from_file_location('direct_source_fixed_environment', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    selected, base = module.build_environment(0, args.device_uuid)
    selected.update(LATTICA_V2_GPU_RETAINED_TREE_STORAGE='host',
                    LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES=str(8 * GIB))
    encoded = b''.join((name + '=' + selected[name] + '\0').encode('utf-8')
                       for name in sorted(selected))
    return selected, {**base, 'schema': 'direct-ring-source-plan-environment-v1',
                      'selector': SELECTOR, 'entry_count': len(selected),
                      'serialized_bytes': len(encoded),
                      'sha256_sorted_name_equals_value_nul': hashlib.sha256(encoded).hexdigest(),
                      'gpu_dispatch': False, 'performance_qualified': False,
                      'complete_faithful_ringct_workflow': False,
                      'complete_request_admission': False, 'scope': 'source_phase_only'}


def validate_log(content):
    content = content.replace('test ' + SELECTOR + ' ... ', '', 1)
    require(not any(marker in content for marker in (
        'PUBLIC_HASH_EXECUTION', 'proving_stage_report', 'OPENCL_OPT_RESULT',
        'DIRECT_SPEND_RESULT', 'DIRECT_RING_RESULT', 'NATIVE_EXECUTION_RECEIPT',
        'bounded_gpu_initialized', 'bounded_gpu_checkpoint')),
        'source plan emitted runtime or proof execution evidence')
    require(len(re.findall(r'^test result: ok\. 1 passed; 0 failed; 0 ignored;.*$',
                           content, re.M)) == 1, 'source plan must run one passing test')
    cases = [json.loads(line[len('direct_ring_source_plan_case '):])
             for line in content.splitlines() if line.startswith('direct_ring_source_plan_case ')]
    terminals = [json.loads(line[len('direct_ring_source_plan_terminal '):])
                 for line in content.splitlines() if line.startswith('direct_ring_source_plan_terminal ')]
    require(len(cases) == 2 and len(terminals) == 1, 'missing or duplicate source plan evidence')
    for case, height, admitted in zip(cases, (1 << 19, 1 << 20), (True, False)):
        require(case.get('schema') == 'direct-ring-source-plan-case-v1'
                and case.get('program_kind') == 'four_public_empty_padded_shell'
                and case.get('source_upper_bound_claimed') is False
                and case.get('admitted') is admitted, 'wrong source case or order')
        actual = case.get('actual_program', {})
        expected_descriptor = dict(active_rows=1, padded_rows=height, wires=4,
                                   witness_values=0, canonical_manifest_digest=[0] * 32,
                                   registered_program_id=[0] * 4)
        require(actual == expected_descriptor
                and all(type(actual[k]) is int for k in
                        ('active_rows', 'padded_rows', 'wires', 'witness_values'))
                and all(type(word) is int for k in
                        ('canonical_manifest_digest', 'registered_program_id')
                        for word in actual[k]), 'wrong actual shell geometry')
        if admitted:
            footprint = case.get('footprint') or {}
            require(case.get('error') is None and footprint.get('rows') == height
                    and footprint.get('main_columns') == 94
                    and footprint.get('preprocessing_columns') == 200
                    and footprint.get('managed_limit_bytes') == 8 * GIB
                    and footprint.get('context_reserve_bytes') == 4 * GIB
                    and footprint.get('worker_host_limit_bytes') == 32 * GIB,
                    'source plan changed the qualified geometry or allowances')
            peak = footprint.get('device_phase_peak_bytes')
            require(type(peak) is int and 0 < peak <= 8 * GIB
                    and footprint.get('device_phase_bound_complete') is True
                    and footprint.get('host_phase_bound_complete') is True,
                    'source plan lacks complete phase admission')
        else:
            error = case.get('error') or {}
            message = error.get('core_error')
            require(case.get('footprint') is None and error.get('actual_program') == actual
                    and isinstance(message, str) and 0 < len(message.encode('utf-8')) <= 2048
                    and error.get('original_error_complete') is True
                    and type(error.get('original_error_bytes')) is int
                    and error['original_error_bytes'] == len(message.encode('utf-8')),
                    'source refusal lost its exact bounded original error')
    expected = dict(schema='direct-ring-source-plan-terminal-v1', cases=2, admitted=1, refused=1,
                    engine_report_absent_before=True, engine_report_absent_after=True,
                    public_hash_absent_before=True, public_hash_absent_after=True,
                    session_creation_attempts=0, cryptographic_proof_started=False)
    require(terminals[0] == expected and all(type(terminals[0][k]) is type(v)
                                            for k, v in expected.items()),
            'source plan terminal evidence differs')
    return {'schema': 'direct-ring-source-plan-audit-v1', 'cases': cases,
            'terminal': terminals[0], 'gpu_dispatch': False,
            'complete_workflow_qualified': False, 'performance_qualified': False}
