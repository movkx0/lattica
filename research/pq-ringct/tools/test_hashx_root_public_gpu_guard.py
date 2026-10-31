"""Synthetic guard policy fixtures; these tests never qualify real GPU work."""
from copy import deepcopy
import json
from types import SimpleNamespace
import unittest

import hashx_root_public_gpu_guard as guard

ROOT = '/tmp/recorded-root-public'
UUID = 'GPU-00000000-1111-2222-3333-444444444444'
COMMAND = [ROOT + '/target/lattica_pq_ringct_research-recorded', guard.SELECTOR,
           '--exact', '--ignored', '--test-threads=1', '--nocapture']
GROWTH = 'bounded_proof_input_growth old_values=0 new_values=4 live_bytes=32 value_limit=1048576'
NATIVE_STAGES = set('public_values witness_trace preprocessing transform quotient randomness hiding '
                    'commitment opening fri_fold fri_query final_polynomial scalar transcript grinding'.split())


def arguments(**changes):
    result = dict(owned_hashx_root_public_test='gpu', command=list(COMMAND), profile='full',
                  expect_tests=True, build_label='root-public-build', device_uuid=UUID)
    result.update(changes)
    return SimpleNamespace(**result)


def base_environment():
    result = guard.expected_environment(ROOT, UUID)
    for key in (guard.FLAG, 'LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION', 'LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'):
        result.pop(key)
    result['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'device'
    return result


def bound_plan():
    environment = guard.expected_environment(ROOT, UUID)
    sources = {path: 'a' * 64 for path in guard.REQUIRED_SOURCES}
    executable = dict(path=COMMAND[0], resolved_path=COMMAND[0], sha256='b' * 64,
                      build_record=ROOT + '/.tools/pq-opencl-opt/runs/root-public-build.json',
                      build_record_sha256='c' * 64)
    plan = dict(command=list(COMMAND), environment=environment, profile='full', expect_tests=True,
                memory_max_bytes=47 * guard.GIB, memory_high_bytes=45 * guard.GIB,
                fresh_memavailable_required_bytes=49 * guard.GIB, cpu_quota='800%',
                benchmark=False, performance_qualified=False, comparison_baseline=False,
                public_hash_kernel='baseline', expect_result=False, expect_direct_result=False,
                correctness_label=None, record_artifacts=[], runtime_seconds=3600,
                build_label='root-public-build', input_sha256=sources, executable_provenance=executable,
                observation_before_validation_ns=1000)
    plan[guard.ENV_KEY] = guard.receipt(environment)
    plan[guard.BINDING_KEY] = guard.bind_execution(plan, sources, executable, ROOT)
    return plan


def stage_report(entry):
    if entry == 'ringct_owned_native_shake':
        scope, stages = 'proof_request', NATIVE_STAGES
    elif entry == 'block_v2_preprocessing':
        scope, stages = 'preprocessing', set('preprocessing randomness transform commitment'.split())
    else:
        assert entry == 'block_v2_registered_program'
        scope, stages = 'registered_proof', (NATIVE_STAGES - {'public_values'}) | {'lookup'}
    return dict(schema='lattica-proving-stages-v1', entry_point=entry, policy='gpu_required',
                capabilities=dict(scope=scope, profile='block_v2_cubic', max_log_fri_arity=1,
                                  stages=[dict(stage=stage, backend='open_cl') for stage in sorted(stages)]),
                elapsed_ns=10, succeeded=True, stage_coverage_complete=True, completion_rejected=False,
                observation_errors=0, observations=[dict(stage=stage, backend='open_cl', calls=1,
                    completed_calls=1, device_calls=1, inclusive_ns=1, device_ns=1) for stage in sorted(stages)],
                components=[])


def records():
    values = [
        (guard.ROOT_CLAIMS, dict(guard.ROOT_FIXED, verifier_host_bytes=16 << 20,
                               caller_host_bytes=256 << 10, total_host_bytes=(16 << 20) + (256 << 10))),
        (guard.SOURCE_CLAIMS, dict(guard.SOURCE_FIXED, host_bytes=9 * guard.GIB, device_bytes=0)),
    ]
    values.extend(('receipt', stage_report(entry)) for entry in guard.ENTRIES)
    metrics = dict(active_rows=100, padded_rows=128, wires=200, input_values=100,
                   compiler_ns=20, source_cpu_verification_ns=5)
    for ordinal, (first, units) in enumerate(guard.LEAF_SPANS):
        values.append((guard.LEAF, dict(guard.PROVISIONAL, **metrics, ordinal=ordinal,
            first_segment=2 * ordinal, segment_count=2, first_unit=first, units=units)))
    for ordinal, (first, units, level) in enumerate(guard.PARENT_SPANS):
        values.append((guard.PARENT, dict(guard.PROVISIONAL, **metrics, ordinal=ordinal,
            first_unit=first, units=units, level=level)))
    values += [
        (guard.ACCEPTANCE, dict(guard.PROVISIONAL, first_unit=0, units=122, level=3,
            mutation_checks_complete='false', artifact_roundtrip_complete='false', preparation_through_acceptance_ns=600)),
        (guard.ROOT_SCOPE, dict(guard.ROOT_SCOPE_FIXED, positive_verification_ns=20,
            mutation_verification_ns=100, root_recheck_ns=150)),
        (guard.COMPLETE, dict(guard.COMPLETE_FIXED, component_through_destruction_ns=800)),
        (guard.TERMINAL, dict(guard.TERMINAL_FIXED, peak_host_bytes=guard.HOST,
            peak_device_bytes=guard.DEVICE, component_through_destruction_ns=800)),
    ]
    return values


def fixture(values=None, same_line=False, header_payload=''):
    values = records() if values is None else values
    lines = ['test ' + guard.SELECTOR + ' ... ' + header_payload]
    for name, record in values:
        lines.append('proving_stage_report ' + json.dumps(record) if name == 'receipt'
                     else name + ' ' + ' '.join(f'{key}={value}' for key, value in record.items()))
    if same_line:
        lines[:2] = [lines[0] + lines[1]]
    return '\n'.join([*lines, 'ok', 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
                     '515 filtered out; finished in 0.01s', ''])


class HashxRootPublicGpuGuardTests(unittest.TestCase):
    def test_exact_environment_and_isolated_gpu_selector(self):
        environment, note = guard.build_environment(arguments(), base_environment(), ROOT, 'baseline', 'host')
        self.assertEqual(environment, guard.expected_environment(ROOT, UUID))
        self.assertEqual(note, guard.receipt(environment))
        for flag in (guard.FLAG, 'LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION'):
            self.assertEqual(environment[flag], '1')
        for flag in ('LATTICA_OWNED_HASHX_FIRST_LEAF_QUALIFICATION', 'LATTICA_OWNED_HASHX_ROOT_PUBLIC_SOURCE_QUALIFICATION',
                     'LATTICA_OWNED_HASHX_SEQUENCE_SOURCE_QUALIFICATION', 'LATTICA_OWNED_HASHX_SEQUENCE_REFUSAL_QUALIFICATION'):
            self.assertNotIn(flag, environment)
        self.assertEqual(environment['LATTICA_PROVING_POLICY'], 'gpu-required')
        self.assertEqual(environment['LATTICA_V2_GPU_MANAGED_BYTES'], str(8 * guard.GIB))
        self.assertEqual(environment['LATTICA_V2_GPU_CONTEXT_BYTES'], str(4 * guard.GIB))
        self.assertEqual(environment['LATTICA_V2_HOST_OUTPUT_BYTES'], str(24 * guard.GIB))
        self.assertEqual(environment['RAYON_NUM_THREADS'], '8')
        self.assertEqual(guard.build_environment(arguments(command=['--', *COMMAND]), base_environment(),
                         ROOT, 'baseline', 'host'), (environment, note))

    def test_environment_rejects_all_siblings_modes_and_drift(self):
        prefix = guard.SELECTOR.rsplit('::', 1)[0] + '::'
        for tail in ('cpu_original_hashx_sequence_root_public_capacity', 'cpu_original_hashx_sequence_capacity',
                     'gpu_original_hashx_sequence_source_authenticated', 'gpu_original_hashx_sequence_preissue',
                     'gpu_original_hashx_sequence_refusal_after_preissue',
                     'gpu_original_hashx_sequence_refusal_before_first_start',
                     'gpu_original_hashx_sequence_refusal_after_first_producer',
                     'gpu_original_hashx_sequence_refusal_after_first_acceptance'):
            command = [COMMAND[0], prefix + tail, *COMMAND[2:]]
            with self.subTest(tail=tail), self.assertRaises(ValueError):
                guard.build_environment(arguments(command=command), base_environment(), ROOT, 'baseline', 'host')
        for changes in ({'owned_hashx_root_public_test': 'capacity'}, {'profile': 'direct-full'},
                        {'expect_tests': False}, {'build_label': None}, {'device_uuid': None},
                        *({key: True} for key in guard.EXCLUSIVE)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                guard.build_environment(arguments(**changes), base_environment(), ROOT, 'baseline', 'host')
        for command in (COMMAND[:-1], COMMAND + ['--skip', guard.SELECTOR], ['/tmp/other', *COMMAND[1:]]):
            with self.subTest(command=command), self.assertRaises(ValueError):
                guard.build_environment(arguments(command=command), base_environment(), ROOT, 'baseline', 'host')
        for kernel, storage in (('sbox-pair-v1', 'host'), ('baseline', 'device')):
            with self.subTest(kernel=kernel, storage=storage), self.assertRaises(ValueError):
                guard.build_environment(arguments(), base_environment(), ROOT, kernel, storage)
        for key, value in (('EXTRA', '1'), ('RAYON_NUM_THREADS', '4'), (guard.FLAG, '1')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                guard.build_environment(arguments(), dict(base_environment(), **{key: value}), ROOT, 'baseline', 'host')

    def test_binding_and_parser_reject_changed_provenance(self):
        for key, value in (('memory_max_bytes', 48 * guard.GIB), ('memory_high_bytes', 46 * guard.GIB),
                           ('fresh_memavailable_required_bytes', 48 * guard.GIB), ('cpu_quota', '900%'),
                           ('benchmark', True), ('performance_qualified', True), ('comparison_baseline', True),
                           ('expect_result', True), ('expect_direct_result', True), ('correctness_label', 'other'),
                           ('record_artifacts', ['/tmp/other']), ('runtime_seconds', True),
                           ('owned_hashx_sequence_environment', {}),
                           ('owned_hashx_sequence_refusal_environment', {})):
            plan = bound_plan()
            plan[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                guard.validate_log(fixture(), plan)
        for section, key, value in ((guard.BINDING_KEY, 'source_manifest_sha256', 'd' * 64),
                                    (guard.BINDING_KEY, 'selected_physical_device_uuid', 'GPU-invalid'),
                                    ('input_sha256', guard.REQUIRED_SOURCES[0], 'd' * 64),
                                    ('input_sha256', '../escape', 'd' * 64),
                                    ('environment', 'LATTICA_GPU_DEVICE_UUID', 'GPU-invalid'),
                                    ('environment', 'RAYON_NUM_THREADS', '4'),
                                    (guard.ENV_KEY, 'dispatch_authority', True),
                                    ('executable_provenance', 'sha256', 'd' * 64),
                                    ('executable_provenance', 'build_record', ROOT + '/other.json')):
            plan = bound_plan()
            plan[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                guard.validate_log(fixture(), plan)
        plan = bound_plan()
        plan['input_sha256'].pop(guard.REQUIRED_SOURCES[0])
        with self.assertRaises(ValueError):
            guard.validate_log(fixture(), plan)

    def test_valid_root_public_scope_and_pinned_receipt_position_mapping(self):
        for content in (fixture(), fixture(same_line=True), fixture(header_payload=GROWTH)):
            result = guard.validate_log(content, bound_plan())
            self.assertEqual(result['scope'], 'final-root-public-binding-only')
            self.assertEqual((result['native_proofs'], result['recursive_proofs'], result['stage_receipts']), (10, 9, 28))
            self.assertEqual((result['positive_checks'], result['public_probes']), (2, 46))
            self.assertTrue(result['root_public_recheck_complete'])
            self.assertTrue(result['owner_quota_cleanup_complete'])
            self.assertEqual(result['receipt_phase_identity'], 'pinned-source-order-only')
            for key in ('process_engine_device_audit_complete', 'transaction_context_authenticated',
                        'raw_proof_mutation_checks_complete', 'interior_mutation_checks_complete',
                        'mutation_checks_complete', 'artifact_roundtrip_complete',
                        'complete_ringct_workflow', 'performance_qualified'):
                self.assertFalse(result[key], key)
            self.assertEqual([(v['kind'], v['ordinal']) for v in result['recursive_phases']], list(guard.ORDER))
        values = records()
        for index in range(28):
            values[index + 2][1]['elapsed_ns'] = index + 1
        values[39][1]['preparation_through_acceptance_ns'] = 700
        values[41][1]['component_through_destruction_ns'] = 900
        values[42][1]['component_through_destruction_ns'] = 900
        result = guard.validate_log(fixture(values), bound_plan())
        for position, phase in enumerate(result['recursive_phases']):
            self.assertEqual((phase['setup_ns'], phase['proving_ns']), (11 + 2 * position, 12 + 2 * position))

    def test_rejects_missing_duplicated_or_reordered_receipts_and_summaries(self):
        values = records()
        cases = []
        for index in (0, 1, 2, 11, 12, 29, 30, 34, 35, 38, 39, 40, 41, 42):
            cases.extend((values[:index] + values[index + 1:], values[:index] + [values[index]] + values[index:]))
        for left, right in ((1, 2), (11, 12), (12, 13), (29, 30), (30, 31), (35, 36), (39, 40), (41, 42)):
            changed = deepcopy(values)
            changed[left], changed[right] = changed[right], changed[left]
            cases.append(changed)
        for changed in cases:
            with self.subTest(records=changed), self.assertRaises(ValueError):
                guard.validate_log(fixture(changed), bound_plan())

    def test_rejects_receipt_policy_schema_and_execution_gaps(self):
        for section, key, value in ((None, 'policy', 'cpu_required'), (None, 'succeeded', False),
                                   (None, 'stage_coverage_complete', False), (None, 'completion_rejected', True),
                                   (None, 'observation_errors', True), (None, 'components', [{}]),
                                   (None, 'elapsed_ns', 0), (None, 'elapsed_ns', True),
                                   (None, 'elapsed_ns', 1.5), (None, 'elapsed_ns', float('nan')),
                                   ('capabilities', 'max_log_fri_arity', 2),
                                   ('capabilities', 'scope', 'registered_proof'),
                                   ('capabilities', 'profile', 'legacy_quadratic')):
            values = records()
            target = values[2][1] if section is None else values[2][1][section]
            target[key] = value
            with self.subTest(section=section, key=key, value=value), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), bound_plan())
        for key, value in (('backend', 'cpu'), ('calls', 0), ('calls', True), ('calls', 1 << 64),
                           ('completed_calls', 0), ('device_calls', 0), ('device_calls', 2),
                           ('device_ns', 0), ('inclusive_ns', -1), ('stage', [])):
            values = records()
            values[2][1]['observations'][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), bound_plan())
        values = records()
        values[2][1]['capabilities']['stages'][0]['backend'] = 'cpu'
        with self.assertRaises(ValueError):
            guard.validate_log(fixture(values), bound_plan())
        for section in ('observations',):
            values = records()
            values[2][1][section][1] = deepcopy(values[2][1][section][0])
            with self.assertRaises(ValueError):
                guard.validate_log(fixture(values), bound_plan())
        for section in (None, 'capabilities'):
            values = records()
            target = values[2][1] if section is None else values[2][1][section]
            target['invented'] = True
            with self.assertRaises(ValueError):
                guard.validate_log(fixture(values), bound_plan())
        duplicated = fixture().replace('"schema": "lattica-proving-stages-v1"',
                                        '"schema": "lattica-proving-stages-v1", "schema": "lattica-proving-stages-v1"', 1)
        with self.assertRaises(ValueError):
            guard.validate_log(duplicated, bound_plan())

    def test_rejects_coverage_geometry_and_authority_changes(self):
        for index, key, value in ((0, 'planned_public_probes', 45), (0, 'actual_root_public_probes', 1),
                                  (0, 'total_host_bytes', 1), (0, 'caller_host_bytes', 64 << 10),
                                  (1, 'native_outputs', 9), (1, 'device_bytes', 1),
                                  (30, 'segment_count', 1), (31, 'first_segment', 0), (34, 'units', 1),
                                  (37, 'level', 1), (38, 'units', 121), (38, 'first_unit', 1),
                                  (39, 'level', 2), (40, 'positive_checks', 1), (40, 'public_probes', 45),
                                  (40, 'retained_output_immutable', 'false'), (40, 'provisional', 'false'),
                                  (40, 'mutation_checks_complete', 'true'), (41, 'compiler_reclamations', 8),
                                  (41, 'root_public_recheck_complete', 'false'),
                                  (41, 'process_engine_device_audit_complete', 'true'),
                                  (41, 'complete_ringct_workflow', 'true'), (42, 'current_host_bytes', 1),
                                  (42, 'peak_device_bytes', guard.DEVICE - 1), (42, 'component_success', 'false')):
            values = records()
            values[index][1][key] = value
            with self.subTest(index=index, key=key, value=value), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), bound_plan())
        for key, value in (('active_rows', 0), ('active_rows', 129), ('padded_rows', 127),
                           ('padded_rows', 1 << 21), ('wires', (1 << 26) + 1),
                           ('input_values', (1 << 20) + 1), ('source_cpu_verification_ns', 0),
                           ('compiler_ns', '020')):
            values = records()
            values[30][1][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), bound_plan())
        values = records()
        values[1][1]['host_bytes'] = 1
        values[42][1]['peak_host_bytes'] = 1
        with self.assertRaises(ValueError):
            guard.validate_log(fixture(values), bound_plan())

    def test_timers_are_disjoint_lower_bounds_and_observation_is_runner_owned(self):
        for index, key, value in ((2, 'elapsed_ns', 601), (30, 'compiler_ns', 601),
                                  (35, 'source_cpu_verification_ns', 601),
                                  (39, 'preparation_through_acceptance_ns', 504),
                                  (40, 'positive_verification_ns', 0), (40, 'mutation_verification_ns', 0),
                                  (40, 'root_recheck_ns', 119), (41, 'component_through_destruction_ns', 799),
                                  (42, 'component_through_destruction_ns', 799)):
            values = records()
            values[index][1][key] = value
            with self.subTest(index=index, key=key, value=value), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), bound_plan())
        values = records()
        for index in (41, 42):
            values[index][1]['component_through_destruction_ns'] = 749
        with self.assertRaises(ValueError):
            guard.validate_log(fixture(values), bound_plan())
        for observation in (None, True, 0, -1, 1000.0, 799, 1 << 128):
            plan = bound_plan()
            plan['observation_before_validation_ns'] = observation
            with self.subTest(observation=observation), self.assertRaises(ValueError):
                guard.validate_log(fixture(), plan)
        # Nested/device observations are not added to Report.elapsed_ns.
        values = records()
        for name, report in values:
            if name == 'receipt':
                for item in report['observations']:
                    item['inclusive_ns'] = 9
                    item['device_ns'] = 9
        self.assertTrue(guard.validate_log(fixture(values), bound_plan())['root_public_recheck_complete'])

    def test_rejects_foreign_markers_bad_headers_and_failed_or_reordered_completion(self):
        for payload in ('failed', 'ok', 'ignored', 'fixture', GROWTH + ' extra=1',
                        GROWTH.replace('live_bytes=32', 'live_bytes=31')):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                guard.validate_log(fixture(header_payload=payload), bound_plan())
        for token in ('ringct_hashx_sequence_complete native_proofs=10',
                      'ringct_hashx_sequence_capacity_complete native_proofs=0',
                      'ringct_hashx_sequence_preissue_complete native_proofs=0',
                      'ringct_hashx_sequence_returned_refusal_complete component_success=false',
                      'ringct_hashx_first_leaf_complete native_proofs=10', 'ringct_unknown complete=true',
                      'OPENCL_OPT_RESULT {}', 'DIRECT_RING_RESULT {}', 'fallback=true', 'retry=true',
                      'test foreign::test ... ok', "thread 'test' panicked at fixture:1"):
            with self.subTest(token=token), self.assertRaises(ValueError):
                guard.validate_log(fixture() + token + '\n', bound_plan())
        for old, new in (('\nok\n', '\n'), ('\nok\n', '\nok\nok\n'), ('1 passed;', '2 passed;'),
                         ('0 failed;', '1 failed;'), ('0 ignored;', '1 ignored;'),
                         ('cpu_heights=18 ', 'cpu_heights=18 extra=1 '),
                         ('cpu_heights=18 ', 'cpu_heights=18 cpu_heights=18 ')):
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                guard.validate_log(fixture().replace(old, new), bound_plan())


if __name__ == '__main__':
    unittest.main()
