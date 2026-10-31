"""Synthetic returned-refusal fixtures; no real proof/failure qualification."""
from copy import deepcopy
import json
from types import SimpleNamespace
import unittest

import hashx_sequence_refusal_guard as guard

ROOT = '/tmp/recorded-sequence-refusal'
UUID = 'GPU-00000000-1111-2222-3333-444444444444'
DEFAULT = 'after-first-producer'
GROWTH = 'bounded_proof_input_growth old_values=0 new_values=4 live_bytes=32 value_limit=1048576'
NATIVE_STAGES = set('public_values witness_trace preprocessing transform quotient randomness hiding '
                    'commitment opening fri_fold fri_query final_polynomial scalar transcript grinding'.split())


def command(mode):
    return [ROOT + '/target/lattica_pq_ringct_research-recorded', guard.selector(mode),
            '--exact', '--ignored', '--test-threads=1', '--nocapture']


def arguments(mode=DEFAULT, **changes):
    result = dict(owned_hashx_sequence_refusal_test=mode, command=command(mode), profile='full',
                  expect_tests=True, build_label='refusal-build', device_uuid=UUID)
    result.update(changes)
    return SimpleNamespace(**result)


def base_environment():
    result = guard.expected_environment(ROOT, UUID)
    for key in (guard.FLAG, 'LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION', 'LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'):
        result.pop(key)
    result['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'device'
    return result


def bound_plan(mode=DEFAULT):
    environment = guard.expected_environment(ROOT, UUID)
    sources = {path: 'a' * 64 for path in guard.REQUIRED_SOURCES}
    executable = dict(path=command(mode)[0], resolved_path=command(mode)[0], sha256='b' * 64,
                      build_record=ROOT + '/.tools/pq-opencl-opt/runs/refusal-build.json',
                      build_record_sha256='c' * 64)
    plan = dict(command=command(mode), environment=environment, profile='full', expect_tests=True,
                memory_max_bytes=47 * guard.GIB, memory_high_bytes=45 * guard.GIB,
                fresh_memavailable_required_bytes=49 * guard.GIB, cpu_quota='800%',
                benchmark=False, performance_qualified=False, comparison_baseline=False,
                public_hash_kernel='baseline', expect_result=False, expect_direct_result=False,
                correctness_label=None, record_artifacts=[], runtime_seconds=3600,
                build_label='refusal-build', input_sha256=sources, executable_provenance=executable,
                observation_before_validation_ns=1000)
    plan[guard.ENV_KEY] = guard.receipt(mode, environment)
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


def records(mode=DEFAULT):
    native, recursive, installed = guard.COUNTS[mode]
    requested = guard.probe(mode)
    values = [(guard.SOURCE, dict(guard.SOURCE_FIXED, mode=requested, host_bytes=9 * guard.GIB, device_bytes=0))]
    entries = ['ringct_owned_native_shake'] * native
    entries += ['block_v2_preprocessing', 'block_v2_registered_program'] * recursive
    values.extend(('receipt', stage_report(entry)) for entry in entries)
    values.extend([
        (guard.REACHED, dict(guard.REACHED_FIXED, probe=requested)),
        (guard.COMPLETE, dict(guard.COMPLETE_FIXED, probe=requested,
            native_proofs_before_refusal=native, recursive_proofs_before_refusal=recursive,
            installed_leaf_outputs_before_refusal=installed, component_through_destruction_ns=500)),
        (guard.TERMINAL, dict(guard.TERMINAL_FIXED, mode=requested, peak_host_bytes=guard.HOST,
            peak_device_bytes=guard.DEVICE, component_through_destruction_ns=500)),
    ])
    return values


def fixture(mode=DEFAULT, values=None, same_line=False, header_payload=''):
    values = records(mode) if values is None else values
    lines = ['test ' + guard.selector(mode) + ' ... ' + header_payload]
    for name, record in values:
        lines.append('proving_stage_report ' + json.dumps(record) if name == 'receipt'
                     else name + ' ' + ' '.join(f'{key}={value}' for key, value in record.items()))
    if same_line:
        lines[:2] = [lines[0] + lines[1]]
    return '\n'.join([*lines, 'ok', 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
                     '515 filtered out; finished in 0.01s', ''])


class SequenceRefusalGuardTests(unittest.TestCase):
    def test_each_mode_has_exact_environment_and_selector(self):
        for mode in guard.COUNTS:
            environment, note = guard.build_environment(arguments(mode), base_environment(), ROOT, 'baseline', 'host')
            self.assertEqual(environment, guard.expected_environment(ROOT, UUID))
            self.assertEqual(note, guard.receipt(mode, environment))
            self.assertEqual(note['selector'], guard.selector(mode))
            for flag in (guard.FLAG, 'LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION'):
                self.assertEqual(environment[flag], '1')
            for flag in ('LATTICA_OWNED_HASHX_ROOT_PUBLIC_QUALIFICATION', 'LATTICA_OWNED_HASHX_FIRST_LEAF_QUALIFICATION',
                         'LATTICA_OWNED_HASHX_SEQUENCE_SOURCE_QUALIFICATION', 'LATTICA_NATIVE_SPEND_QUALIFICATION'):
                self.assertNotIn(flag, environment)
            self.assertEqual(environment['LATTICA_PROVING_POLICY'], 'gpu-required')
            self.assertEqual(environment['LATTICA_V2_GPU_MANAGED_BYTES'], str(8 * guard.GIB))
            self.assertEqual(environment['LATTICA_V2_GPU_CONTEXT_BYTES'], str(4 * guard.GIB))
            self.assertEqual(environment['LATTICA_V2_HOST_OUTPUT_BYTES'], str(24 * guard.GIB))
            self.assertEqual(environment['RAYON_NUM_THREADS'], '8')
            self.assertEqual(guard.build_environment(arguments(mode, command=['--', *command(mode)]),
                             base_environment(), ROOT, 'baseline', 'host'), (environment, note))

    def test_mode_selection_and_all_siblings_are_exclusive(self):
        prefix = guard.SELECTOR_PREFIX.rsplit('::', 1)[0] + '::'
        for tail in ('cpu_original_hashx_sequence_capacity', 'cpu_original_hashx_sequence_root_public_capacity',
                     'gpu_original_hashx_sequence_preissue', 'gpu_original_hashx_sequence_source_authenticated',
                     'gpu_original_hashx_sequence_root_public_recheck'):
            selected = command(DEFAULT)
            selected[1] = prefix + tail
            with self.subTest(tail=tail), self.assertRaises(ValueError):
                guard.build_environment(arguments(command=selected), base_environment(), ROOT, 'baseline', 'host')
        for mode in guard.COUNTS:
            other = next(item for item in guard.COUNTS if item != mode)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                guard.build_environment(arguments(mode, command=command(other)), base_environment(), ROOT, 'baseline', 'host')
        for changes in ({'owned_hashx_sequence_refusal_test': 'all'}, {'profile': 'direct-full'},
                        {'expect_tests': False}, {'build_label': None}, {'device_uuid': None},
                        *({key: True} for key in guard.EXCLUSIVE)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                guard.build_environment(arguments(**changes), base_environment(), ROOT, 'baseline', 'host')
        for selected in (command(DEFAULT)[:-1], command(DEFAULT) + ['--skip', guard.selector(DEFAULT)],
                         ['/tmp/other', *command(DEFAULT)[1:]]):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                guard.build_environment(arguments(command=selected), base_environment(), ROOT, 'baseline', 'host')
        for kernel, storage in (('sbox-pair-v1', 'host'), ('baseline', 'device')):
            with self.subTest(kernel=kernel, storage=storage), self.assertRaises(ValueError):
                guard.build_environment(arguments(), base_environment(), ROOT, kernel, storage)
        for key, value in (('EXTRA', '1'), ('RAYON_NUM_THREADS', '4'), (guard.FLAG, '1')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                guard.build_environment(arguments(), dict(base_environment(), **{key: value}), ROOT, 'baseline', 'host')

    def test_binding_rejects_cross_mode_and_changed_provenance(self):
        for mode in guard.COUNTS:
            other = next(item for item in guard.COUNTS if item != mode)
            plan = bound_plan(mode)
            plan['command'] = command(other)
            plan[guard.ENV_KEY] = guard.receipt(other, plan['environment'])
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                guard.validate_log(fixture(other), plan)
        for key, value in (('memory_max_bytes', 48 * guard.GIB), ('memory_high_bytes', 46 * guard.GIB),
                           ('fresh_memavailable_required_bytes', 48 * guard.GIB), ('cpu_quota', '900%'),
                           ('benchmark', True), ('performance_qualified', True), ('comparison_baseline', True),
                           ('expect_result', True), ('expect_direct_result', True), ('correctness_label', 'other'),
                           ('record_artifacts', ['/tmp/other']), ('runtime_seconds', True),
                           *((key, {}) for key in guard.FOREIGN_RECEIPTS)):
            plan = bound_plan()
            plan[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                guard.validate_log(fixture(), plan)
        for section, key, value in ((guard.BINDING_KEY, 'source_root', '/tmp/other'),
                                    (guard.BINDING_KEY, 'source_manifest_sha256', 'd' * 64),
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

    def test_exact_counts_distinguish_pre_native_native_and_first_outer_refusals(self):
        for mode, (native, recursive, installed) in guard.COUNTS.items():
            for content in (fixture(mode), fixture(mode, same_line=True), fixture(mode, header_payload=GROWTH)):
                result = guard.validate_log(content, bound_plan(mode))
                self.assertEqual(result['scope'], 'ordinary-returned-refusal-only')
                self.assertEqual(result['stage_receipts'], native + 2 * recursive)
                self.assertEqual(result['native_proofs_before_refusal'], native)
                self.assertEqual(result['recursive_proofs_before_refusal'], recursive)
                self.assertEqual(result['installed_leaf_outputs_before_refusal'], installed)
                self.assertEqual(result['fresh_native_proof_receipts'], native)
                self.assertEqual(result['fresh_outer_preprocessing_receipts'], recursive)
                self.assertEqual(result['fresh_outer_proof_receipts'], recursive)
                self.assertEqual(result['native_proof_dispatch_started'], native > 0)
                self.assertEqual(result['recursive_proof_dispatch_started'], recursive > 0)
                self.assertEqual(result['original_startup_pcs_reused_for_outer_proof'], recursive > 0)
                self.assertEqual(result['outer_preprocessing_receipt_elapsed_ns'], [10] * recursive)
                self.assertEqual(result['outer_proof_receipt_elapsed_ns'], [10] * recursive)
                self.assertEqual(result['receipt_phase_identity'], 'pinned-source-order-only')
                self.assertEqual(result['compiler_reclamations'], 0)
                self.assertTrue(result['expected_returned_refusal'])
                self.assertTrue(result['physical_runtime_preissued'])
                self.assertTrue(result['owner_quota_cleanup_complete'])
                for key in ('component_success', 'process_engine_device_audit_complete',
                            'asynchronous_failure_checked', 'unwind_checked', 'complete_component_fit_qualified',
                            'transaction_context_authenticated', 'mutation_checks_complete',
                            'artifact_roundtrip_complete', 'complete_ringct_workflow', 'performance_qualified'):
                    self.assertFalse(result[key], key)
        values = records()
        values[11][1]['elapsed_ns'] = 21
        values[12][1]['elapsed_ns'] = 31
        result = guard.validate_log(fixture(values=values), bound_plan())
        self.assertEqual(result['outer_preprocessing_receipt_elapsed_ns'], [21])
        self.assertEqual(result['outer_proof_receipt_elapsed_ns'], [31])

    def test_rejects_missing_duplicated_reordered_and_unexpected_events(self):
        for mode in guard.COUNTS:
            values = records(mode)
            cases = []
            for index in range(len(values)):
                cases.extend((values[:index] + values[index + 1:], values[:index] + [values[index]] + values[index:]))
            for left, right in ((0, 1), (-3, -2), (-2, -1)):
                changed = deepcopy(values)
                changed[left], changed[right] = changed[right], changed[left]
                cases.append(changed)
            cases.append(values[:1] + [('receipt', stage_report('ringct_owned_native_shake'))] + values[1:])
            for changed in cases:
                with self.subTest(mode=mode, events=len(changed)), self.assertRaises(ValueError):
                    guard.validate_log(fixture(mode, values=changed), bound_plan(mode))
        values = records()
        values[11], values[12] = values[12], values[11]
        with self.assertRaises(ValueError):
            guard.validate_log(fixture(values=values), bound_plan())

    def test_rejects_wrong_probe_counts_cleanup_and_success_credit(self):
        for mode in guard.COUNTS:
            other = next(item for item in guard.COUNTS if item != mode)
            for index, key, value in ((0, 'mode', guard.probe(other)), (0, 'native_dispatch_started', 'true'),
                                      (-3, 'probe', guard.probe(other)), (-3, 'provisional', 'false'),
                                      (-3, 'terminal_cleanup_complete', 'true'),
                                      (-2, 'probe', guard.probe(other)), (-2, 'compiler_reclamations', 1),
                                      (-2, 'component_success', 'true'), (-2, 'owner_quota_cleanup_complete', 'false'),
                                      (-2, 'process_engine_device_audit_complete', 'true'),
                                      (-2, 'asynchronous_failure_checked', 'true'), (-2, 'unwind_checked', 'true'),
                                      (-2, 'mutation_checks_complete', 'true'), (-2, 'artifact_roundtrip_complete', 'true'),
                                      (-2, 'complete_ringct_workflow', 'true'), (-1, 'current_host_bytes', 1),
                                      (-1, 'current_device_bytes', 1), (-1, 'component_success', 'true')):
                values = records(mode)
                values[index][1][key] = value
                with self.subTest(mode=mode, index=index, key=key), self.assertRaises(ValueError):
                    guard.validate_log(fixture(mode, values=values), bound_plan(mode))
            for key in ('native_proofs_before_refusal', 'recursive_proofs_before_refusal',
                        'installed_leaf_outputs_before_refusal'):
                values = records(mode)
                values[-2][1][key] += 1
                with self.subTest(mode=mode, key=key), self.assertRaises(ValueError):
                    guard.validate_log(fixture(mode, values=values), bound_plan(mode))

    def test_rejects_receipt_policy_schema_and_execution_gaps(self):
        for section, key, value in ((None, 'policy', 'cpu_required'), (None, 'succeeded', False),
                                   (None, 'stage_coverage_complete', False), (None, 'completion_rejected', True),
                                   (None, 'observation_errors', True), (None, 'components', [{}]),
                                   (None, 'elapsed_ns', 0), (None, 'elapsed_ns', True),
                                   (None, 'elapsed_ns', 1.5), (None, 'elapsed_ns', float('nan')),
                                   ('capabilities', 'max_log_fri_arity', 2), ('capabilities', 'scope', 'registered_proof'),
                                   ('capabilities', 'profile', 'legacy_quadratic')):
            values = records()
            target = values[1][1] if section is None else values[1][1][section]
            target[key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                guard.validate_log(fixture(values=values), bound_plan())
        for key, value in (('backend', 'cpu'), ('calls', 0), ('calls', True), ('calls', 1 << 64),
                           ('completed_calls', 0), ('device_calls', 0), ('device_calls', 2),
                           ('device_ns', 0), ('inclusive_ns', -1), ('stage', [])):
            values = records()
            values[1][1]['observations'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                guard.validate_log(fixture(values=values), bound_plan())
        for section in (None, 'capabilities', 'observation'):
            values = records()
            target = values[1][1] if section is None else (values[1][1]['observations'][0] if section == 'observation'
                                                         else values[1][1][section])
            target['invented'] = True
            with self.subTest(section=section), self.assertRaises(ValueError):
                guard.validate_log(fixture(values=values), bound_plan())
        for section in ('stages',):
            values = records()
            values[1][1]['capabilities'][section][0]['backend'] = 'cpu'
            with self.assertRaises(ValueError):
                guard.validate_log(fixture(values=values), bound_plan())
        values = records()
        values[1][1]['observations'][1] = deepcopy(values[1][1]['observations'][0])
        with self.assertRaises(ValueError):
            guard.validate_log(fixture(values=values), bound_plan())
        duplicate = fixture().replace('"schema": "lattica-proving-stages-v1"',
            '"schema": "lattica-proving-stages-v1", "schema": "lattica-proving-stages-v1"', 1)
        with self.assertRaises(ValueError):
            guard.validate_log(duplicate, bound_plan())

    def test_memory_and_timing_are_bounded_without_invented_cpu_intervals(self):
        for mode in guard.COUNTS:
            for index, key, value in ((0, 'device_bytes', 1), (0, 'host_bytes', 0),
                                      (-1, 'peak_host_bytes', 9 * guard.GIB),
                                      (-1, 'peak_host_bytes', guard.HOST + 1),
                                      (-1, 'peak_device_bytes', guard.DEVICE - 1),
                                      (-2, 'component_through_destruction_ns', 499),
                                      (-1, 'component_through_destruction_ns', 499)):
                values = records(mode)
                values[index][1][key] = value
                with self.subTest(mode=mode, index=index, key=key), self.assertRaises(ValueError):
                    guard.validate_log(fixture(mode, values=values), bound_plan(mode))
            values = records(mode)
            for index in (-2, -1):
                values[index][1]['component_through_destruction_ns'] = 0
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                guard.validate_log(fixture(mode, values=values), bound_plan(mode))
        values = records()
        for index in (-2, -1):
            values[index][1]['component_through_destruction_ns'] = 119
        with self.assertRaises(ValueError):
            guard.validate_log(fixture(values=values), bound_plan())
        for observation in (None, True, 0, -1, 1000.0, 499, 1 << 128):
            plan = bound_plan()
            plan['observation_before_validation_ns'] = observation
            with self.subTest(observation=observation), self.assertRaises(ValueError):
                guard.validate_log(fixture(), plan)
        values = records()
        for name, report in values:
            if name == 'receipt':
                for item in report['observations']:
                    item['inclusive_ns'] = 9
                    item['device_ns'] = 9
        self.assertTrue(guard.validate_log(fixture(values=values), bound_plan())['expected_returned_refusal'])

    def test_rejects_unqualified_failures_success_markers_and_bad_libtest_status(self):
        for payload in ('failed', 'ok', 'ignored', 'fixture', GROWTH + ' extra=1',
                        GROWTH.replace('live_bytes=32', 'live_bytes=31')):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                guard.validate_log(fixture(header_payload=payload), bound_plan())
        for token in ('ringct_hashx_sequence_returned_refusal_unqualified requested_probe=other',
                      'ringct_hashx_sequence_failure phase=compiler retry=false',
                      'ringct_hashx_sequence_complete native_proofs=10',
                      'ringct_hashx_sequence_preissue_complete native_proofs=0',
                      'ringct_hashx_sequence_capacity_complete native_proofs=0',
                      'ringct_hashx_sequence_leaf ordinal=0', 'ringct_hashx_sequence_parent ordinal=0',
                      'ringct_hashx_sequence_acceptance_scope first_unit=0',
                      'ringct_hashx_root_public_recheck_complete native_proofs=10',
                      'ringct_unknown complete=true', 'OPENCL_OPT_RESULT {}', 'DIRECT_RING_RESULT {}',
                      'fallback=true', 'retry=true', 'test foreign::test ... ok',
                      "thread 'test' panicked at fixture:1"):
            with self.subTest(token=token), self.assertRaises(ValueError):
                guard.validate_log(fixture() + token + '\n', bound_plan())
        for old, new in (('\nok\n', '\n'), ('\nok\n', '\nok\nok\n'), ('1 passed;', '2 passed;'),
                         ('0 failed;', '1 failed;'), ('0 ignored;', '1 ignored;'),
                         ('compiler_reclamations=0 ', 'compiler_reclamations=00 '),
                         ('compiler_reclamations=0 ', 'compiler_reclamations=0 extra=1 '),
                         ('compiler_reclamations=0 ', 'compiler_reclamations=0 compiler_reclamations=0 ')):
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                guard.validate_log(fixture().replace(old, new), bound_plan())


if __name__ == '__main__':
    unittest.main()
