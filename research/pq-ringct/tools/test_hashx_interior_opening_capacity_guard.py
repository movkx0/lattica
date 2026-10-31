"""Synthetic CPU capacity-policy fixtures, never actual proof/GPU evidence."""
from copy import deepcopy
from types import SimpleNamespace
import unittest

import hashx_interior_opening_capacity_guard as guard
import test_hashx_interior_opening_gpu_guard as gpu_fixtures

ROOT = '/tmp/recorded-interior-opening-capacity'
COMMAND = [ROOT + '/target/lattica_pq_ringct_research-recorded', guard.SELECTOR,
           '--exact', '--ignored', '--test-threads=1', '--nocapture']


def arguments(**changes):
    values = dict(owned_source_shape_test=True, command=list(COMMAND), profile='research-compile-large',
                  expect_tests=True, build_label='opening-capacity-build', device_uuid=None)
    values.update(changes)
    return SimpleNamespace(**values)


def base_environment():
    environment = guard.expected_environment(ROOT)
    environment.pop(guard.FLAG)
    environment.pop(guard.SEQUENCE_FLAG)
    return environment


def bound_plan():
    environment = guard.expected_environment(ROOT)
    sources = {path: 'a' * 64 for path in guard.REQUIRED_SOURCES}
    executable = dict(path=COMMAND[0], resolved_path=COMMAND[0], sha256='b' * 64,
                      build_record=ROOT + '/.tools/pq-opencl-opt/runs/opening-capacity-build.json',
                      build_record_sha256='c' * 64)
    plan = dict(command=list(COMMAND), environment=environment, profile='research-compile-large', expect_tests=True,
                memory_max_bytes=32 * guard.GIB, memory_high_bytes=30 * guard.GIB,
                fresh_memavailable_required_bytes=36 * guard.GIB, cpu_quota='200%',
                benchmark=False, performance_qualified=False, comparison_baseline=False,
                public_hash_kernel='baseline', expect_result=False, expect_direct_result=False,
                correctness_label=None, record_artifacts=[], runtime_seconds=3600,
                build_label='opening-capacity-build', input_sha256=sources, executable_provenance=executable,
                observation_before_validation_ns=1000)
    plan[guard.ENV_KEY] = guard.receipt(environment)
    plan[guard.BINDING_KEY] = guard.bind_execution(plan, sources, executable, ROOT)
    return plan


def records():
    original = gpu_fixtures.records()
    root = deepcopy(gpu_fixtures.record(original, guard.ROOT_CLAIMS))
    root.update(guard.ROOT_FIXED)
    source = deepcopy(gpu_fixtures.record(original, guard.SOURCE_CLAIMS))
    source.update(guard.SOURCE_FIXED)
    startup, wrappers = guard.DEVICE + (1 << 20), 1 << 20
    pcs = guard.HOST - source['host_bytes'] - startup - wrappers
    capacity = dict(guard.CAPACITY_FIXED, original_claims_host_bytes=source['host_bytes'],
        startup_host_bytes=startup, startup_device_bytes=guard.STARTUP_DEVICE,
        phase_wrappers_host_bytes=wrappers, phase_wrappers_device_bytes=0,
        pcs_host_bytes=pcs, pcs_device_bytes=guard.DEVICE - guard.STARTUP_DEVICE,
        simultaneous_host_bytes=guard.HOST, simultaneous_device_bytes=guard.DEVICE, projection_ns=20)
    terminal = dict(guard.TERMINAL_FIXED, peak_host_bytes=guard.HOST, peak_device_bytes=guard.DEVICE,
        component_through_destruction_ns=800, terminal_observer_fixed_host_bytes=65536)
    return [(guard.ROOT_CLAIMS, root), (guard.SOURCE_CLAIMS, source),
            (guard.CAPACITY_COMPLETE, capacity), (guard.TERMINAL, terminal)]


def fixture(values=None, same_line=False, header_payload=''):
    values = records() if values is None else values
    lines = ['test ' + guard.SELECTOR + ' ... ' + header_payload]
    for name, record in values:
        lines.append(name + ' ' + ' '.join(f'{key}={value}' for key, value in record.items()))
    if same_line:
        lines[:2] = [lines[0] + lines[1]]
    return '\n'.join([*lines, 'ok', 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
                     '515 filtered out; finished in 0.01s', ''])


class InteriorOpeningCapacityGuardTests(unittest.TestCase):
    def test_exact_cpu_environment_and_recorded_selector(self):
        environment, note = guard.build_environment(arguments(), base_environment(), ROOT, 'baseline', 'device')
        self.assertEqual(environment, guard.expected_environment(ROOT))
        self.assertEqual(note, guard.receipt(environment))
        self.assertEqual(environment['LATTICA_PROVING_POLICY'], 'cpu-required')
        self.assertEqual(environment['RAYON_NUM_THREADS'], '2')
        self.assertEqual(environment[guard.FLAG], '1')
        self.assertEqual(environment[guard.SEQUENCE_FLAG], '1')
        self.assertFalse(any('GPU' in key for key in environment))
        self.assertNotIn(guard.gpu.FLAG, environment)
        self.assertFalse(note['gpu_dispatch'])
        self.assertFalse(note['dispatch_authority'])
        self.assertEqual(guard.build_environment(arguments(command=['--', *COMMAND]), base_environment(),
                         ROOT, 'baseline', 'device'), (environment, note))

    def test_cpu_route_rejects_gpu_siblings_profiles_flags_and_inherited_environment(self):
        for selector in (guard.gpu.SELECTOR,
                guard.SELECTOR.replace('::interior::', '::opening::').replace('leaf0_opening_capacity', 'root_opening_capacity'),
                guard.SELECTOR.replace('::interior::', '::transport::').replace('leaf0_opening_capacity', 'root_transport_capacity'),
                guard.SELECTOR.replace('::interior::', '::'),
                guard.SELECTOR.replace('leaf0_opening_capacity', 'root_public_capacity')):
            with self.subTest(selector=selector), self.assertRaises(ValueError):
                guard.build_environment(arguments(command=[COMMAND[0], selector, *COMMAND[2:]]),
                                        base_environment(), ROOT, 'baseline', 'device')
        for changes in ({'owned_source_shape_test': False}, {'owned_source_shape_test': 1},
                        {'profile': 'full'}, {'profile': 'research-compile'}, {'expect_tests': False},
                        {'build_label': None}, {'device_uuid': gpu_fixtures.UUID},
                        *({key: True} for key in guard.EXCLUSIVE)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                guard.build_environment(arguments(**changes), base_environment(), ROOT, 'baseline', 'device')
        for kernel, storage in (('sbox-pair-v1', 'device'), ('baseline', 'host')):
            with self.subTest(kernel=kernel, storage=storage), self.assertRaises(ValueError):
                guard.build_environment(arguments(), base_environment(), ROOT, kernel, storage)
        for key, value in (('RAYON_NUM_THREADS', '8'), (guard.FLAG, '1'), (guard.gpu.FLAG, '1'),
                           ('LATTICA_GPU_DEVICE_UUID', gpu_fixtures.UUID)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                guard.build_environment(arguments(), dict(base_environment(), **{key: value}), ROOT, 'baseline', 'device')
        for command in (COMMAND[:-1], COMMAND + ['extra'], ['/tmp/other', *COMMAND[1:]]):
            with self.subTest(command=command), self.assertRaises(ValueError):
                guard.build_environment(arguments(command=command), base_environment(), ROOT, 'baseline', 'device')

    def test_binding_rejects_resource_provenance_and_foreign_mode_drift(self):
        for sibling in ('owned_hashx_interior_opening_environment', 'owned_hashx_root_opening_environment',
                        'owned_hashx_root_transport_environment'):
            self.assertIn(sibling, guard.FOREIGN_RECEIPTS)
        for key, value in (('memory_max_bytes', 47 * guard.GIB), ('memory_high_bytes', 31 * guard.GIB),
                           ('fresh_memavailable_required_bytes', 35 * guard.GIB), ('cpu_quota', '800%'),
                           ('benchmark', True), ('performance_qualified', True), ('comparison_baseline', True),
                           ('expect_result', True), ('expect_direct_result', True), ('correctness_label', 'other'),
                           ('record_artifacts', ['/tmp/other']), ('runtime_seconds', True),
                           ('runtime_seconds', 86401), *((key, {}) for key in guard.FOREIGN_RECEIPTS)):
            plan = bound_plan()
            plan[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                guard.validate_log(fixture(), plan)
        for section, key, value in ((guard.BINDING_KEY, 'source_manifest_sha256', 'd' * 64),
                                   (guard.BINDING_KEY, 'dispatch_authority', 0),
                                   ('environment', 'LATTICA_GPU_DEVICE_UUID', gpu_fixtures.UUID),
                                   (guard.ENV_KEY, 'dispatch_authority', 0),
                                   ('input_sha256', '../escape', 'd' * 64),
                                   ('executable_provenance', 'resolved_path', ROOT + '/target/other'),
                                   ('executable_provenance', 'sha256', 'd' * 64),
                                   ('executable_provenance', 'build_record_sha256', 'd' * 64)):
            plan = bound_plan()
            plan[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                guard.validate_log(fixture(), plan)
        for path in guard.REQUIRED_SOURCES:
            plan = bound_plan()
            plan['input_sha256'].pop(path)
            with self.subTest(path=path), self.assertRaises(ValueError):
                guard.bind_execution(plan, plan['input_sha256'], plan['executable_provenance'], ROOT)

    def test_capacity_result_never_credits_actual_proof_opening_or_gpu_work(self):
        for content in (fixture(), fixture(same_line=True), fixture(header_payload=gpu_fixtures.GROWTH)):
            result = guard.validate_log(content, bound_plan())
            self.assertEqual(result['scope'], 'interior-opening-quota-projection-only')
            self.assertEqual(result['memory_peak_kind'], 'original-ledger-projected-quota')
            self.assertEqual(result['terminal_observer_scope'], 'process-audit-only')
            self.assertLessEqual(result['terminal_observer_event_bytes'], 4096)
            for key in ('native_proofs', 'recursive_proofs', 'stage_receipts', 'numerical_positive_checks',
                        'typed_opening_relation_rejections', 'actual_opening_probes'):
                self.assertEqual(result[key], 0, key)
            for key in ('physical_backend_fit', 'actual_proving_fit', 'native_dispatch_started',
                        'interior_opening_probe_complete', 'transaction_context_authenticated',
                        'process_engine_device_audit_complete', 'released_claims_cover_terminal_observer',
                        'terminal_observer_census_is_physical_measurement',
                        'raw_proof_mutation_checks_complete', 'parent_boundary_mutation_checks_complete',
                        'interior_mutation_checks_complete', 'whole_graph_mutation_checks_complete',
                        'child_restoration_observed', 'parent0_child_consumed',
                        'mutation_checks_complete', 'disk_artifact_roundtrip_complete',
                        'artifact_roundtrip_complete', 'complete_ringct_workflow', 'performance_qualified'):
                self.assertFalse(result[key], key)
            self.assertTrue(result['owner_quota_cleanup_complete'])
            self.assertTrue(result['wrong_request_and_ledger_refused'])

    def test_four_event_order_and_no_actual_or_synthetic_codec_receipts(self):
        original = records()
        cases = []
        for index in range(4):
            cases.extend((original[:index] + original[index + 1:], original[:index] + [original[index]] + original[index:]))
        for index in range(3):
            changed = deepcopy(original)
            changed[index], changed[index + 1] = changed[index + 1], changed[index]
            cases.append(changed)
        for ordinal, changed in enumerate(cases):
            with self.subTest(case=ordinal), self.assertRaises(ValueError):
                guard.validate_log(fixture(changed), bound_plan())
        for token in ('proving_stage_report {}', 'bounded_decoded_proof_storage rejected=false',
                      'transport_schema_case rows=8', 'opening_schema_case rows=8', 'retained_output_immutable=true',
                      'ringct_hashx_root_transport_scope header_positive_checks=2',
                      'ringct_hashx_interior_opening_scope numerical_positive_checks=2',
                      'ringct_hashx_interior_opening_complete interior_opening_probe_complete=true',
                      'OPENCL_OPT_RESULT {}', 'DIRECT_RING_RESULT {}', 'fallback=true', 'retry=true',
                      'FAILED', "thread 'test' panicked at fixture:1", 'prefixringct_unknown complete=true'):
            with self.subTest(token=token), self.assertRaises(ValueError):
                guard.validate_log(fixture() + token + '\n', bound_plan())

    def test_independent_probe_and_complete_driver_claims_are_additive_and_required(self):
        for index, key, value in ((0, 'actual_opening_probes', 1), (0, 'cpu_heights', 17),
                (0, 'planned_opening_probes', 0), (0, 'probe_verifier_host_bytes', 0),
                (0, 'probe_caller_host_bytes', 64 << 10), (0, 'driver_host_bytes', 64 << 10),
                (0, 'probe_host_bytes', 1), (0, 'total_host_bytes', 1),
                (1, 'host_bytes', 1), (1, 'device_bytes', 1), (1, 'original_outer_sequence', 'false')):
            values = records()
            values[index][1][key] = value
            with self.subTest(index=index, key=key), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), bound_plan())
        for key in guard.gpu.ROOT_NUMBERS:
            for value in ('01', '-1', True, 1 << 64):
                values = records()
                values[0][1][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    guard.validate_log(fixture(values), bound_plan())

    def test_projection_must_use_original_remaining_quota_and_preserve_all_claims(self):
        for key, value in (('original_claims_host_bytes', 1), ('startup_host_bytes', guard.DEVICE),
                           ('startup_device_bytes', guard.STARTUP_DEVICE + 1), ('phase_wrappers_host_bytes', 0),
                           ('phase_wrappers_device_bytes', 1), ('pcs_host_bytes', guard.NATIVE_HOST + 1),
                           ('pcs_device_bytes', guard.DEVICE), ('simultaneous_host_bytes', guard.HOST - 1),
                           ('simultaneous_device_bytes', guard.DEVICE - 1), ('projection_ns', 0),
                           ('native_proofs', 1), ('recursive_proofs', 1), ('wrong_request_and_ledger_refused', 'false'),
                           ('original_claims_preserved', 'false'), ('physical_backend_fit', 'true'),
                           ('native_dispatch_started', 'true'), ('complete_ringct_workflow', 'true')):
            values = records()
            values[2][1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), bound_plan())
        values = records()
        values[2][1]['pcs_host_bytes'] -= 1
        values[2][1]['simultaneous_host_bytes'] -= 1
        with self.assertRaises(ValueError):
            guard.validate_log(fixture(values), bound_plan())

    def test_cleanup_observer_and_timing_remain_process_only(self):
        for key, value in (('current_host_bytes', 1), ('current_device_bytes', 1), ('component_success', 'true'),
                           ('peak_host_bytes', guard.HOST - 1), ('peak_host_bytes', guard.HOST + 1),
                           ('peak_device_bytes', guard.DEVICE - 1), ('component_through_destruction_ns', 19),
                           ('terminal_observer_fixed_host_bytes', 0),
                           ('terminal_observer_fixed_host_bytes', guard.gpu.OBSERVER_HOST_LIMIT + 1),
                           ('terminal_observer_scope', 'worker-ledger'), ('released_claims_cover_terminal_observer', 'true'),
                           ('process_engine_device_audit_complete', 'true'), ('artifact_roundtrip_complete', 'true')):
            values = records()
            values[3][1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), bound_plan())
        for observation in (None, True, 0, 799, 1000.0, 1 << 128):
            plan = bound_plan()
            plan['observation_before_validation_ns'] = observation
            with self.subTest(observation=observation), self.assertRaises(ValueError):
                guard.validate_log(fixture(), plan)

    def test_malformed_headers_numbers_fields_and_completion_are_rejected(self):
        for payload in ('ok', 'ignored', 'fixture', gpu_fixtures.GROWTH + ' extra=1'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                guard.validate_log(fixture(header_payload=payload), bound_plan())
        for old, new in (('\nok\n', '\n'), ('\nok\n', '\nok\nok\n'), ('1 passed;', '2 passed;'),
                         ('0 failed;', '1 failed;'), ('cpu_heights=18 ', 'cpu_heights=18 extra=1 '),
                         ('cpu_heights=18 ', 'cpu_heights=18 cpu_heights=18 '),
                         ('projection_ns=20', 'projection_ns=020'),
                         ('driver_host_bytes=262144', 'driver_host_bytes=18446744073709551616')):
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                guard.validate_log(fixture().replace(old, new), bound_plan())
        with self.assertRaises(ValueError):
            guard.validate_log(fixture() + ('x' * (16 << 20)), bound_plan())


    def test_capacity_cannot_claim_actual_restoration_consumption_or_boundary_probes(self):
        for index in range(4):
            for key in ('parent0_child_consumed', 'retained_output_restored', 'child_restoration_observed',
                        'parent_boundary_mutation_checks_complete', 'whole_graph_mutation_checks_complete'):
                values=records()
                values[index][1][key]='true'
                with self.subTest(index=index,key=key), self.assertRaises(ValueError):
                    guard.validate_log(fixture(values),bound_plan())


if __name__ == '__main__':
    unittest.main()
