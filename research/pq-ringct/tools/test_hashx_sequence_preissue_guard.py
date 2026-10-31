"""Evidence and authority boundaries for the proofless physical-source mode."""
from copy import deepcopy
from types import SimpleNamespace
import unittest

import hashx_sequence_preissue_guard as guard

ROOT = '/tmp/recorded-ringct'
UUID = 'GPU-00000000-1111-2222-3333-444444444444'
COMMAND = [ROOT + '/target/lattica_pq_ringct_research-recorded', guard.SELECTOR,
           '--exact', '--ignored', '--test-threads=1', '--nocapture']


def arguments(**changes):
    result = dict(owned_hashx_sequence_test='preissue', command=list(COMMAND), profile='full',
                  expect_tests=True, build_label='recorded-build', device_uuid=UUID)
    result.update(changes)
    return SimpleNamespace(**result)


def base_environment():
    result = guard.expected_environment(ROOT, UUID)
    result.pop(guard.FLAG)
    result.pop('LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES')
    result['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'device'
    return result


def bound_plan():
    environment = guard.expected_environment(ROOT, UUID)
    sources = {path: 'a' * 64 for path in guard.REQUIRED_SOURCES}
    executable = dict(path=COMMAND[0], resolved_path=COMMAND[0], sha256='b' * 64,
                      build_record=ROOT + '/.tools/pq-opencl-opt/runs/recorded-build.json',
                      build_record_sha256='c' * 64)
    plan = dict(command=list(COMMAND), environment=environment,
                owned_hashx_sequence_environment=guard.receipt(environment),
                profile='full', expect_tests=True, memory_max_bytes=47 * guard.GIB,
                memory_high_bytes=45 * guard.GIB, fresh_memavailable_required_bytes=49 * guard.GIB,
                cpu_quota='800%', benchmark=False, public_hash_kernel='baseline',
                expect_result=False, expect_direct_result=False, correctness_label=None,
                record_artifacts=[], runtime_seconds=3600, build_label='recorded-build',
                input_sha256=sources, executable_provenance=executable,
                observation_before_validation_ns=300)
    plan['owned_hashx_sequence_binding'] = guard.bind_execution(plan, sources, executable, ROOT)
    return plan


def fixture(same_line=False):
    records = [('source_claims', dict(guard.SOURCE_FIXED, host_bytes=9 * guard.GIB, device_bytes=0)),
               ('preissue_complete', dict(guard.PREISSUE_FIXED, host_bytes=guard.HOST, device_bytes=guard.DEVICE)),
               ('terminal', dict(guard.TERMINAL_FIXED, peak_host_bytes=guard.HOST,
                                 peak_device_bytes=guard.DEVICE, component_through_destruction_ns=200))]
    lines = ['test ' + guard.SELECTOR + ' ... ',
             *(guard.PREFIX + name + ' ' + ' '.join(f'{key}={value}' for key, value in record.items())
               for name, record in records),
             'ok', 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 500 filtered out; finished in 0.01s', '']
    if same_line:
        lines[:2] = [lines[0] + lines[1]]
    return '\n'.join(lines)


class HashxSequencePreissueGuardTests(unittest.TestCase):
    def test_exact_environment_and_command(self):
        environment, receipt = guard.build_environment(arguments(), base_environment(), ROOT, 'baseline', 'host')
        self.assertEqual(environment, guard.expected_environment(ROOT, UUID))
        self.assertEqual(receipt, guard.receipt(environment))
        self.assertEqual(environment[guard.FLAG], '1')
        self.assertEqual(environment['LATTICA_PROVING_POLICY'], 'gpu-required')
        self.assertEqual(environment['LATTICA_GPU_DEVICE_UUID'], UUID)
        self.assertEqual(environment['LATTICA_V2_GPU_MANAGED_BYTES'], str(8 * guard.GIB))
        self.assertEqual(environment['LATTICA_V2_GPU_CONTEXT_BYTES'], str(4 * guard.GIB))
        self.assertEqual(environment['LATTICA_V2_HOST_OUTPUT_BYTES'], str(24 * guard.GIB))
        for key in ('LATTICA_OWNED_HASHX_FIRST_LEAF_QUALIFICATION',
                    'LATTICA_OWNED_HASHX_SEQUENCE_SOURCE_QUALIFICATION',
                    'LATTICA_OWNED_HASHX_SEQUENCE_REFUSAL_QUALIFICATION'):
            self.assertNotIn(key, environment)
        self.assertEqual(guard.build_environment(arguments(command=['--', *COMMAND]),
                         base_environment(), ROOT, 'baseline', 'host'), (environment, receipt))

    def test_refuses_siblings_foreign_modes_and_environment_drift(self):
        changed_commands = [COMMAND + ['--skip', guard.SELECTOR], COMMAND[:-1],
                            [COMMAND[0], guard.SELECTOR + 'other', *COMMAND[2:]],
                            ['/tmp/lattica_prover_p3-recorded', *COMMAND[1:]]]
        for suffix in ('cpu_original_hashx_sequence_capacity',
                       'gpu_original_hashx_sequence_source_authenticated',
                       'gpu_original_hashx_sequence_refusal_after_preissue',
                       'gpu_original_hashx_sequence_refusal_before_first_start',
                       'gpu_original_hashx_sequence_refusal_after_first_producer',
                       'gpu_original_hashx_sequence_refusal_after_first_acceptance'):
            changed_commands.append([COMMAND[0], guard.SELECTOR.rsplit('::', 1)[0] + '::' + suffix, *COMMAND[2:]])
        for command in changed_commands:
            with self.subTest(command=command), self.assertRaises(ValueError):
                guard.build_environment(arguments(command=command), base_environment(), ROOT, 'baseline', 'host')
        for changes in ({'owned_hashx_sequence_test': 'gpu'}, {'profile': 'direct-full'},
                        {'profile': 'research-compile-large'}, {'expect_tests': False},
                        {'build_label': None}, {'device_uuid': None},
                        *({key: True} for key in guard.EXCLUSIVE)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                guard.build_environment(arguments(**changes), base_environment(), ROOT, 'baseline', 'host')
        for kernel, storage in [('sbox-pair-v1', 'host'), ('baseline', 'device')]:
            with self.subTest(kernel=kernel, storage=storage), self.assertRaises(ValueError):
                guard.build_environment(arguments(), base_environment(), ROOT, kernel, storage)
        for key, value in [('EXTRA', '1'), ('RAYON_NUM_THREADS', '16'), (guard.FLAG, '1')]:
            changed = dict(base_environment(), **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                guard.build_environment(arguments(), changed, ROOT, 'baseline', 'host')

    def test_binding_rejects_resource_environment_source_and_build_drift(self):
        baseline = bound_plan()
        changes = [('memory_max_bytes', 48 * guard.GIB), ('memory_high_bytes', 46 * guard.GIB),
                   ('fresh_memavailable_required_bytes', 48 * guard.GIB), ('cpu_quota', '900%'),
                   ('profile', 'direct-full'), ('benchmark', True), ('expect_result', True),
                   ('expect_direct_result', True), ('record_artifacts', ['/tmp/unrelated']),
                   ('owned_hashx_leaf_environment', {}), ('runtime_seconds', True)]
        for key, value in changes:
            plan = deepcopy(baseline)
            plan[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                guard.bind_execution(plan, plan['input_sha256'], plan['executable_provenance'], ROOT)
        for key, value in [('LATTICA_GPU_DEVICE_UUID', 'GPU-invalid'), ('RAYON_NUM_THREADS', '4'),
                           ('LATTICA_V2_GPU_RETAINED_TREE_STORAGE', 'device'), ('EXTRA', '1')]:
            plan = deepcopy(baseline)
            plan['environment'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                guard.bind_execution(plan, plan['input_sha256'], plan['executable_provenance'], ROOT)
        for key, value in [('path', '/tmp/other'), ('sha256', 'bad'), ('resolved_path', '../other'),
                           ('build_record', ROOT + '/wrong.json'), ('build_record_sha256', 'bad')]:
            plan = deepcopy(baseline)
            plan['executable_provenance'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                guard.bind_execution(plan, plan['input_sha256'], plan['executable_provenance'], ROOT)
        for path, value in [('../escape', 'a' * 64), ('/absolute', 'a' * 64), ('bad-sha', 'bad')]:
            plan = deepcopy(baseline)
            plan['input_sha256'][path] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                guard.bind_execution(plan, plan['input_sha256'], plan['executable_provenance'], ROOT)
        plan = deepcopy(baseline)
        plan['input_sha256'].pop(guard.REQUIRED_SOURCES[0])
        with self.assertRaises(ValueError):
            guard.bind_execution(plan, plan['input_sha256'], plan['executable_provenance'], ROOT)
        plan = deepcopy(baseline)
        plan['owned_hashx_sequence_environment']['dispatch_authority'] = True
        with self.assertRaises(ValueError):
            guard.bind_execution(plan, plan['input_sha256'], plan['executable_provenance'], ROOT)

    def test_valid_preissue_is_proofless_and_has_no_workflow_credit(self):
        for same_line in (False, True):
            result = guard.validate_log(fixture(same_line), bound_plan())
            self.assertTrue(result['source_backend_preissue_complete'])
            self.assertTrue(result['owner_quota_cleanup_complete'])
            self.assertEqual((result['native_proofs'], result['recursive_proofs'], result['stage_receipts']), (0, 0, 0))
            for key in ('actual_proving_fit', 'native_dispatch_started', 'process_engine_device_audit_complete',
                        'mutation_checks_complete', 'artifact_roundtrip_complete',
                        'complete_ringct_workflow', 'performance_qualified'):
                self.assertFalse(result[key])
        growth = 'bounded_proof_input_growth old_values=0 new_values=4 live_bytes=32 value_limit=1048576'
        self.assertTrue(guard.validate_log(fixture().replace(' ... \n', ' ... ' + growth + '\n'),
                                         bound_plan())['source_backend_preissue_complete'])

    def test_rejects_coherent_host_underreport_and_invalid_header_diagnostics(self):
        records = fixture().replace('host_bytes=' + str(9 * guard.GIB), 'host_bytes=1')
        records = records.replace('host_bytes=' + str(guard.HOST), 'host_bytes=1')
        with self.assertRaises(ValueError):
            guard.validate_log(records, bound_plan())
        source = 9 * guard.GIB
        short = source + 8 * guard.GIB - 1
        records = fixture().replace('host_bytes=' + str(guard.HOST), 'host_bytes=' + str(short))
        with self.assertRaises(ValueError):
            guard.validate_log(records, bound_plan())
        for payload in ('failed', 'ignored', 'ok', 'fixture',
                        'bounded_proof_input_growth old_values=0 new_values=4 live_bytes=31 value_limit=1048576',
                        'bounded_proof_input_growth old_values=00 new_values=4 live_bytes=32 value_limit=1048576',
                        'bounded_proof_input_growth old_values=4 new_values=9 live_bytes=104 value_limit=1048576',
                        'bounded_proof_input_growth old_values=0 new_values=4 live_bytes=32 value_limit=1048577',
                        'bounded_proof_input_growth old_values=0 new_values=4 live_bytes=32 value_limit=1048576 extra=1'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                guard.validate_log(fixture().replace(' ... \n', ' ... ' + payload + '\n'), bound_plan())

    def test_parser_rechecks_original_binding_and_observation(self):
        for field in ('source_manifest_sha256', 'environment_sha256', 'executable_sha256',
                      'build_record_sha256', 'selected_physical_device_uuid', 'selector'):
            plan = bound_plan()
            plan['owned_hashx_sequence_binding'][field] = 'changed'
            with self.subTest(field=field), self.assertRaises(ValueError):
                guard.validate_log(fixture(), plan)
        for section, key in [('input_sha256', guard.REQUIRED_SOURCES[0]),
                             ('executable_provenance', 'sha256')]:
            plan = bound_plan()
            plan[section][key] = 'd' * 64
            with self.subTest(section=section), self.assertRaises(ValueError):
                guard.validate_log(fixture(), plan)
        for observation in (None, True, 0, -1, 300.0, 199, 1 << 128):
            plan = bound_plan()
            plan['observation_before_validation_ns'] = observation
            with self.subTest(observation=observation), self.assertRaises(ValueError):
                guard.validate_log(fixture(), plan)

    def test_rejects_counts_flags_limits_and_noncanonical_numbers(self):
        changes = [('native_outputs=10', 'native_outputs=9'), ('mode=preissue', 'mode=gpu'),
                   ('native_proofs=0', 'native_proofs=10'), ('recursive_proofs=0', 'recursive_proofs=1'),
                   ('outer_source_backends=9', 'outer_source_backends=8'),
                   ('original_successor_backends=8', 'original_successor_backends=7'),
                   ('actual_proving_fit=false', 'actual_proving_fit=true'),
                   ('component_success=true', 'component_success=false'),
                   ('current_host_bytes=0', 'current_host_bytes=1'),
                   ('current_device_bytes=0', 'current_device_bytes=1'),
                   ('device_bytes=0', 'device_bytes=1'),
                   ('peak_host_bytes=' + str(guard.HOST), 'peak_host_bytes=' + str(guard.HOST - 1)),
                   ('peak_device_bytes=' + str(guard.DEVICE), 'peak_device_bytes=' + str(guard.DEVICE + 1)),
                   ('component_through_destruction_ns=200', 'component_through_destruction_ns=0'),
                   ('component_through_destruction_ns=200', 'component_through_destruction_ns=0200'),
                   ('component_through_destruction_ns=200', 'component_through_destruction_ns=' + str(1 << 128)),
                   ('host_bytes=' + str(guard.HOST), 'host_bytes=' + str(1 << 64)),
                   ('mutation_checks_complete=false', 'mutation_checks_complete=true'),
                   ('artifact_roundtrip_complete=false', 'artifact_roundtrip_complete=true'),
                   ('complete_ringct_workflow=false', 'complete_ringct_workflow=true'),
                   ('1 passed;', '2 passed;'), ('0 ignored;', '1 ignored;')]
        for old, new in changes:
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                guard.validate_log(fixture().replace(old, new), bound_plan())

    def test_rejects_missing_duplicate_reordered_and_foreign_evidence(self):
        content = fixture()
        lines = content.splitlines(True)
        invalid = [content + lines[1], ''.join(lines[:1] + lines[2:]),
                   ''.join([lines[0], lines[2], lines[1], *lines[3:]]),
                   content.replace('\nok\n', '\n'), content.replace('\nok\n', '\nFAILED\n'),
                   content.replace('\nok\n', '\nok\nok\n'),
                   content.replace(' ... \n', ' ... ok\n'), content + lines[-1],
                   content + 'test foreign::test ... ok\n', content + "thread 'test' panicked at file:1\n",
                   content.replace('host_bytes=' + str(9 * guard.GIB), 'host_bytes=1 extra=1', 1),
                   content.replace('host_bytes=' + str(9 * guard.GIB), 'host_bytes=1 host_bytes=1', 1)]
        invalid += [content + token + '\n' for token in (
            'proving_stage_report {}', 'NATIVE_EXECUTION_RECEIPT {}', 'PUBLIC_HASH_EXECUTION {}',
            'OPENCL_OPT_RESULT {}', 'DIRECT_SPEND_RESULT {}', 'DIRECT_RING_RESULT {}',
            'ringct_hashx_sequence_complete', 'ringct_hashx_sequence_capacity_complete',
            'ringct_hashx_sequence_returned_refusal_complete',
            'ringct_hashx_first_leaf_complete native_proofs=10',
            'ringct_native_sequence_complete native_proofs=3',
            'ringct_parent_acceptance_complete source_key_authenticated=true',
            'ringct_unknown_evidence complete=true')]
        for text in invalid:
            with self.subTest(content=text), self.assertRaises(ValueError):
                guard.validate_log(text, bound_plan())


if __name__ == '__main__':
    unittest.main()
