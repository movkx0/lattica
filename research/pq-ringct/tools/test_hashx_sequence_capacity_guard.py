"""Reject contradictory source-only projection evidence without running a prover."""
import unittest
import hashx_sequence_capacity_guard as guard


def fixture(same_line=False):
    source_host = 1 << 30
    startup_host = (8 << 30) + (64 << 20)
    wrapper_host = 16 << 20
    source = dict(guard.SOURCE_FIXED, host_bytes=source_host, device_bytes=0)
    capacity = dict(guard.CAPACITY_FIXED, original_claims_host_bytes=source_host,
                    startup_host_bytes=startup_host, startup_device_bytes=guard.STARTUP_DEVICE,
                    phase_wrappers_host_bytes=wrapper_host, phase_wrappers_device_bytes=0,
                    pcs_host_bytes=guard.HOST - source_host - startup_host - wrapper_host,
                    pcs_device_bytes=guard.DEVICE - guard.STARTUP_DEVICE,
                    simultaneous_host_bytes=guard.HOST, simultaneous_device_bytes=guard.DEVICE,
                    projection_ns=100)
    terminal = dict(guard.TERMINAL_FIXED, peak_host_bytes=guard.HOST,
                    peak_device_bytes=guard.DEVICE, component_through_destruction_ns=200)
    lines = [
        'test ' + guard.SELECTOR + ' ... ',
        *(guard.PREFIX + name + ' ' + ' '.join(f'{key}={value}' for key, value in fields.items())
          for name, fields in [('source_claims', source), ('capacity_complete', capacity), ('terminal', terminal)]),
        'ok', 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 500 filtered out; finished in 0.01s', '']
    if same_line:
        lines[:2] = [lines[0] + lines[1]]
    return '\n'.join(lines)


class HashxSequenceCapacityGuardTests(unittest.TestCase):
    def test_exact_source_only_projection(self):
        result = guard.validate_log(fixture(), 300)
        self.assertEqual(result['native_proofs'], 0)
        self.assertTrue(result['original_quota_released'])
        for key in ('physical_backend_fit', 'complete_ringct_workflow', 'performance_qualified'):
            self.assertFalse(result[key])

    def test_first_marker_can_follow_exact_libtest_prefix(self):
        self.assertTrue(guard.validate_log(fixture(same_line=True), 300)['original_quota_released'])

    def test_refuses_changed_fields_and_limits(self):
        changes = [('native_outputs=10', 'native_outputs=9'), ('mode=capacity', 'mode=gpu'),
                   ('native_proofs=0', 'native_proofs=10'), ('physical_backend_fit=false', 'physical_backend_fit=true'),
                   ('component_success=true', 'component_success=false'),
                   ('mutation_checks_complete=false', 'mutation_checks_complete=true'),
                   ('artifact_roundtrip_complete=false', 'artifact_roundtrip_complete=true'),
                   ('current_host_bytes=0', 'current_host_bytes=1'),
                   ('original_claims_host_bytes=' + str(1 << 30), 'original_claims_host_bytes=101'),
                   ('startup_host_bytes=' + str((8 << 30) + (64 << 20)), 'startup_host_bytes=' + str((8 << 30) - 1)),
                   ('startup_device_bytes=' + str(guard.STARTUP_DEVICE), 'startup_device_bytes=301'),
                   ('phase_wrappers_device_bytes=0', 'phase_wrappers_device_bytes=1'),
                   ('phase_wrappers_host_bytes=' + str(16 << 20), 'phase_wrappers_host_bytes=0'),
                   ('peak_host_bytes=' + str(guard.HOST), 'peak_host_bytes=' + str(guard.HOST + 1)),
                   ('projection_ns=100', 'projection_ns=0'), ('projection_ns=100', 'projection_ns=201'),
                   ('projection_ns=100', 'projection_ns=0100'),
                   ('projection_ns=100', 'projection_ns=' + str(1 << 128)),
                   ('component_through_destruction_ns=200', 'component_through_destruction_ns=301'),
                   ('0 ignored;', '1 ignored;'), ('1 passed;', '2 passed;'),
                   (guard.SELECTOR, guard.SELECTOR + 'other')]
        for old, new in changes:
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                guard.validate_log(fixture().replace(old, new), 300)

    def test_refuses_missing_duplicate_reordered_and_foreign_evidence(self):
        lines = fixture().splitlines(True)
        invalid = [fixture() + lines[1], ''.join(lines[:1] + lines[2:]),
                   ''.join([lines[0], lines[2], lines[1], *lines[3:]]),
                   fixture() + 'proving_stage_report {}\n', fixture() + 'NATIVE_EXECUTION_RECEIPT {}\n',
                   fixture() + 'ringct_hashx_sequence_preissue_complete\n',
                   fixture() + lines[-1],
                   fixture().replace('host_bytes=' + str(1 << 30), 'host_bytes=100 extra=1', 1),
                   fixture().replace('host_bytes=' + str(1 << 30), 'host_bytes=100 host_bytes=100', 1),
                   fixture().replace('\nok\n', '\nFAILED\n'),
                   fixture().replace('\nok\n', '\n'),
                   fixture().replace('\nok\n', '\nok\nok\n'),
                   fixture() + 'test foreign::test ... ok\n',
                   fixture() + "thread 'test' panicked at source.rs:1\n",
                   fixture().replace(' ... \n', ' ... FAILED\n'),
                   fixture().replace(' ... \n', ' ... ok\n')]
        for content in invalid:
            with self.subTest(content=content), self.assertRaises(ValueError):
                guard.validate_log(content, 300)

    def test_refuses_consistently_underreported_original_quota(self):
        pcs = guard.HOST - (1 << 30) - ((8 << 30) + (64 << 20)) - (16 << 20)
        content = fixture().replace('pcs_host_bytes=' + str(pcs), 'pcs_host_bytes=' + str(pcs - 1))
        content = content.replace('simultaneous_host_bytes=' + str(guard.HOST),
                                  'simultaneous_host_bytes=' + str(guard.HOST - 1))
        content = content.replace('peak_host_bytes=' + str(guard.HOST),
                                  'peak_host_bytes=' + str(guard.HOST - 1))
        with self.assertRaises(ValueError):
            guard.validate_log(content, 300)

    def test_requires_runner_owned_integer_observation(self):
        for observation in (None, True, 0, -1, 300.0, 1 << 128):
            with self.subTest(observation=observation), self.assertRaises(ValueError):
                guard.validate_log(fixture(), observation)


if __name__ == '__main__':
    unittest.main()
