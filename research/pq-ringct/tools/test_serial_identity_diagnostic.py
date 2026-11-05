import json
import unittest
from unittest.mock import patch

import serial_identity_diagnostic as diagnostic
import opencl_private_spend_validate as guard
from test_opencl_private_spend_validate import arguments


def log():
    lines = []
    for i in range(5):
        report = dict(schema='lattica-proving-stages-v1', entry_point='block_v2_registered_program',
                      policy='gpu_required', succeeded=True, stage_coverage_complete=True,
                      completion_rejected=False, observation_errors=0, components=[], elapsed_ns=50,
                      capabilities=dict(scope='registered_proof'),
                      observations=[dict(stage=stage, backend='open_cl', calls=1, completed_calls=1,
                                         device_calls=1, device_ns=1) for stage in sorted(diagnostic.STAGES)])
        lines.extend([
            f'SERIAL_IDENTITY_BEGIN {i}',
            'bounded_cpu_identity_hash fields=100 count_ns=10 hash_and_framing_ns=90 total_ns=100',
            f'SERIAL_IDENTITY_END {i}',
            diagnostic.PREFIX + json.dumps({
                'schema': 'ringct-serial-cpu-identity-diagnostic-v1',
                'program': i, 'height': 1 << 17, 'public_values': 46, 'registration_ns': 1000,
                'cpu_identity_ns': 110, 'gpu_preprocessing_ns': 800,
                'identity': [1, 2, 3, 4], 'gpu_reference_checked': i == 0,
                'independent_cpu_verified_proof': i < 2,
                'changed_public_rejected': i < 2, 'complete_workflow': False,
                'proof_wall_ns': 100 if i < 2 else None,
                'verification_ns': 10 if i < 2 else None,
                'proof_report': report if i < 2 else None,
            }),
        ])
    lines.append(diagnostic.COMPLETE)
    return '\n'.join(lines)


def options(**changes):
    values = dict(profile='full', expect_tests=True, serial_identity_diagnostic=True,
                  command=['/tmp/lattica_pq_ringct_research-test', diagnostic.SELECTOR,
                           '--exact', '--ignored', '--test-threads=1', '--nocapture'],
                  build_label='build', retained_tree_storage='host',
                  device_uuid='GPU-00000000-0000-0000-0000-000000000000')
    values.update(changes)
    return arguments(**values)


class SerialIdentityDiagnosticTests(unittest.TestCase):
    def test_reconciled_component_clocks(self):
        result = diagnostic.validate(log())
        self.assertEqual(result['count_ns'], 50)
        self.assertEqual(result['hash_and_framing_ns'], 450)
        self.assertEqual(result['count_fraction'], .1)
        self.assertFalse(result['performance_qualified'])
        self.assertFalse(result['complete_workflow'])

    def test_compiled_out_missing_or_duplicate_clocks_fail(self):
        text = log()
        clock = text.splitlines()[1]
        for replacement in ('', clock + '\n' + clock):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                diagnostic.validate(text.replace(clock, replacement, 1))

    def test_rejects_bad_order_clock_or_proof_evidence(self):
        for old, new in [
            ('SERIAL_IDENTITY_END 0', 'SERIAL_IDENTITY_END 1'),
            ('SERIAL_IDENTITY_BEGIN 0', 'SERIAL_IDENTITY_BEGIN 1'),
            ('total_ns=100', 'total_ns=99'),
            ('"registration_ns": 1000', '"registration_ns": 99'),
            ('"cpu_identity_ns": 110', '"cpu_identity_ns": 99'),
            ('"gpu_preprocessing_ns": 800', '"gpu_preprocessing_ns": 1000'),
            ('"public_values": 46', '"public_values": 1'),
            ('"changed_public_rejected": true', '"changed_public_rejected": false'),
            ('"gpu_reference_checked": true', '"gpu_reference_checked": false'),
            ('"identity": [1, 2, 3, 4]', '"identity": [18446744069414584321, 2, 3, 4]'),
            ('"complete_workflow": false', '"complete_workflow": true'),
            ('"backend": "open_cl"', '"backend": "cpu"'),
            ('"completed_calls": 1', '"completed_calls": 0'),
            ('"elapsed_ns": 50', '"elapsed_ns": 101'),
            (diagnostic.COMPLETE, ''),
        ]:
            with self.subTest(old=old), self.assertRaises(ValueError):
                diagnostic.validate(log().replace(old, new, 1))

    @patch.object(guard, 'identity_physical_cpus', return_value=list(range(16)))
    def test_guard_sets_diagnostic_and_preserves_resource_bounds(self, _):
        plan = guard.build_plan(options())
        self.assertTrue(plan['serial_identity_diagnostic'])
        self.assertEqual(plan['environment']['LATTICA_RINGCT_FULL_WORKFLOW_PROFILE'], 'detail')
        self.assertEqual(plan['environment']['RAYON_NUM_THREADS'], '8')
        self.assertEqual(plan['memory_max_bytes'], 47 << 30)
        self.assertEqual(plan['cpu_quota'], '1600%')
        self.assertFalse(plan['performance_qualified'])
        for changes in ({'profile': 'smoke'}, {'device_uuid': None},
                        {'retained_tree_storage': 'device'},
                        {'identity_cpu_qualification': True},
                        {'command': ['/tmp/lattica_pq_ringct_research-test', 'unrelated',
                                     '--exact', '--ignored', '--test-threads=1', '--nocapture']}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                guard.build_plan(options(**changes))


if __name__ == '__main__':
    unittest.main()
