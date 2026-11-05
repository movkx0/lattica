"""The component guard must not accept missing work, CPU fallback or wider limits."""
import copy
import json
import unittest
from unittest.mock import patch

import native_quotient_screen as screen
import opencl_private_spend_validate as guard
from test_opencl_private_spend_validate import arguments


def measurements():
    rows = []
    shapes = [('aes', d, n, n * 1024) for n in (8, 64) for d in (17, 29)]
    shapes += [('affine', v, n, n * 512) for n in (8, 64) for v in range(4)]
    for round in range(2):
        for case, (family, variant, count, height) in enumerate(shapes):
            report = dict(schema='lattica-proving-stages-v1',
                          entry_point='pq_aes_lane_native' if family == 'aes' else 'ringct_native_quotient_affine_screen',
                          policy='gpu_required', succeeded=True, stage_coverage_complete=True,
                          completion_rejected=False, observation_errors=0, components=[], elapsed_ns=10,
                capabilities=dict(scope='proof_request', profile='block_v2_cubic', max_log_fri_arity=1),
                          observations=[dict(stage=s, backend='open_cl', calls=1, completed_calls=1,
                                             device_calls=1, device_ns=1) for s in sorted(screen.STAGES)])
            rows.append(dict(schema='ringct-native-quotient-screen-v1', round=round, case=case,
                             family=family, variant=variant, count=count, rows=height,
                             operation_host_bytes=24 << 30, proof_wall_ns=20, verification_ns=4,
                             verified=True, mutation_rejected=True, public_synthetic_inputs=True,
                             complete_workflow=False, report=report))
    return rows


def log(rows):
    return '\n'.join([*(screen.PREFIX + json.dumps(row) for row in rows), screen.COMPLETE,
                      'test result: ok. 1 passed; 0 failed; 0 ignored;'])


def options(**changes):
    values = dict(profile='full', expect_tests=True, native_quotient_screen=True,
                  command=['/tmp/lattica_pq_ringct_research-test', screen.SELECTOR,
                           '--exact', '--ignored', '--test-threads=1', '--nocapture'],
                  build_label='build', retained_tree_storage='host',
                  device_uuid='GPU-00000000-0000-0000-0000-000000000000')
    values.update(changes)
    return arguments(**values)


class NativeQuotientScreenTests(unittest.TestCase):
    def test_complete_native_proofs_are_component_evidence_only(self):
        accepted = screen.validate(log(measurements()))
        self.assertEqual(accepted['proofs'], 24)
        self.assertEqual(accepted['independent_cpu_verifications'], 24)
        self.assertFalse(accepted['complete_workflow_qualified'])

    def test_missing_reordered_mutated_and_incomplete_proofs_are_rejected(self):
        rows = measurements()
        variants = [rows[:-1], rows[::-1]]
        for key, value in [('complete_workflow', True), ('verified', False),
                           ('mutation_rejected', False), ('operation_host_bytes', 32 << 30),
                           ('rows', 1 << 20), ('proof_wall_ns', 9), ('verification_ns', 0)]:
            changed = copy.deepcopy(rows)
            changed[0][key] = value
            variants.append(changed)
        for changed in variants:
            with self.assertRaises(ValueError):
                screen.validate(log(changed))

    def test_missing_or_cpu_arithmetic_is_rejected(self):
        for change in ('cpu', 'missing', 'incomplete'):
            rows = measurements()
            observations = rows[0]['report']['observations']
            if change == 'cpu':
                observations[0]['backend'] = 'cpu'
            elif change == 'missing':
                observations.pop()
            else:
                observations[0]['completed_calls'] = 0
            with self.assertRaises(ValueError):
                screen.validate(log(rows))

    def test_partial_proof_scope_is_rejected(self):
        rows = measurements()
        rows[0]['report']['capabilities']['scope'] = 'operation'
        with self.assertRaisesRegex(ValueError, 'native proof profile'):
            screen.validate(log(rows))

    @patch.object(guard, 'identity_physical_cpus', return_value=list(range(16)))
    def test_exact_guard_pins_device_threads_and_existing_limits(self, _):
        plan = guard.build_plan(options())
        self.assertEqual(plan['cpu_quota'], '1600%')
        self.assertEqual(plan['identity_physical_cpus'], list(range(16)))
        self.assertEqual(plan['environment'][screen.ENVIRONMENT], '1')
        self.assertEqual(plan['environment']['RAYON_NUM_THREADS'], '8')
        self.assertEqual(plan['environment']['LATTICA_V2_GPU_MANAGED_BYTES'], str(8 << 30))
        self.assertEqual(plan['memory_max_bytes'], 47 << 30)
        for change in [dict(profile='smoke'), dict(device_uuid=None),
                       dict(retained_tree_storage='device'), dict(build_label=None),
                       dict(host_profile='expanded-36'), dict(identity_cpu_qualification=True),
                       dict(command=['/tmp/lattica_pq_ringct_research-test', 'wrong', '--exact',
                                     '--ignored', '--test-threads=1', '--nocapture'])]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                guard.build_plan(options(**change))


if __name__ == '__main__':
    unittest.main()
