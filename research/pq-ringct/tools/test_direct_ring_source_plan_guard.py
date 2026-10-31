"""Synthetic source-audit policy tests; no device enumeration or proving."""
import copy
import json
import unittest

import direct_ring_source_plan_guard as guard
from test_direct_ring_screen_guard import arguments, runner


def args(**changes):
    selected = dict(profile='source-preflight', direct_ring_screen=False,
                    direct_ring_source_plan=True,
                    command=['/tmp/lattica_pq_direct_spend_research-recorded', guard.SELECTOR,
                             '--exact', '--ignored', '--test-threads=1', '--nocapture'])
    selected.update(changes)
    return arguments(**selected)


def records():
    small = dict(active_rows=1, padded_rows=1 << 19, wires=4, witness_values=0,
                 canonical_manifest_digest=[0] * 32, registered_program_id=[0] * 4)
    large = dict(small, padded_rows=1 << 20)
    common = dict(schema='direct-ring-source-plan-case-v1',
                  program_kind='four_public_empty_padded_shell', source_upper_bound_claimed=False)
    accepted = dict(common, actual_program=small, admitted=True, error=None,
                    footprint=dict(rows=1 << 19, main_columns=94, preprocessing_columns=200,
                                   managed_limit_bytes=8 * guard.GIB, context_reserve_bytes=4 * guard.GIB,
                                   worker_host_limit_bytes=32 * guard.GIB,
                                   device_phase_peak_bytes=7 * guard.GIB,
                                   device_phase_bound_complete=True, host_phase_bound_complete=True))
    message = 'complete source phase refused'
    refused = dict(common, actual_program=large, admitted=False, footprint=None,
                   error=dict(actual_program=large, core_error=message,
                              original_error_bytes=len(message), original_error_complete=True))
    terminal = dict(schema='direct-ring-source-plan-terminal-v1', cases=2, admitted=1, refused=1,
                    engine_report_absent_before=True, engine_report_absent_after=True,
                    public_hash_absent_before=True, public_hash_absent_after=True,
                    session_creation_attempts=0, cryptographic_proof_started=False)
    return [accepted, refused], terminal


def log(cases, terminal):
    return '\n'.join(['direct_ring_source_plan_case ' + json.dumps(case) for case in cases]
                     + ['direct_ring_source_plan_terminal ' + json.dumps(terminal),
                        'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;'])


class DirectSourcePlanGuardTests(unittest.TestCase):
    def test_shell_descriptor_is_exact(self):
        mutations = dict(active_rows=2, padded_rows=True, wires=5, witness_values=1,
                         canonical_manifest_digest=[1] + [0] * 31,
                         registered_program_id=[1, 0, 0, 0])
        for field, value in mutations.items():
            for index in (0, 1):
                cases, terminal = records()
                cases[index]['actual_program'][field] = value
                with self.subTest(field=field, index=index), self.assertRaises(ValueError):
                    guard.validate_log(log(cases, terminal))
        for field, value in (('active_rows', True), ('witness_values', False),
                             ('canonical_manifest_digest', [False] * 32),
                             ('registered_program_id', [False] * 4)):
            cases, terminal = records()
            cases[0]['actual_program'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                guard.validate_log(log(cases, terminal))

    def test_original_error_bytes_must_be_integer(self):
        cases, terminal = records()
        cases[1]['error']['original_error_bytes'] = float(cases[1]['error']['original_error_bytes'])
        with self.assertRaises(ValueError):
            guard.validate_log(log(cases, terminal))

    def test_exact_mode_preserves_source_only_limits(self):
        plan = runner.build_plan(args())
        self.assertEqual(plan['memory_max_bytes'], 8 * guard.GIB)
        self.assertEqual(plan['memory_high_bytes'], 6 * guard.GIB)
        self.assertEqual(plan['fresh_memavailable_required_bytes'], 10 * guard.GIB)
        self.assertFalse(plan['direct_ring_source_plan_environment']['gpu_dispatch'])
        self.assertEqual(plan['environment']['LATTICA_PROVING_POLICY'], 'gpu-required')
        self.assertEqual(plan['environment']['LATTICA_V2_GPU_MANAGED_BYTES'], str(8 * guard.GIB))

    def test_wrong_modes_selectors_and_execution_settings_refuse(self):
        for changes in (dict(profile='build'), dict(profile='full'), dict(expect_tests=False),
                        dict(build_label=None), dict(device_uuid=None), dict(expect_result=True),
                        dict(public_hash_kernel='sbox-pair-v1'), dict(retained_tree_storage='device'),
                        dict(active_hashx_preflight=True), dict(direct_ring_aggregate=True),
                        dict(command=args().command + ['--include-ignored'])):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner.build_plan(args(**changes))

    def test_complete_source_records_are_not_workflow_qualification(self):
        result = guard.validate_log(log(*records()))
        self.assertFalse(result['gpu_dispatch'])
        self.assertFalse(result['complete_workflow_qualified'])
        self.assertFalse(result['performance_qualified'])

    def test_missing_reordered_or_mutated_case_refuses(self):
        cases, terminal = records()
        bad = copy.deepcopy(cases)
        bad[0]['footprint']['managed_limit_bytes'] += 1
        for changed in (cases[:1], cases + cases[:1], cases[::-1], bad):
            with self.subTest(cases=changed), self.assertRaises(ValueError):
                guard.validate_log(log(changed, terminal))

    def test_truncated_error_or_runtime_evidence_refuses(self):
        cases, terminal = records()
        cases[1]['error']['original_error_complete'] = False
        with self.assertRaises(ValueError):
            guard.validate_log(log(cases, terminal))
        for marker in ('proving_stage_report', 'bounded_gpu_initialized', 'NATIVE_EXECUTION_RECEIPT'):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                guard.validate_log(log(*records()) + '\n' + marker)

    def test_failed_or_duplicate_terminal_refuses(self):
        cases, terminal = records()
        terminal['engine_report_absent_after'] = False
        with self.assertRaises(ValueError):
            guard.validate_log(log(cases, terminal))
        cases, terminal = records()
        with self.assertRaises(ValueError):
            guard.validate_log(log(cases, terminal) + '\ndirect_ring_source_plan_terminal ' + json.dumps(terminal))
