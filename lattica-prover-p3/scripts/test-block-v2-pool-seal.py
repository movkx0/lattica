#!/usr/bin/env python3
"""Clock/application ordering fixtures, not cryptographic proving evidence."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import block_v2_pool_seal as S


class SealContracts(unittest.TestCase):
    def setUp(self):
        self.boot = '01234567-89ab-cdef-0123-456789abcdef'
        self.workflow = {'schema_version': 1, 'boot_id': self.boot, 'started_monotonic_ms': 100000,
                         'deadline_monotonic_ms': 700000}
        with patch.object(S.T, 'workflow_clock', return_value=(self.boot, 200000)):
            self.seal = S.issue(self.workflow)

    def test_original_seal_clock_and_workflow_both_bound_completion(self):
        self.assertEqual(S.check(self.seal, self.workflow, clock=(self.boot, 379999)), 179999)
        for now in [199999, 380000, 700000]:
            with self.subTest(now=now), self.assertRaises(ValueError):
                S.check(self.seal, self.workflow, clock=(self.boot, now))
        with patch.object(S.T, 'workflow_clock', return_value=(self.boot, 690000)):
            near_end = S.issue(self.workflow)
        self.assertEqual(near_end['deadline_monotonic_ms'], 700000)
        self.assertEqual(S.check(near_end, self.workflow, clock=(self.boot, 699999)), 9999)
        with self.assertRaises(ValueError):
            S.check(near_end, self.workflow, clock=(self.boot, 700000))

    def test_clock_rejects_reboot_renewed_horizon_and_malformed_integer_fields(self):
        with self.assertRaises(ValueError):
            S.check(self.seal, self.workflow, clock=('00000000-0000-0000-0000-000000000000', 200001))
        for key, value in [('schema_version', True), ('sealed_monotonic_ms', True),
                           ('deadline_monotonic_ms', 380001), ('sealed_monotonic_ms', 200001),
                           ('pool_workflow', self.workflow | {'started_monotonic_ms': 100001}),
                           ('unexpected', 0)]:
            changed = copy.deepcopy(self.seal)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                S.check(changed, self.workflow, clock=(self.boot, 210000))

    def fixture(self):
        operations = []
        receipt = {'head_token': 'new-head', 'generation': 1}
        candidate = SimpleNamespace(binding={'native': 'checked'})
        candidate.apply = Mock(side_effect=lambda *args: (operations.append('apply'), receipt)[1])
        intake = SimpleNamespace(
            check_selection=Mock(return_value={'pool_seal': self.seal}),
            record_application=Mock(side_effect=lambda *args: operations.append('record')),
            verify_recorded_application=Mock(side_effect=lambda *args: operations.append('replay')))
        return intake, candidate, operations, receipt

    def test_deadline_covers_application_durable_intake_publication_and_replay(self):
        intake, candidate, operations, receipt = self.fixture()
        with patch.object(S.T, 'workflow_clock', side_effect=[(self.boot, 201000), (self.boot, 201001), (self.boot, 201010)]):
            result = S.apply(intake, candidate, 'selection', '/root-proof', self.workflow, self.seal)
        self.assertEqual(operations, ['apply', 'record', 'replay'])
        self.assertTrue(result['native_applied'] and result['post_seal_deadline_met'])
        self.assertEqual(result['application'], receipt)
        self.assertEqual(result['completed_post_seal_ms'], 1010)

    def test_late_success_is_reported_as_applied_with_a_missed_deadline(self):
        intake, candidate, operations, receipt = self.fixture()
        with patch.object(S.T, 'workflow_clock', side_effect=[(self.boot, 201000), (self.boot, 201001), (self.boot, 380000)]):
            result = S.apply(intake, candidate, 'selection', '/root-proof', self.workflow, self.seal)
        self.assertEqual(operations, ['apply', 'record', 'replay'])
        self.assertTrue(result['native_applied'])
        self.assertFalse(result['post_seal_deadline_met'])
        self.assertEqual(result['application'], receipt)

    def test_expired_or_substituted_selection_cannot_begin_native_application(self):
        intake, candidate, operations, _ = self.fixture()
        with patch.object(S.T, 'workflow_clock', return_value=(self.boot, 380000)), self.assertRaises(ValueError):
            S.apply(intake, candidate, 'selection', '/root-proof', self.workflow, self.seal)
        candidate.apply.assert_not_called()
        changed = copy.deepcopy(self.seal)
        changed['sealed_monotonic_ms'] += 1
        changed['deadline_monotonic_ms'] += 1
        with patch.object(S.T, 'workflow_clock', return_value=(self.boot, 210000)), self.assertRaisesRegex(ValueError, 'changed the original'):
            S.apply(intake, candidate, 'selection', '/root-proof', self.workflow, changed)
        self.assertEqual(operations, [])


if __name__ == '__main__':
    unittest.main()
