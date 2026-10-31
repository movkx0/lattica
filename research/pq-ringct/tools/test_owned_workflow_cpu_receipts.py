"""Synthetic receipt mutation tests; no fixture is cryptographic evidence."""
import copy
import unittest

from opencl_private_spend_validate import collect_gpu_receipts
from owned_workflow_case_receipts import validate as _validate
from test_owned_workflow_case_receipts import fixture, index_of, render


def validate(content, report, collect_gpu_receipts):
    return _validate(content, report, collect_gpu_receipts, verification_mode='existing-format-partial')


class CpuVerificationReceiptTests(unittest.TestCase):
    def audit(self, events, report):
        return validate(render(events), report, collect_gpu_receipts)['cpu_verification']

    def test_exact_epoch_coverage_is_separate_from_unavailable_identity_and_timing(self):
        for count in (3, 4):
            events, report = fixture(count)
            result = self.audit(events, report)
            self.assertEqual(result['coverage'], 'existing-format-partial')
            self.assertTrue(result['proof_epoch_coverage_complete'])
            self.assertEqual(result['recursive_proofs_verified'], count)
            self.assertEqual(result['recursive_proofs_with_cpu_timing'], count - 1)
            self.assertEqual(result['recursive_proofs_without_cpu_timing'], 1)
            self.assertEqual(result['known_cpu_verification_ns'], 12 * 300 + 2 * (count - 1) * 100 + 1000)
            self.assertEqual(result['final_stage_cpu_verification_ns'],
                             {'compile': (count - 1) * 100, 'outer': (count - 1) * 100, 'verify': 1000})
            self.assertIsNone(result['complete_cpu_verification_ns'])
            self.assertIsNone(result['nonfinal_recursive_cpu_verification_ns'])
            self.assertFalse(result['exact_dispatch_identity_coverage_complete'])
            self.assertFalse(result['source_member_request_identity_authenticated'])
            self.assertEqual(result['artifact_mutation_qualification_scope'], 'final-aggregate')

    def test_missing_duplicate_and_reordered_epochs_fail(self):
        for prefix in ('owned_source_native_epoch', 'owned_native_epoch', 'owned_outer_epoch',
                       'owned_group_epoch', 'owned_final_compile_epoch', 'owned_final_stage'):
            for mutation in ('missing', 'duplicate', 'reordered'):
                events, report = fixture()
                index = index_of(events, prefix)
                if mutation == 'missing':
                    del events[index]
                elif mutation == 'duplicate':
                    events.insert(index, copy.deepcopy(events[index]))
                else:
                    events[index], events[index - 1] = events[index - 1], events[index]
                with self.subTest(prefix=prefix, mutation=mutation), self.assertRaises(ValueError):
                    self.audit(events, report)

    def test_false_verification_and_unretired_epochs_fail(self):
        mutations = (
            lambda epoch: epoch.update(independent_verification_complete=False),
            lambda epoch: epoch.update(independent_verification_complete=1),
            lambda epoch: epoch['startup'].update(succeeded=False),
            lambda epoch: epoch['retirement'].update(managed_live_bytes=1),
            lambda epoch: epoch['retirement'].update(host_tree_live_bytes=1),
            lambda epoch: epoch['retirement'].update(lease_released=False),
            lambda epoch: epoch['retirement'].update(managed_peak_bytes=(8 << 30) + 1),
            lambda epoch: epoch['startup'].update(retained_tree_host_bytes=(32 << 30) + 1),
        )
        for prefix in ('owned_source_native_epoch', 'owned_outer_epoch'):
            for mutation in mutations:
                events, report = fixture()
                mutation(events[index_of(events, prefix)][1]['epoch'])
                with self.subTest(prefix=prefix, mutation=mutation), self.assertRaises(ValueError):
                    self.audit(events, report)

    def test_epoch_wrong_schema_and_native_family_fail(self):
        events, report = fixture()
        index = index_of(events, 'owned_source_native_epoch')
        events[index][0] = 'owned_sparse_native_epoch'
        with self.assertRaises(ValueError):
            self.audit(events, report)
        for schema in ('ringct-owned-outer-epoch-v1', 'ringct-owned-source-native-epoch-v2'):
            events, report = fixture()
            events[index_of(events, 'owned_source_native_epoch')][1]['schema'] = schema
            with self.subTest(schema=schema), self.assertRaises(ValueError):
                self.audit(events, report)

    def test_cpu_time_is_required_bounded_integer_and_not_proving_time(self):
        for invalid in (None, False, -1, 0.5, '1', 1 << 128):
            events, report = fixture()
            epoch = events[index_of(events, 'owned_source_native_epoch')][1]['epoch']
            epoch['cpu_verification_ns'] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.audit(events, report)
        events, report = fixture()
        events[index_of(events, 'owned_source_native_epoch')][1]['epoch']['proving_ns'] += 1
        with self.assertRaises(ValueError):
            self.audit(events, report)

    def test_local_ordinals_are_not_global_proof_identities(self):
        events, report = fixture()
        native = [value for prefix, value in events if prefix.endswith('_native_epoch')
                  or prefix == 'owned_native_epoch']
        self.assertGreater(len(native), 1)
        self.assertEqual({value['ordinal'] for value in native}, {0})
        result = self.audit(events, report)
        self.assertFalse(result['local_epoch_ordinals_used_as_global_identities'])

    def test_row_sequence_and_session_cannot_be_substituted(self):
        for key, invalid in (('sequence', 1), ('session_id', 11), ('entry_point', 'ringct_owned_native_aes')):
            events, report = fixture()
            events[index_of(events, 'owned_proof_rows')][1][key] = invalid
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.audit(events, report)

    def test_missing_cpu_time_is_not_filled_from_outer_setup_or_proving(self):
        events, report = fixture()
        value = events[index_of(events, 'owned_outer_epoch')][1]
        value['epoch']['cpu_verification_ns'] = 0
        with self.assertRaises(ValueError):
            self.audit(events, report)  # v1 does not promise or emit this field.

    def test_final_stage_identity_timing_and_summary_mutations_fail(self):
        for key, invalid in (('merge', 99), ('count', 1), ('first', 3),
                             ('active_rows', 99), ('padded_rows', 256),
                             ('compile_ns', 1), ('setup_ns', 0), ('proving_ns', 0)):
            events, report = fixture()
            outer = next(value for prefix, value in events
                         if prefix == 'owned_final_stage' and value['stage'] == 'outer')
            outer['report'][key] = invalid
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.audit(events, report)
        for key, invalid in (('final_cpu_verification_ns', 999), ('qualification_scope', 'all-children')):
            events, report = fixture()
            report[key] = invalid
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.audit(events, report)

    def test_final_qualification_is_not_credited_at_compile(self):
        events, report = fixture()
        stage = next(value for prefix, value in events
                     if prefix == 'owned_final_stage' and value['stage'] == 'compile')
        stage['report']['qualification']['artifact_round_trip'] = True
        with self.assertRaises(ValueError):
            self.audit(events, report)

    def test_unknown_epochs_and_mislabeled_json_fail(self):
        for prefix in ('owned_unknown_epoch', 'mystery_epoch', ''):
            events, report = fixture()
            index = index_of(events, 'owned_outer_epoch')
            events[index][0] = prefix
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                self.audit(events, report)

    def test_epoch_framing_and_duplicate_json_keys_fail(self):
        events, report = fixture()
        content = render(events)
        malformed = (
            content.replace('owned_outer_epoch ', 'owned_outer_epoch\t', 1),
            content.replace('owned_outer_epoch ', ' owned_outer_epoch ', 1),
            content.replace('owned_outer_epoch {', 'owned_outer_epoch {"ordinal": 0, ', 1),
        )
        for value in malformed:
            with self.subTest(value=value[:40]), self.assertRaises(ValueError):
                validate(value, report, collect_gpu_receipts)


if __name__ == '__main__':
    unittest.main()
