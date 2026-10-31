"""Synthetic row audits; none of these fixtures qualifies a GPU workflow."""
import copy
import unittest

from opencl_private_spend_validate import collect_gpu_receipts
from owned_workflow_case_receipts import validate as _validate
from test_owned_workflow_case_receipts import fixture, render


def validate(content, report, collect_gpu_receipts):
    return _validate(content, report, collect_gpu_receipts, verification_mode='existing-format-partial')


class RowReceiptTests(unittest.TestCase):
    def setUp(self):
        self.events, self.report = fixture(3)

    def audit(self):
        return validate(render(self.events), self.report, collect_gpu_receipts)

    def row(self, recursive=False):
        return next(value for prefix, value in self.events
                    if prefix == 'owned_proof_rows'
                    and (value['entry_point'] == 'block_v2_registered_program') == recursive)

    def test_actual_native_padding_excludes_hiding_expansion(self):
        evidence = self.audit()['proof_rows']
        self.assertEqual(evidence['row_receipts'], 15)
        self.assertEqual(evidence['machine_rows'],
                         {'proofs': 3, 'active_rows': 300, 'padded_rows': 384})
        self.assertIs(evidence['native_active_rows_available'], False)
        self.row()['padded_rows'] *= 2
        with self.assertRaisesRegex(ValueError, 'hiding-expanded'):
            self.audit()

    def test_missing_duplicate_reordered_or_orphan_row(self):
        baseline = copy.deepcopy(self.events)
        index = next(i for i, event in enumerate(baseline) if event[0] == 'owned_proof_rows')
        for mutation in ('missing', 'duplicate', 'reordered', 'orphan'):
            with self.subTest(mutation=mutation):
                self.events = copy.deepcopy(baseline)
                if mutation == 'missing':
                    self.events.pop(index)
                elif mutation == 'duplicate':
                    self.events.insert(index, copy.deepcopy(self.events[index]))
                elif mutation == 'reordered':
                    self.events[index - 1], self.events[index] = self.events[index], self.events[index - 1]
                else:
                    self.events.append(copy.deepcopy(self.events[index]))
                with self.assertRaises(ValueError):
                    self.audit()

    def test_context_sequence_identity_schema_and_field_binding(self):
        for key, value in (('session_id', 11), ('sequence', 1), ('entry_point', 'wrong'),
                           ('schema', 'wrong'), ('unexpected', 0)):
            with self.subTest(key=key):
                self.setUp()
                self.row()[key] = value
                with self.assertRaises(ValueError):
                    self.audit()

    def test_invalid_native_rows_and_degree(self):
        for key, value in (('active_rows', 0), ('padded_rows', 0), ('padded_rows', 1000),
                           ('padded_rows', True), ('native_degree_bits', None),
                           ('native_degree_bits', 64), ('native_degree_bits', -1),
                           ('native_degree_bits', True)):
            with self.subTest(key=key, value=value):
                self.setUp()
                self.row()[key] = value
                with self.assertRaises(ValueError):
                    self.audit()

    def test_invalid_recursive_rows_and_native_degree(self):
        for key, value in (('active_rows', None), ('active_rows', 129), ('active_rows', -1),
                           ('active_rows', True), ('padded_rows', 4),
                           ('native_degree_bits', 8)):
            with self.subTest(key=key, value=value):
                self.setUp()
                self.row(True)[key] = value
                with self.assertRaises(ValueError):
                    self.audit()

    def test_fixed_snapshot_mutations_and_overflow(self):
        for kind, key, value in (('root', 'row_receipts', 14),
                                 ('machine', 'proofs', 4), ('machine', 'active_rows', 301),
                                 ('machine', 'padded_rows', 1 << 128),
                                 ('native', 'proofs', 0), ('native', 'active_rows', 0),
                                 ('native', 'padded_rows', 1025),
                                 ('native', 'proofs', True)):
            with self.subTest(kind=kind, key=key):
                self.setUp()
                owned = self.report['owned_observations']
                target = owned if kind == 'root' else owned['machine_rows'] if kind == 'machine' \
                    else owned['native_proofs'][0]['rows']
                target[key] = value
                with self.assertRaises(ValueError):
                    self.audit()

    def test_legacy_snapshot_cannot_claim_actual_rows(self):
        self.report['owned_observations']['schema'] = 'ringct-owned-workflow-observations-v1'
        with self.assertRaises(ValueError):
            self.audit()

    def test_preprocessing_cannot_receive_row_credit(self):
        index = next(i for i, (_, value) in enumerate(self.events)
                     if value.get('entry_point') == 'block_v2_preprocessing')
        self.events.insert(index + 1, ['owned_proof_rows', copy.deepcopy(self.row(True))])
        with self.assertRaises(ValueError):
            self.audit()

    def test_native_family_without_proofs_keeps_unavailable_active_rows(self):
        owned = self.report['owned_observations']
        item = owned['native_proofs'][0]
        entry = item['entry_point']
        self.events = [event for event in self.events if event[1].get('entry_point') != entry
                       and event[0] != 'owned_source_native_epoch']
        item['totals'] = {'reports': 0, 'elapsed_ns': 0}
        item['rows'] = {'proofs': 0, 'active_rows': None, 'padded_rows': 0}
        for sequence, row in enumerate(value for prefix, value in self.events
                                       if prefix == 'owned_proof_rows'):
            row['sequence'] = sequence
        owned['row_receipts'] -= 1
        self.report['native_proofs'] -= 1
        self.audit()
        item['rows']['active_rows'] = 0
        with self.assertRaises(ValueError):
            self.audit()

    def test_row_framing_duplicate_fields_and_noninteger_numbers(self):
        content = render(self.events)
        row = next(line for line in content.splitlines() if line.startswith('owned_proof_rows '))
        variants = [
            ' ' + row,
            row.replace('owned_proof_rows ', 'owned_proof_rows  ', 1),
            row.replace('owned_proof_rows ', 'owned_proof_rows\t', 1),
            row.replace('"sequence": 0', '"sequence": 0, "sequence": 0', 1),
            row.replace('"sequence": 0', '"sequence": 0.0', 1),
            row.replace('"sequence": 0', '"sequence": NaN', 1),
            row.replace('"sequence": 0', '"sequence": true', 1),
        ]
        for replacement in variants:
            with self.subTest(replacement=replacement):
                self.assertNotEqual(row, replacement)
                with self.assertRaises(ValueError):
                    validate(content.replace(row, replacement, 1), self.report, collect_gpu_receipts)

    def test_extra_row_schema_under_unknown_prefix_is_rejected(self):
        content = render(self.events)
        row = next(line for line in content.splitlines() if line.startswith('owned_proof_rows '))
        for extra in (row.replace('owned_proof_rows ', 'unknown ', 1), row.split(' ', 1)[1]):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                validate(content + '\n' + extra, self.report, collect_gpu_receipts)


if __name__ == '__main__':
    unittest.main()
