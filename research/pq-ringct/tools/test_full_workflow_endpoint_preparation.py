"""Synthetic receipt checks only; no source plan, proof, or GPU is executed."""
import copy
import unittest

from opencl_private_spend_validate import collect_gpu_receipts
from owned_workflow_case_receipts import validate
from test_owned_workflow_case_receipts import fixture, receipt, render, totals
from test_owned_workflow_verification_receipts import enrich


class EndpointPreparationReceiptTests(unittest.TestCase):
    def extended(self, count):
        events, report = enrich(*fixture(count))
        baseline = copy.deepcopy(report)
        extras = [['proving_stage_report', receipt('pq_graph_witness_preparation', 2_000_000 + i)]
                  for i in range(count + 5)]
        first_inventory = next(i for i, (prefix, value) in enumerate(events)
                               if prefix == 'owned_dispatch_verification' and value['stage'] == 'inventory')
        events[first_inventory:first_inventory] = extras
        delta = totals([body for _, body in extras])
        source = report['source_preparation']
        for name in ('calls', 'succeeded', 'complete_reports'):
            source[name] += delta['reports']
        for name in ('witness_completed_calls', 'witness_device_calls', 'witness_device_ns'):
            source[name] += delta[name]
        source['seconds'] += delta['elapsed_ns'] / 1e9
        report['generation_and_planning_ns'] += delta['elapsed_ns']
        return events, report, baseline, delta, first_inventory

    def validate(self, events, report):
        return validate(render(events), report, collect_gpu_receipts,
                        verification_mode='exact-dispatch-v1')

    def test_n3_n4_extra_endpoint_preparation_is_setup_not_proof_credit(self):
        for count in (3, 4):
            with self.subTest(count=count):
                events, report, baseline, delta, _ = self.extended(count)
                accepted = self.validate(events, report)
                self.assertEqual(accepted['source_preparation']['reports'], count + delta['reports'])
                self.assertEqual(accepted['gpu_receipts']['native_reports'], baseline['native_proofs'])
                for name in ('native_proofs', 'recursive_proofs', 'generation',
                             'owned_observations', 'proving_and_verification_ns'):
                    self.assertEqual(report[name], baseline[name])
                self.assertEqual(report['generation_and_planning_ns'],
                                 baseline['generation_and_planning_ns'] + delta['elapsed_ns'])

    def test_each_stale_source_counter_rejects_extra_reports(self):
        for count in (3, 4):
            for name in ('calls', 'succeeded', 'complete_reports',
                         'witness_completed_calls', 'witness_device_calls', 'witness_device_ns'):
                with self.subTest(count=count, counter=name):
                    events, report, baseline, _, _ = self.extended(count)
                    report['source_preparation'][name] = baseline['source_preparation'][name]
                    with self.assertRaises(ValueError):
                        self.validate(events, report)

    def test_stale_source_time_rejects_actual_additional_setup(self):
        for count in (3, 4):
            with self.subTest(count=count):
                events, report, baseline, _, _ = self.extended(count)
                report['source_preparation']['seconds'] = baseline['source_preparation']['seconds']
                with self.assertRaises(ValueError):
                    self.validate(events, report)

    def test_endpoint_preparation_after_inventory_is_refused_with_matching_totals(self):
        for count in (3, 4):
            with self.subTest(count=count):
                events, report, _, _, first_extra = self.extended(count)
                moved = events.pop(first_extra)
                first_inventory = next(i for i, (prefix, value) in enumerate(events)
                                       if prefix == 'owned_dispatch_verification' and value['stage'] == 'inventory')
                events.insert(first_inventory + 1, moved)
                with self.assertRaises(ValueError):
                    self.validate(events, report)

    def test_cpu_or_empty_gpu_endpoint_receipt_is_refused(self):
        for count in (3, 4):
            for mutation in ('cpu_policy', 'no_device_calls'):
                with self.subTest(count=count, mutation=mutation):
                    events, report, _, _, first_extra = self.extended(count)
                    value = events[first_extra][1]
                    if mutation == 'cpu_policy':
                        value['policy'] = 'cpu_required'
                    else:
                        observation = value['observations'][0]
                        report['source_preparation']['witness_device_calls'] -= observation['device_calls']
                        report['source_preparation']['witness_device_ns'] -= observation['device_ns']
                        observation['device_calls'] = 0
                        observation['device_ns'] = 0
                    with self.assertRaises(ValueError):
                        self.validate(events, report)

    def test_endpoint_reports_cannot_inflate_native_or_recursive_proofs(self):
        for count in (3, 4):
            for name in ('native_proofs', 'recursive_proofs'):
                with self.subTest(count=count, counter=name):
                    events, report, _, delta, _ = self.extended(count)
                    report[name] += delta['reports']
                    with self.assertRaises(ValueError):
                        self.validate(events, report)


if __name__ == '__main__':
    unittest.main()
