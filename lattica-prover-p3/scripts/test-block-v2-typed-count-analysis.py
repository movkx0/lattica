#!/usr/bin/env python3
"""Accounting and tamper checks; synthetic data does not qualify GPU work."""

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

SPEC = importlib.util.spec_from_file_location('count_analysis', Path(__file__).with_name('block-v2-typed-count-analysis.py'))
A = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A)
M = A.controller(Path(__file__).with_name('block-v2-typed-count-matrix.py'))


def trial(count=4, gpu='GPU-a', origin='fresh_matrix_trial'):
    return {'count': count, 'gpu_uuid': gpu, 'origin': origin,
            'cpu_audited': True, 'fresh_proofs': count}


def stage_fixture():
    plan = {'fresh_proofs': 3, 'tasks': [
        {'file': 'node.1.0', 'count': 2, 'mode': 4},
        {'file': 'node.1.1', 'count': 2, 'mode': 4},
        {'file': 'node.2.0', 'count': 4, 'mode': 3},
    ]}
    stages = [
        {'event': 'fresh_typed_node', 'level': 1, 'index': 0, 'count': 2, 'mode': 4, 'seconds': 8, 'bytes': 64},
        {'event': 'fresh_typed_node', 'level': 1, 'index': 1, 'count': 2, 'mode': 4, 'seconds': 5, 'bytes': 64},
        {'event': 'fresh_typed_node', 'level': 2, 'index': 0, 'count': 4, 'mode': 3, 'seconds': 7, 'bytes': 64},
        {'event': 'typed_gpu_work_complete', 'seconds': 21, 'recursive_proofs': 3, 'cpu_only': False},
    ]
    return plan, stages


def log(rows):
    return '\n'.join(json.dumps(row) for row in rows)


class CountAnalysisTests(unittest.TestCase):
    def test_previous_roots_are_separate_from_new_work(self):
        totals = A.accounting([trial(), trial(gpu='GPU-b', origin='retained_and_revalidated'), trial(8)])
        self.assertEqual(totals['new_recursive_proofs'], 12)
        self.assertEqual(totals['new_cpu_audited_roots'], 2)
        self.assertEqual(totals['recursive_proofs_in_prior_roots'], 4)
        self.assertEqual(totals['revalidated_prior_roots'], 1)
        self.assertEqual(totals['recursive_proofs_in_all_covered_roots'], 16)

    def test_duplicate_or_unaccountable_proofs_reject(self):
        for trials in ([trial(), trial()], [trial(origin='unknown')],
                       [{**trial(), 'cpu_audited': False}], [{**trial(), 'fresh_proofs': True}],
                       [{**trial(), 'fresh_proofs': 0}]):
            with self.subTest(trials=trials), self.assertRaises(ValueError):
                A.accounting(trials)

    def test_stage_samples_preserve_first_and_later_observations(self):
        plan, stages = stage_fixture()
        result = A.stage_costs(plan, log(stages), 22)
        self.assertEqual(result['measured_node_seconds'], 20)
        self.assertEqual(result['outside_node_timers_seconds'], 2)
        modes = {row['mode']: row for row in result['modes']}
        self.assertEqual(modes[4]['first_observed_seconds'], 8)
        self.assertEqual(modes[4]['subsequent_median_seconds'], 5)
        self.assertIsNone(modes[3]['subsequent_median_seconds'])
        self.assertAlmostEqual(sum(r['share_of_measured_node_seconds'] for r in result['modes']), 1)

    def test_missing_reordered_duplicate_and_wrong_mode_stages_reject(self):
        plan, stages = stage_fixture()
        variants = [stages[1:], [stages[1], stages[0], *stages[2:]],
                    [stages[0], stages[0], *stages[2:]],
                    [{**stages[0], 'mode': 8}, *stages[1:]]]
        for rows in variants:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                A.stage_costs(plan, log(rows), 22)

    def test_invalid_durations_or_enclosure_reject(self):
        plan, stages = stage_fixture()
        for value in (True, 0, -1, float('nan'), float('inf'), 99):
            with self.subTest(value=value), self.assertRaises(ValueError):
                A.stage_costs(plan, log([{**stages[0], 'seconds': value}, *stages[1:]]), 22)
        with self.assertRaises(ValueError):
            A.stage_costs(plan, log(stages), 20)

    def test_completion_must_be_unique_and_cover_exact_work(self):
        plan, stages = stage_fixture()
        for rows in (stages[:-1], stages + [stages[-1]],
                     [*stages[:-1], {**stages[-1], 'recursive_proofs': 4}],
                     [*stages[:-1], {**stages[-1], 'cpu_only': True}]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                A.stage_costs(plan, log(rows), 22)

    def fixture(self, root):
        worker = root / '001-typed'
        (worker / 'root-only').mkdir(parents=True)
        plan, stages = stage_fixture()
        (root / 'plan.json').write_text(json.dumps(plan))
        (worker / 'prove.log').write_text(log(stages))
        (worker / 'root-only/body.json').write_text(json.dumps({'transactions': [
            {'kind': kind} for kind in ('joinsplit', 'htlc_redeem', 'htlc_refund', 'issuance')]}))
        t = {**trial(), 'fresh_proofs': 3, 'summary_source': {'path': str(root / 'summary.json')},
             'result_source': {'path': str(worker / 'result.json')}, 'worker_seconds': 24,
             'proving_seconds': 22, 'cpu_audit_seconds': 1, 'root_bytes': 64, 'root_sha256': 'a' * 64,
             'peak_charged_ram_bytes': 1024, 'budget': {}, 'context_measurement': {}}
        checked = {k: v for k, v in t.items() if k != 'origin'}
        module = SimpleNamespace(T=SimpleNamespace(check_pins=lambda _: None), coverage=M.coverage,
                                 checked_trial=lambda *args: copy.deepcopy(checked))
        s = {'schema': 'lattica-typed-count-matrix-v1', 'status': 'running',
             'cold_full64_qualified': False, 'post_seal_qualified': False,
             'delivered_transactions_measured': False, 'production_ready': False,
             'input_pins': {}, 'trials': [t], 'counts': list(M.T.COUNTS), 'gpu_uuids': ['GPU-a'],
             'coverage': M.coverage(list(M.T.COUNTS), ['GPU-a'], [t]),
             'construction': 'paired', 'profile': {}, 'gpu_sha256': 'b' * 64,
             'cpu_sha256': 'c' * 64, 'profile_sha256': 'd' * 64, 'fixture_pins': {}}
        return s, module

    def test_partial_snapshot_withholds_qualification_and_labels_fixture_rate(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot, module = self.fixture(Path(tmp))
            result = A.analyze(snapshot, module)
            self.assertFalse(result['coverage']['all_required_counts_passed'])
            self.assertFalse(result['delivered_transactions_measured'])
            self.assertEqual(result['rows'][0]['useful_fixture_inputs_per_minute'], 7.5)
            snapshot['status'] = 'succeeded'
            with self.assertRaises(ValueError):
                A.analyze(snapshot, module)

    def test_changed_trial_or_coverage_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot, module = self.fixture(Path(tmp))
            for mutate in (lambda s: s['trials'][0].update(worker_seconds=1),
                           lambda s: s['coverage'].update(all_required_counts_passed=True),
                           lambda s: s.update(delivered_transactions_measured=True)):
                changed = copy.deepcopy(snapshot)
                mutate(changed)
                with self.assertRaises(ValueError):
                    A.analyze(changed, module)


if __name__ == '__main__':
    unittest.main()
