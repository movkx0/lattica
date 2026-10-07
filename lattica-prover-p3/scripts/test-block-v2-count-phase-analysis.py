#!/usr/bin/env python3
"""Failure checks for deriving performance observations from proof-plan logs."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    'count_phase', Path(__file__).with_name('block-v2-count-phase-analysis.py'))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


def fixture():
    row = {'fresh_proofs': 5, 'proving_seconds': 20,
           'stage_costs': {'stages': [{'mode': mode} for mode in (4, 4, 8, 3, 3)]}}
    lines = [f'performance_span target="{target}" name="{name}" '
             f'calls={3 if key == "preprocessing_setup" else 5} total_ns=1000000000 max_ns=900000000'
             for key, (target, name) in P.PHASES.items()]
    return row, '\n'.join(lines)


class PhaseAnalysisTests(unittest.TestCase):
    def test_cache_transitions_and_inclusive_parallel_spans(self):
        row, log = fixture()
        log += '\nperformance_span target="parallel" name="nested work" calls=40 total_ns=90000000000 max_ns=9000000000'
        result = P.phase_metrics(row, log)
        self.assertEqual(result['expected_preprocessing_cache_transitions'], 3)
        self.assertEqual(result['phases']['quotient_polynomial']['inclusive_seconds'], 1)
        self.assertEqual(result['all_spans'][-1]['total_ns'], 90000000000)

    def test_incomplete_proof_coverage_cannot_supply_phase_results(self):
        row, log = fixture()
        for changed in (log.replace('calls=5', 'calls=4', 1), '\n'.join(log.splitlines()[1:])):
            with self.assertRaises(ValueError):
                P.phase_metrics(row, changed)
        row['stage_costs']['stages'].pop()
        with self.assertRaises(ValueError):
            P.phase_metrics(row, log)

    def test_cache_miss_count_must_match_mode_order_not_unique_modes(self):
        row, log = fixture()
        row['stage_costs']['stages'] = [{'mode': mode} for mode in (4, 8, 4, 8, 3)]
        with self.assertRaises(ValueError):
            P.phase_metrics(row, log)

    def test_duplicate_or_malformed_cumulative_counters_reject(self):
        _, log = fixture()
        bad_logs = [log + '\n' + log.splitlines()[0], log.replace('calls=3', 'calls=3 calls=3', 1),
                    log.replace('max_ns=900000000', 'max_ns=1000000001', 1),
                    log.replace('total_ns=1000000000', 'total_ns=-1', 1),
                    log.replace('total_ns=1000000000', 'total_ns=nan', 1)]
        for bad in bad_logs:
            with self.subTest(log=bad[:120]), self.assertRaises(ValueError):
                P.spans(bad)

    def test_outer_span_cannot_exceed_proving_interval(self):
        row, log = fixture()
        with self.assertRaises(ValueError):
            P.phase_metrics(row, log.replace('total_ns=1000000000', 'total_ns=21000000000', 1))

    def test_changed_log_is_rejected_before_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'prove.log'
            path.write_text(fixture()[1])
            item = P.pin(path)
            self.assertEqual(P.read_pinned(item, root), path.read_bytes())
            path.write_bytes(path.read_bytes() + b'\n')
            with self.assertRaises(ValueError):
                P.read_pinned(item, root)


if __name__ == '__main__':
    unittest.main()
