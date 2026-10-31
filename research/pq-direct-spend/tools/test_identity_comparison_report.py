"""Comparison bookkeeping only; fixtures confer no proof qualification."""
import copy
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch
from pathlib import Path

import identity_comparison_report as report


def fixtures(count=6, offset=0):
    out = []
    start = datetime(2026, 10, 25, tzinfo=timezone.utc)
    for index in range(count):
        order = offset + index
        value = 100 if index % 2 == 0 else 80
        evidence = {key: 'same' for key in ('executable_sha256', 'source_snapshot_sha256',
            'physical_gpu_uuid', 'build_record_sha256', 'process_memory_max_bytes',
            'process_memory_high_bytes', 'swap_limit_bytes')}
        evidence.update(guard_record=str(order), guard_record_sha256=str(order),
            started_utc=(start + timedelta(seconds=2 * order)).isoformat(),
            finished_utc=(start + timedelta(seconds=2 * order + 1)).isoformat(),
            guard_wall_seconds=value, guarded_cgroup_host_peak_bytes=value)
        workflow = {key: value for key in ('complete_research_workflow_ns', 'prover_setup_ns',
                    'verifier_setup_ns', 'cpu_verification_ns')}
        out.append(dict(schema='lattica-direct-ring-identity-evidence-audit-v1',
            source_executable_artifact_log_bound=True, research_only=True,
            complete_faithful_ringct_workflow=False, performance_qualified=False,
            mode=('baseline', 'receipt-v1')[index % 2], evidence=evidence,
            file_sha256={'case-0/proof.bin': str(order)},
            screen=dict(workflow=workflow, complete_single_case_screen_ns=value,
                        timing_boundary='fixture'), actual_identity_execution={}))
    return out


class ComparisonTests(unittest.TestCase):
    def test_matched_medians_have_narrow_scope(self):
        result = report.summarize(fixtures(), 'matched')
        self.assertEqual(result['metrics']['workflow_ns']['reduction_percent'], 20)
        self.assertTrue(result['single_case_research_timing_threshold_met'])
        self.assertFalse(result['performance_qualified'])
        self.assertFalse(result['production_promotion_qualified'])
        self.assertFalse(report.summarize(fixtures(2), 'screening')['single_case_research_timing_threshold_met'])

    def test_count_order_provenance_and_freshness(self):
        for mutate in (
            lambda a: a.pop(),
            lambda a: a[1].update(mode='baseline'),
            lambda a: a[1]['evidence'].update(source_snapshot_sha256='different'),
            lambda a: a[1]['evidence'].update(guard_record_sha256='0'),
            lambda a: a[1]['file_sha256'].update({'case-0/proof.bin': '0'}),
            lambda a: a[1]['evidence'].update(started_utc=a[0]['evidence']['started_utc']),
            lambda a: a[1].update(performance_qualified=True),
        ):
            audits = fixtures()
            mutate(audits)
            with self.assertRaises(ValueError):
                report.summarize(audits, 'matched')

    def test_screening_cannot_be_counted_again(self):
        matched, screened = fixtures(6, 2), fixtures(2)
        with patch.object(report.screen, 'audit', side_effect=matched + screened):
            result = report.compare([Path(str(i)) for i in range(6)], 'matched', [Path('s0'), Path('s1')])
            self.assertEqual(len(result['excluded_screening_records']), 2)
        duplicate = copy.deepcopy(screened)
        duplicate[0]['file_sha256'] = matched[0]['file_sha256']
        with patch.object(report.screen, 'audit', side_effect=matched + duplicate):
            with self.assertRaises(ValueError):
                report.compare([Path(str(i)) for i in range(6)], 'matched', [Path('s0'), Path('s1')])


if __name__ == '__main__':
    unittest.main()
