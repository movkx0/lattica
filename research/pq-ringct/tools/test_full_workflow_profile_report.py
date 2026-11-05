"""Comparison gates must not promote incomplete, unbalanced or different work."""
import json
import hashlib
from pathlib import Path
import tempfile
import unittest

from full_workflow_profile_report import compare, identity_cpu_cost, identity_cpu_breakdown, quotient_compilation_cost, read_record, utilization


def campaign():
    pairs = []
    time = 0
    for case in ('n3', 'n4'):
        for number, workload, first in [(1, 'public-a', 'baseline'), (2, 'public-b', 'candidate'),
                                         (3, 'public-a', 'candidate'), (4, 'public-b', 'baseline')]:
            order = [first, 'candidate' if first == 'baseline' else 'baseline']
            runs = {}
            for variant in order:
                runs[variant] = dict(record=f'{case}-{number}-{variant}', record_sha256='digest',
                    case=case, mode='summary', total_ns=10_000 if variant == 'baseline' else 9_000,
                    workload=[workload, 'context'], layout='paired-v1', host_profile=case,
                    device={'uuid': 'gpu'}, runtime={'policy': 'gpu_required'}, inventory=[100, 200],
                    source={'source.rs': variant}, binary=variant, workers=[16, 16],
                    started_utc=time, finished_utc=time + 10)
                time += 20
            pairs.append(dict(case=case, order=order, runs=runs))
    return pairs


class FullWorkflowComparisonTests(unittest.TestCase):
    def test_serial_identity_detail_is_optional_and_reconciles(self):
        self.assertIsNone(identity_cpu_breakdown('historical profile without detail'))
        content = '\n'.join([
            'bounded_cpu_identity_hash fields=100 count_ns=20 hash_and_framing_ns=80 total_ns=100',
            'bounded_cpu_identity_hash fields=200 count_ns=40 hash_and_framing_ns=160 total_ns=200'])
        result = identity_cpu_breakdown(content)
        self.assertEqual(result['measurements'], 2)
        self.assertEqual(result['fields'], 300)
        self.assertEqual(result['count_fraction'], .2)
        for invalid in [content.replace('total_ns=100', 'total_ns=101'),
                        content.replace('fields=100', 'fields=-1')]:
            with self.assertRaises(ValueError):
                identity_cpu_breakdown(invalid)

    def test_external_utilization_uses_counter_deltas_and_sample_duration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'telemetry.jsonl'
            rows = [dict(schema='ringct-workflow-telemetry-v1', since_start_ns=ns,
                         cpu_usage_usec=cpu, memory_peak_bytes=memory,
                         gpu={'utilization.gpu': busy, 'memory.used': 2048})
                    for ns, cpu, memory, busy in [(0, 100, 1000, 0),
                                                  (2_000_000_000, 2_000_100, 3000, 20),
                                                  (5_000_000_000, 5_000_100, 2000, 80)]]
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            evidence = dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                            samples=3, samples_with_errors=0, write_error=None)
            summary = utilization(dict(full_workflow_telemetry=evidence))
            self.assertEqual(summary['mean_cpu_cores'], 1)
            self.assertEqual(summary['whole_device_gpu_mean_percent'], 56)
            self.assertEqual(summary['gpu_observation_fraction'], 1)
            self.assertEqual(summary['host_peak_bytes'], 3000)
            self.assertEqual(summary['whole_device_gpu_peak_mib'], 2048)
            path.write_text(path.read_text() + '\n')
            with self.assertRaisesRegex(ValueError, 'telemetry changed'):
                utilization(dict(full_workflow_telemetry=evidence))

    def test_missing_utilization_is_not_invented(self):
        self.assertIsNone(utilization({}))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'telemetry.jsonl'
            rows = [dict(schema='ringct-workflow-telemetry-v1', since_start_ns=ns)
                    for ns in (0, 1_000_000_000)]
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            evidence = dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                            samples=2, samples_with_errors=2, write_error='incomplete')
            summary = utilization(dict(full_workflow_telemetry=evidence))
            self.assertIsNone(summary['mean_cpu_cores'])
            self.assertIsNone(summary['whole_device_gpu_mean_percent'])
            self.assertEqual(summary['gpu_observation_fraction'], 0)
            self.assertEqual(summary['write_error'], 'incomplete')

    def test_compiler_source_identity_does_not_claim_a_driver_cache_hit(self):
        first, second = 'a' * 64, 'b' * 64
        content = '\n'.join(
            f'bounded_gpu_quotient_specialization selected=true source_sha3={source} build_ns={ns}'
            for source, ns in [(first, 10), (first, 20), (second, 30)])
        result = quotient_compilation_cost(content, 1000)
        self.assertEqual(result['distinct_observed_sources'], 2)
        self.assertEqual(result['repeated_source_builds'], 1)
        self.assertEqual(result['source_build_seconds'][first], [10 / 1e9, 20 / 1e9])
        self.assertFalse(result['lower_bound'])
        with self.assertRaises(ValueError):
            quotient_compilation_cost(
                'bounded_gpu_quotient_specialization selected=true source_sha3=bad build_ns=10', 1000)

    def test_compilation_wall_time_excludes_device_events_and_marks_missing_clocks(self):
        content = '\n'.join([
            'bounded_gpu_quotient_specialization selected=true private_bytes=24 build_ns=100',
            'bounded_device_quotient device_ns=1000 wall_ns=2000',
            'bounded_gpu_quotient_specialization selected=false private_bytes=1520',
            'bounded_gpu_quotient_specialization selected=false private_bytes=900 build_ns=50',
        ])
        result = quotient_compilation_cost(content, 1000)
        self.assertEqual(result['fraction'], .15)
        self.assertEqual(result['measured_builds'], 2)
        self.assertEqual(result['selected_builds'], 1)
        self.assertEqual(result['rejected_builds'], 2)
        self.assertEqual(result['builds_without_wall_clock'], 1)
        self.assertTrue(result['lower_bound'])
        with self.assertRaises(ValueError):
            quotient_compilation_cost('bounded_gpu_quotient_specialization selected=true build_ns=-1', 1000)

    def test_identity_cost_uses_cohort_wall_time_and_excludes_gpu_analysis(self):
        report = dict(owned_observations=dict(identity_preprocessing=dict(
            hash_wall_ns=10, worker_elapsed_ns=160, analysis_ns=30,
            elapsed_ns=40, finalization_ns=100)))
        self.assertAlmostEqual(identity_cpu_cost(report, 1_000)['fraction'], .11)
        self.assertEqual(identity_cpu_cost(dict(owned_observations={}), 1_000)['seconds'], 0)

    def test_balanced_fresh_runs_meet_both_gates(self):
        result = compare(campaign())
        self.assertTrue(result['eligible_for_promotion'])
        self.assertTrue(result['n4_target_met'])

    def test_small_gain_or_n3_regression_does_not_promote(self):
        for case, candidate_ns in [('n4', 9_600), ('n3', 10_400)]:
            pairs = campaign()
            for pair in pairs:
                if pair['case'] == case:
                    pair['runs']['candidate']['total_ns'] = candidate_ns
            self.assertFalse(compare(pairs)['eligible_for_promotion'])

    def test_order_sensitive_gain_does_not_promote(self):
        pairs = campaign()
        for pair in pairs:
            if pair['case'] == 'n4':
                pair['runs']['candidate']['total_ns'] = 8_000 if pair['order'][0] == 'baseline' else 10_000
        result = compare(pairs)
        self.assertAlmostEqual(result['cases']['n4']['median_reduction'], .1)
        self.assertFalse(result['eligible_for_promotion'])

    def test_duplicate_missing_and_overlapping_runs_are_rejected(self):
        incomplete = campaign()[:-1]
        duplicate = campaign()
        duplicate[1]['runs']['baseline']['record'] = duplicate[0]['runs']['baseline']['record']
        overlap = campaign()
        overlap[1]['runs']['candidate']['started_utc'] = 0
        for pairs in (incomplete, duplicate, overlap):
            with self.assertRaises(ValueError):
                compare(pairs)

    def test_changed_work_hardware_sources_modes_or_workers_are_rejected(self):
        changes = [('inventory', [1, 200]), ('device', {'uuid': 'different'}),
                   ('workload', ['different', 'context']), ('source', {'source.rs': 'changed'}),
                   ('mode', 'detail'), ('workers', [16, 4]), ('runtime', {'policy': 'cpu_required'})]
        for key, value in changes:
            pairs = campaign()
            pairs[0]['runs']['candidate'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                compare(pairs)

    def test_unbalanced_public_workloads_are_rejected(self):
        pairs = campaign()
        for run in pairs[2]['runs'].values():
            run['workload'] = ['public-b', 'context']
        with self.assertRaises(ValueError):
            compare(pairs)

    def test_incomplete_receipt_is_not_a_performance_sample(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'incomplete.json'
            path.write_text(json.dumps(dict(status='failed_or_incomplete', profile='full')))
            with self.assertRaisesRegex(ValueError, 'only completed'):
                read_record(path)


if __name__ == '__main__':
    unittest.main()
