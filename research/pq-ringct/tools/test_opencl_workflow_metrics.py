import unittest

import opencl_workflow_metrics as report
from test_opencl_private_spend_benchmark import arguments, result_fixture, runner


def record_fixture():
    record = runner.build_plan(arguments())
    result = result_fixture(benchmark=True)
    result['context']['operations']['prove_calls'] += len(result['cases'])
    result['context']['operations']['prove_succeeded'] += len(result['cases'])
    record.update(status='passed', error=None, all_subprocesses_terminal_and_reaped=True,
                  correctness_result=result,
                  prior_correctness={'device': result['context']['device']})
    return record


class WorkflowMetricsTests(unittest.TestCase):
    def test_observed_native_recursive_and_batch_counts_stay_distinct(self):
        metrics = report.metrics(record_fixture())
        self.assertEqual(metrics['proofs'], {
            'native_stark': 8, 'recursive_transaction': 2, 'recursive_batch': 5, 'total_stark': 15,
        })
        self.assertIsNone(metrics['geometry']['registered_active_rows'])
        self.assertIsNone(metrics['timing_seconds']['worker_cpu_verification'])
        self.assertFalse(metrics['performance_qualified'])

    def test_counter_mismatch_rejects_report(self):
        for key in ['native_gpu_succeeded', 'prove_succeeded']:
            with self.subTest(key=key):
                record = record_fixture()
                record['correctness_result']['context']['operations'][key] += 1
                with self.assertRaises(ValueError):
                    report.metrics(record)

    def test_live_or_failed_runs_cannot_be_summarized_as_accepted(self):
        for key, value in [('status', 'starting'), ('error', 'failed'), ('all_subprocesses_terminal_and_reaped', False)]:
            with self.subTest(key=key):
                record = record_fixture()
                record[key] = value
                with self.assertRaises(ValueError):
                    report.metrics(record)


if __name__ == '__main__':
    unittest.main()
