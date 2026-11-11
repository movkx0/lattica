import json
import unittest
from gpu_aggregation_telemetry import reduce_intervals


class TelemetryTests(unittest.TestCase):
    def test_terminal_counters_are_not_summed_with_worker_observations(self):
        text = ('bounded_gpu_lde_checkpoint label="worker context observation" transform_device_ns=30\n'
                'bounded_gpu_lde_checkpoint label="recursive OpenCL session complete" transform_device_ns=30\n')
        value = reduce_intervals(text)
        self.assertEqual(value['terminal_counters']['bounded_gpu_lde_checkpoint']['transform_device_ns'], 30)
        with self.assertRaises(RuntimeError):
            reduce_intervals(text + text)

    def test_overlapping_tasks_remain_task_time(self):
        rows = [dict(tree=0, job=i, phase='compile', start_ns=i, end_ns=i+10, duration_ns=10) for i in range(2)]
        value = reduce_intervals('\n'.join('GPU_AGGREGATION_INTERVAL '+json.dumps(r) for r in rows))
        self.assertEqual(value['phases']['compile']['task_sum_ns'], 20)
        self.assertFalse(value['additive_wall_decomposition'])
        rows[0]['duration_ns'] = 9
        with self.assertRaises(RuntimeError):
            reduce_intervals('GPU_AGGREGATION_INTERVAL '+json.dumps(rows[0]))
