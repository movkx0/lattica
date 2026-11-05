import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import full_workflow_telemetry as telemetry


class WorkflowTelemetryTests(unittest.TestCase):
    def test_external_samples_preserve_units_and_device_query_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            group = root / 'case'
            group.mkdir()
            (group / 'cpu.stat').write_text('usage_usec 1000000\nuser_usec 700000\nsystem_usec 300000\n')
            (group / 'memory.current').write_text('4096')
            (group / 'memory.peak').write_text('8192')
            sampler = telemetry.Sampler(root / 'samples.jsonl', 'GPU-test')
            real_path = Path
            def paths(value):
                return root if value == '/sys/fs/cgroup' else real_path(value)
            with patch.object(telemetry, 'Path', side_effect=paths), \
                 patch.object(telemetry.subprocess, 'run') as query, \
                 patch.object(telemetry.time, 'monotonic_ns', side_effect=[10**9, 2 * 10**9]):
                query.return_value = SimpleNamespace(stdout='GPU-test, 50, 20, 1024, 2000, 14000, 60, 100\n')
                sampler.sample({'ControlGroup': '/case'})
                (group / 'cpu.stat').write_text('usage_usec 3000000\nuser_usec 2100000\nsystem_usec 900000\n')
                query.side_effect = subprocess.TimeoutExpired('nvidia-smi', 2)
                sampler.sample({'ControlGroup': '/case'})
            result = sampler.finish()
            rows = [json.loads(line) for line in (root / 'samples.jsonl').read_text().splitlines()]
            self.assertEqual(rows[0]['memory_peak_bytes'], 8192)
            self.assertEqual(rows[0]['gpu']['memory.used'], 1024)
            self.assertEqual(rows[1]['cpu_percent_one_core'], 200)
            self.assertEqual(result['samples_with_errors'], 1)
            self.assertNotIn('gpu', rows[1])
            self.assertEqual(len(result['sha256']), 64)


if __name__ == '__main__':
    unittest.main()
