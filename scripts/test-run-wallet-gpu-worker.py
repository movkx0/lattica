#!/usr/bin/env python3
"""Resource choices must reach the pinned assignment and native environment."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name('run-wallet-gpu-worker.py')
spec = importlib.util.spec_from_file_location('wallet_launcher', SOURCE)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class WalletResourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.args = SimpleNamespace(gpu_uuid='GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c',
            workdir=self.root, state_dir=self.root / 'assignments', storage='full',
            command=[sys.executable, '-c', 'pass'], managed_gpu_gib=1, host_output_gib=1)

    def invoke(self):
        calls = []
        def run(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0)
        with patch.dict(os.environ, {}, clear=True), patch.object(launcher.subprocess, 'run', run):
            self.assertEqual(launcher.launch(self.args), 0)
        self.assertEqual(len(calls), 1)
        return calls[0]

    def test_default_and_large_limits_bind_assignment_and_environment(self):
        for gpu, output in [(1, 1), (7, 2)]:
            with self.subTest(gpu=gpu, output=output):
                self.args.managed_gpu_gib, self.args.host_output_gib = gpu, output
                command = self.invoke()
                env = dict(item[len('--setenv='):].split('=', 1) for item in command if item.startswith('--setenv='))
                assignment = Path(env['LATTICA_WALLET_WORKER_BUDGET'])
                budget = json.loads(assignment.read_text())
                self.assertEqual(assignment.stat().st_mode & 0o777, 0o600)
                self.assertEqual(assignment.parent.stat().st_mode & 0o777, 0o700)
                for field, variable, value in [
                    ('managed_gpu_bytes', 'LATTICA_V2_GPU_MANAGED_BYTES', gpu << 30),
                    ('host_output_bytes', 'LATTICA_V2_HOST_OUTPUT_BYTES', output << 30),
                    ('context_gpu_bytes', 'LATTICA_V2_GPU_CONTEXT_BYTES', 4 << 30),
                ]:
                    self.assertEqual(budget[field], value)
                    self.assertEqual(env[variable], str(value))
                self.assertEqual(budget['host_bytes'], 3 << 30)
                self.assertEqual(budget['threads'], 4)
                self.assertEqual(env['LATTICA_PROVING_POLICY'], 'gpu-required')
                for setting in ['MemoryMax=3G', 'MemorySwapMax=0', 'CPUQuota=400%',
                                'RuntimeMaxSec=180', 'KillMode=control-group', 'LimitCORE=0']:
                    self.assertIn('--property=' + setting, command)

    def test_invalid_limits_reject_before_creating_assignments_or_launching(self):
        for field, values in [('managed_gpu_gib', [0, 8, -1, True, 1.5]),
                              ('host_output_gib', [0, 3, 4, -1, True, 1.5])]:
            for value in values:
                with self.subTest(field=field, value=value):
                    old = getattr(self.args, field)
                    setattr(self.args, field, value)
                    with patch.dict(os.environ, {}, clear=True), patch.object(launcher.subprocess, 'run') as run:
                        with self.assertRaises(ValueError):
                            launcher.launch(self.args)
                        run.assert_not_called()
                    self.assertFalse(self.args.state_dir.exists())
                    setattr(self.args, field, old)


if __name__ == '__main__':
    unittest.main()
