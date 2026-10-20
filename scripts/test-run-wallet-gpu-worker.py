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
                self.assertEqual(env['LATTICA_GPU_BACKEND'], 'opencl')
                self.assertEqual(budget['schema'], 'lattica-wallet-local-gpu-v1')
                self.assertNotIn('cuda', budget)
                self.assertEqual(env['LATTICA_V2_GPU_WITNESS'], '1')
                self.assertNotIn('LD_LIBRARY_PATH', env)
                for setting in ['MemoryMax=3G', 'MemorySwapMax=0', 'CPUQuota=400%',
                                'RuntimeMaxSec=180', 'KillMode=control-group', 'LimitCORE=0',
                                'LimitSTACK=8M', 'TasksMax=96']:
                    self.assertIn('--property=' + setting, command)

    def cuda_runtime(self):
        runtime = self.root / 'cuda-libs'
        runtime.mkdir()
        for name in ['libnvrtc.so', 'libnvrtc-builtins.so.12.9']:
            (runtime / name).write_bytes(b'fixture library')
        return runtime

    def test_cuda_selects_native_assignment_and_explicit_runtime(self):
        self.args.gpu_backend = 'cuda'
        self.args.cuda_library_path = self.cuda_runtime()
        self.args.managed_gpu_gib = 7
        command = self.invoke()
        env = dict(item[len('--setenv='):].split('=', 1) for item in command if item.startswith('--setenv='))
        budget = json.loads(Path(env['LATTICA_WALLET_WORKER_BUDGET']).read_text())
        self.assertEqual(budget['schema'], 'lattica-wallet-local-cuda-v1')
        self.assertEqual(budget['cuda'], {'max_allocation_bytes': 1 << 30, 'headroom_bytes': 1 << 30})
        self.assertEqual(budget['managed_gpu_bytes'], 7 << 30)
        self.assertEqual(budget['context_gpu_bytes'], 4 << 30)
        self.assertEqual(budget['host_bytes'], 3 << 30)
        self.assertEqual(budget['threads'], 4)
        self.assertEqual(env['LD_LIBRARY_PATH'], str(self.args.cuda_library_path.resolve()))
        self.assertEqual(env['LATTICA_GPU_BACKEND'], 'cuda')
        self.assertEqual(env['LATTICA_PROVING_POLICY'], 'gpu-required')
        self.assertEqual({key for key in env if key.startswith('LATTICA_V2_GPU_')},
                         {'LATTICA_V2_GPU_MANAGED_BYTES', 'LATTICA_V2_GPU_CONTEXT_BYTES'})
        for setting in ['MemoryMax=3G', 'MemorySwapMax=0', 'CPUQuota=400%',
                        'RuntimeMaxSec=180', 'LimitSTACK=8M', 'TasksMax=96']:
            self.assertIn('--property=' + setting, command)

    def test_backend_and_runtime_mismatches_reject_before_launch(self):
        runtime = self.cuda_runtime()
        for backend, path, storage in [('cuda', None, 'full'), ('opencl', runtime, 'full'),
                                       ('cuda', runtime, 'compact'), ('invalid', None, 'full'),
                                       ('cuda', self.root, 'full')]:
            with self.subTest(backend=backend, path=path, storage=storage):
                self.args.gpu_backend, self.args.cuda_library_path, self.args.storage = backend, path, storage
                with patch.dict(os.environ, {}, clear=True), patch.object(launcher.subprocess, 'run') as run:
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        launcher.launch(self.args)
                    run.assert_not_called()
                self.assertFalse(self.args.state_dir.exists())

    def test_opencl_compact_storage_is_preserved(self):
        self.args.storage = 'compact'
        command = self.invoke()
        env = dict(item[len('--setenv='):].split('=', 1) for item in command if item.startswith('--setenv='))
        for suffix in ['COMPACT_PROVER_DATA', 'DIRECT_READBACK', 'OPENING_COMPACT', 'PARALLEL_READBACK']:
            self.assertEqual(env['LATTICA_V2_GPU_' + suffix], '1')

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
