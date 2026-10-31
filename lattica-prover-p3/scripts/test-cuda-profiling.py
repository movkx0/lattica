#!/usr/bin/env python3
"""Diagnostic launch/measurement boundaries; no synthetic GPU qualification."""
import copy
import importlib
from pathlib import Path
import tempfile
import os
import unittest
from unittest.mock import patch
import block_v2_linux_profile as P

B = importlib.import_module('bench-cuda-recursive')
S = importlib.import_module('block-v2-typed-shared-gpu-run')


class CudaProfilingTests(unittest.TestCase):
    def setUp(self):
        self.profile = dict(tool='nsys', executable='/usr/bin/nsys', nvtx_library='/tmp/nvtx.so')
        self.config = dict(linux_profile=self.profile,
                           pins={'/usr/bin/nsys': 'pin', '/tmp/nvtx.so': 'pin'})

    def test_cuda_timeline_preserves_runtime_and_direct_worker_socket(self):
        argv, env = P.command(self.config, {}, Path('/tmp/run'), ['/tmp/prover', 'serve'],
                              {'LD_LIBRARY_PATH': '/pinned/cuda', 'LATTICA_V2_GPU_MANAGED_BYTES': '123',
                               'AWS_SECRET_ACCESS_KEY': 'secret', 'LD_PRELOAD': '/unrelated.so'})
        self.assertEqual(argv[-2:], ['/tmp/prover', 'serve'])
        self.assertIn('--trace=cuda,nvtx,osrt', argv)
        self.assertIn('--gpu-metrics-devices=none', argv)
        self.assertFalse(any('gb20' in arg for arg in argv))
        self.assertEqual(env['LD_LIBRARY_PATH'], '/pinned/cuda')
        self.assertEqual(env['LATTICA_V2_GPU_MANAGED_BYTES'], '123')
        self.assertNotIn('AWS_SECRET_ACCESS_KEY', env)
        self.assertNotIn('LD_PRELOAD', env)

    def test_cpu_sampling_is_opt_in_and_scoped_to_worker_process_tree(self):
        for enabled in (False, True):
            self.profile['cpu_sampling'] = enabled
            argv, _ = P.command(self.config, {}, Path('/tmp/run'), ['/tmp/prover'], {})
            sampling = 'process-tree' if enabled else 'none'
            self.assertIn('--sample=' + sampling, argv)
            self.assertIn('--cpuctxsw=' + sampling, argv)
            self.assertIn('--gpu-metrics-devices=none', argv)
            self.assertEqual('--backtrace=dwarf' in argv, enabled)
            self.assertFalse(any('system-wide' in arg for arg in argv))

    def test_cpu_sampling_rejects_unscoped_or_ambiguous_values(self):
        for value in ('system-wide', 'process-tree', 1, 0, None, []):
            self.profile['cpu_sampling'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                P.command(self.config, {}, Path('/tmp/run'), ['/tmp/prover'], {})

    def test_cpu_backtrace_accepts_only_scoped_supported_methods(self):
        self.profile.update(cpu_sampling=True, cpu_backtrace='fp')
        argv, _ = P.command(self.config, {}, Path('/tmp/run'), ['/tmp/prover'], {})
        self.assertIn('--backtrace=fp', argv)
        for method in ('lbr', 'none', '--sample=system-wide', None, []):
            self.profile['cpu_backtrace'] = method
            with self.subTest(method=method), self.assertRaises(ValueError):
                P.command(self.config, {}, Path('/tmp/run'), ['/tmp/prover'], {})

    def test_cpu_backtrace_requires_sampling_enabled(self):
        self.profile['cpu_backtrace'] = 'fp'
        with self.assertRaises(ValueError):
            P.command(self.config, {}, Path('/tmp/run'), ['/tmp/prover'], {})

    def test_kernel_capture_is_bounded_and_leaves_clocks_unchanged(self):
        self.profile.update(tool='ncu', executable='/usr/bin/ncu', kernel='ntt_tile',
                            launch_skip=1, launch_count=3, metrics=['sass__inst_executed_per_opcode'])
        self.config['pins']['/usr/bin/ncu'] = 'pin'
        argv, _ = P.command(self.config, {}, Path('/tmp/run'), ['/tmp/prover'], {})
        self.assertEqual(argv[argv.index('--target-processes')+1], 'application-only')
        self.assertEqual(argv[argv.index('--launch-count')+1], '3')
        self.assertEqual(argv[argv.index('--clock-control')+1], 'none')
        self.assertNotIn('--set', argv)
        self.profile['launch_count'] = 0
        with self.assertRaises(ValueError):
            P.command(self.config, {}, Path('/tmp/run'), ['/tmp/prover'], {})

    def test_profile_schema_and_pin_validation(self):
        for change in ({'extra': True}, {'executable': '/unpinned'}, {'nvtx_library': 'relative.so'}, {'tool': 'shell'}):
            config = copy.deepcopy(self.config)
            config['linux_profile'].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                P.command(config, {}, Path('/tmp/run'), ['/tmp/prover'], {})

    def test_shared_profiler_requires_pinned_identity_handoff(self):
        self.config['profile_shared_worker'] = True
        with self.assertRaises(ValueError):
            P.command(self.config, {}, Path('/tmp/run'), ['/tmp/prover'], {})
        self.config['pins'][str(Path(P.__file__).resolve())] = 'pin'
        argv, _ = P.command(self.config, {}, Path('/tmp/run'), ['/tmp/prover'], {})
        self.assertEqual(argv[-3:], ['--worker-exec', '--', '/tmp/prover'])

    def test_worker_identity_handoff_acknowledges_before_exec(self):
        with patch.dict(os.environ, {'NOTIFY_SOCKET': '/run/test-notify'}), \
                patch.object(P.subprocess, 'run') as notify, patch.object(P.os, 'execvpe') as execute:
            P.worker_entry('--worker-exec', ['--', '/tmp/prover', 'serve'])
            self.assertEqual(notify.call_args.args[0], ['/usr/bin/systemd-notify', '--pid='+str(os.getpid())])
            self.assertTrue(notify.call_args.kwargs['check'])
            self.assertEqual(execute.call_args.args[:2], ('/tmp/prover', ['/tmp/prover', 'serve']))

    def test_shared_ncu_follows_worker_handoff_with_bounded_capture(self):
        self.profile.update(tool='ncu', executable='/usr/bin/ncu', kernel='ntt_tile',
                            launch_skip=75, launch_count=1, metrics=['sass__inst_executed_per_opcode'])
        self.config['pins']['/usr/bin/ncu'] = 'pin'
        self.config['pins'][str(Path(P.__file__).resolve())] = 'pin'
        self.config['profile_shared_worker'] = True
        argv, _ = P.command(self.config, {}, Path('/tmp/run'), ['/tmp/prover'], {})
        self.assertEqual(argv[argv.index('--target-processes')+1], 'all')
        self.assertEqual(argv[argv.index('--launch-count')+1], '1')
        self.assertEqual(argv[-3:], ['--worker-exec', '--', '/tmp/prover'])

    def test_capture_accepts_supported_formats(self):
        for tool, name in (('nsys', 'nsight.nsys-rep'),
                           ('ncu', 'kernel-profile.ncu-rep'),
                           ('ncu', 'kernel-profile.ncu-repz')):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                capture = directory / name
                capture.write_bytes(b'report')
                self.assertEqual(P.completed_capture({'tool': tool}, directory), capture)

    def test_capture_rejects_missing_empty_and_ambiguous_reports(self):
        cases = ((), (('kernel-profile.ncu-repz', b''),),
                 (('kernel-profile.ncu-rep', b''),),
                 (('kernel-profile.ncu-rep', b'report'),
                  ('kernel-profile.ncu-repz', b'report')),
                 (('unrelated.ncu-repz', b'report'),))
        for files in cases:
            with self.subTest(files=files), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                for name, data in files:
                    (directory / name).write_bytes(data)
                with self.assertRaisesRegex(ValueError, 'single complete capture'):
                    P.completed_capture({'tool': 'ncu'}, directory)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'kernel-profile.ncu-repz').mkdir()
            with self.assertRaisesRegex(ValueError, 'single complete capture'):
                P.completed_capture({'tool': 'ncu'}, directory)

    def test_cpu_audits_do_not_receive_gpu_or_profiler_arguments(self):
        state = dict(ActiveState='active', SubState='exited', MainPID='0', ControlPID='0',
                     Result='success', ExecMainStatus='0')
        with tempfile.TemporaryDirectory() as directory, patch.object(B, 'check'), \
                patch.object(B, 'sha', return_value='pin'), patch.object(B, 'properties', return_value=state), \
                patch.object(B.subprocess, 'run') as run:
            B.OUT = B.ROOT = Path(directory)
            B.RUN_TOKEN, B.CPU = 'unit-test', Path('/bin/true')
            B.cpu_step('audit', ['audit-root', '/fixture'])
            argv = run.call_args_list[0].args[0]
            self.assertEqual(argv[-3:], ['/bin/true', 'audit-root', '/fixture'])
            self.assertNotIn('--linux-profile', argv)
            self.assertNotIn('--cuda-library-path', argv)
            self.assertEqual(run.call_args_list[-1].args[0][:3], ['systemctl', '--user', 'stop'])

    def test_instrumented_rows_never_become_throughput(self):
        self.assertEqual(B.summarize([dict(count=4, arm='cuda', phase='profile')], ['cuda'], [4]), [])
        self.assertEqual(B.summarize([dict(count=4, arm='cuda', phase='measured', instrumented=True)], ['cuda'], [4]), [])


if __name__ == '__main__':
    unittest.main()
