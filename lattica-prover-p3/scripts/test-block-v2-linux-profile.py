#!/usr/bin/env python3
import copy
from pathlib import Path
import tempfile
import unittest
import block_v2_linux_profile as P


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.profile = dict(nsys='/usr/bin/nsys', gpu_index=0,
                            clock_library='/tmp/clock.so', clock_runner='/tmp/clock.py')
        self.config = dict(linux_profile=self.profile,
                           pins={p: 'pinned' for k, p in self.profile.items() if k != 'gpu_index'})

    def test_capture_keeps_budget_and_excludes_unrelated_credentials(self):
        env = {'HOME': '/home/example', 'PATH': '/usr/bin', 'OPENAI_API_KEY': 'secret',
               'AWS_SESSION_TOKEN': 'secret', 'LD_PRELOAD': '/unrelated.so',
               'LATTICA_V2_GPU_MANAGED_BYTES': '6710886400', 'RAYON_NUM_THREADS': '6'}
        argv, actual = P.command(self.config, {}, Path('/tmp/run'), ['/tmp/prover', 'prove', 8], env)
        self.assertEqual(argv[-3:], ['/tmp/prover', 'prove', '8'])
        self.assertEqual(actual['LATTICA_V2_GPU_MANAGED_BYTES'], env['LATTICA_V2_GPU_MANAGED_BYTES'])
        self.assertEqual(actual['LATTICA_PROFILE_TIMELINE'], '1')
        for key in ('OPENAI_API_KEY', 'AWS_SESSION_TOKEN', 'LD_PRELOAD'):
            self.assertNotIn(key, actual)
        self.assertIn('--gpu-metrics-devices=0', argv)
        self.assertIn('--sample=process-tree', argv)
        self.assertIn('--sampling-period=22660288', argv)

    def test_invalid_or_unpinned_profiler_rejected(self):
        for change in ('index', 'relative', 'unpinned', 'unknown'):
            config = copy.deepcopy(self.config)
            if change == 'index': config['linux_profile']['gpu_index'] = -1
            if change == 'relative': config['linux_profile']['clock_library'] = 'clock.so'
            if change == 'unpinned': del config['pins']['/usr/bin/nsys']
            if change == 'unknown': config['linux_profile']['arbitrary_option'] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                P.command(config, {}, Path('/tmp/run'), ['prover'], {})

    def test_process_counters_follow_child_without_argv_or_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for pid, children in ((12, '13'), (13, '')):
                process = root / str(pid)
                (process / 'task' / str(pid)).mkdir(parents=True)
                fields = ['S'] + ['0'] * 21
                for index, value in ((11, 120), (12, 8), (17, 6), (19, 40), (21, 200)):
                    fields[index] = str(value)
                (process / 'stat').write_text(f'{pid} (test name) ' + ' '.join(fields))
                (process / 'task' / str(pid) / 'children').write_text(children)
            values = P.process_samples(12, root)
            self.assertEqual({x['pid'] for x in values}, {12, 13})
            self.assertTrue(all(x['user_ticks'] == 120 and x['threads'] == 6 for x in values))
            self.assertEqual(P.process_samples(14, root), [])

    def test_nonprofiled_command_is_unchanged(self):
        command, env = ['prover'], {'CUSTOM': 'value'}
        self.assertEqual(P.command({}, {}, Path('/tmp/run'), command, env), (command, env))


if __name__ == '__main__':
    unittest.main()
