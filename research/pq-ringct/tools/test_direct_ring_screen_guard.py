"""Exact research screen admission; no compiler, prover or GPU launched."""
import argparse
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'ring_screen_guard', Path(__file__).with_name('opencl_private_spend_validate.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def arguments(**changes):
    values = dict(
        profile='direct-full', label='seven-ring-policy', seconds=60,
        expect_tests=True, expect_result=False, expect_direct_result=False,
        execute=True, exclusive_window=True, build_label='screen-build',
        record_artifact=[], direct_ring_screen=True, retained_tree_storage='host',
        public_hash_kernel='baseline',
        device_uuid='GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c',
        command=['/tmp/lattica_pq_direct_spend_research-recorded',
                 runner.DIRECT_RING_SCREEN_TEST,
                 '--exact', '--ignored', '--test-threads=1', '--nocapture'])
    values.update(changes)
    return argparse.Namespace(**values)


class DirectRingScreenPolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.state = patch.object(runner, 'STATE', self.root)
        self.state.start()
        self.addCleanup(self.state.stop)

    def test_exact_screen_preserves_existing_limits_and_fresh_output(self):
        plan = runner.build_plan(arguments())
        baseline = runner.build_plan(arguments(direct_ring_screen=False))
        for key in ('memory_max_bytes', 'memory_high_bytes',
                    'fresh_memavailable_required_bytes', 'cpu_quota', 'profile'):
            self.assertEqual(plan[key], baseline[key])
        environment = plan['environment']
        expected = {
            'LATTICA_DIRECT_RING_SCREEN_QUALIFICATION': '1',
            'LATTICA_DIRECT_RING_SCREEN_OUTPUT_DIR': str(self.root / 'artifacts' / 'seven-ring-policy'),
            'LATTICA_PROVING_POLICY': 'gpu-required', 'LATTICA_PROVING_REPORT': '1',
            'LATTICA_V2_GPU_PUBLIC_HASH': 'baseline',
            'LATTICA_V2_GPU_RETAINED_TREE_STORAGE': 'host',
            'LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES': str(8 * runner.GIB),
            'LATTICA_V2_GPU_MANAGED_BYTES': str(8 * runner.GIB),
            'LATTICA_V2_GPU_CONTEXT_BYTES': str(4 * runner.GIB),
            'LATTICA_V2_HOST_OUTPUT_BYTES': str(32 * runner.GIB),
            'LATTICA_V2_GPU_LDE_WORKSPACE_BYTES': '0',
        }
        for key, value in expected.items():
            self.assertEqual(environment[key], value)
        self.assertEqual(plan['memory_max_bytes'], 45 * runner.GIB)
        self.assertEqual(plan['memory_high_bytes'], 43 * runner.GIB)
        self.assertEqual(plan['fresh_memavailable_required_bytes'], 47 * runner.GIB)
        self.assertFalse(plan['performance_qualified'])
        self.assertFalse(plan['direct_ring_screen_environment']['dispatch_authority'])
        self.assertFalse(plan['direct_ring_screen_environment']['complete_faithful_ringct_workflow'])
        self.assertIsNone(baseline['direct_ring_screen_environment'])
        self.assertNotIn('LATTICA_DIRECT_RING_SCREEN_QUALIFICATION', baseline['environment'])

    def test_wrong_modes_envelopes_or_missing_pin_refuse_before_dispatch(self):
        changes = [
            dict(profile=profile) for profile in ('build', 'research-compile', 'smoke', 'full')
        ] + [
            dict(build_label=None), dict(device_uuid=None), dict(expect_tests=False),
            dict(public_hash_kernel='sbox-pair-v1'), dict(retained_tree_storage='device'),
            dict(note_owned_proof=True), dict(note_workflow_cpu=True),
            dict(owned_runtime_test='native-shake'),
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                runner.build_plan(arguments(**change))

    def test_only_exact_recorded_selector_and_single_thread_are_accepted(self):
        original = arguments().command
        commands = [
            ['/usr/bin/cargo', *original[1:]],
            ['/tmp/lattica_prover_p3-recorded', *original[1:]],
            [original[0], original[1] + '-wrong', *original[2:]],
            [original[0], *original[2:]],
            [*original, '--exact'],
            [word for word in original if word != '--ignored'],
            [word.replace('--test-threads=1', '--test-threads=2') for word in original],
        ]
        for command in commands:
            with self.subTest(command=command), self.assertRaises(ValueError):
                runner.build_plan(arguments(command=command))

    def test_existing_or_dangling_symlink_output_is_not_reused(self):
        directory = self.root / 'artifacts'
        directory.mkdir()
        output = directory / 'seven-ring-policy'
        output.mkdir()
        with self.assertRaises(ValueError):
            runner.build_plan(arguments())
        output.rmdir()
        output.symlink_to(directory / 'missing')
        with self.assertRaises(ValueError):
            runner.build_plan(arguments())

    def test_output_path_source_bound_is_checked_before_launch(self):
        long_root = self.root / ('a' * 220) / ('b' * 220) / ('c' * 220) / ('d' * 220) / ('e' * 220)
        with patch.object(runner, 'STATE', long_root), self.assertRaises(ValueError):
            runner.build_plan(arguments())

    def test_existing_isolated_modes_cannot_be_combined(self):
        with self.assertRaises(ValueError):
            runner.build_plan(arguments(direct_ring_screen=False,
                                        note_owned_proof=True, note_workflow_cpu=True))


if __name__ == '__main__':
    unittest.main()
