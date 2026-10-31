"""Synthetic exact CPU capacity routing checks; no proving execution."""
import argparse
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


runner = module('opencl_private_spend_validate')
guard = module('hashx_root_opening_capacity_guard')
PREFIX = ('component_tree::owned_shake::request_merge::source::capture::acceptance::'
          'parent::production::sequence::qualification::')
SELECTOR = PREFIX + 'opening::cpu_original_hashx_sequence_root_opening_capacity'


def arguments(**changes):
    values = dict(profile='research-compile-large', label='root-opening-capacity-policy',
                  seconds=60, command=['/tmp/lattica_pq_ringct_research-recorded', SELECTOR,
                                      '--exact', '--ignored', '--test-threads=1', '--nocapture'],
                  expect_tests=True, expect_result=False, expect_direct_result=False,
                  execute=True, exclusive_window=True, build_label='root-opening-capacity-build',
                  record_artifact=[], retained_tree_storage='device', public_hash_kernel='baseline',
                  device_uuid=None, owned_source_shape_test=True)
    values.update(changes)
    return argparse.Namespace(**values)


class RootOpeningCapacityRunnerTests(unittest.TestCase):
    def test_exact_capacity_route_has_dedicated_cpu_receipt(self):
        plan = runner.build_plan(arguments())
        expected = guard.expected_environment(str(runner.ROOT))
        self.assertEqual(SELECTOR, guard.SELECTOR)
        self.assertEqual(plan['command'], arguments().command)
        self.assertEqual(plan['environment'], expected)
        self.assertEqual(plan['owned_source_shape_environment'], guard.receipt(expected))
        self.assertEqual(expected['LATTICA_OWNED_HASHX_ROOT_OPENING_SOURCE_QUALIFICATION'], '1')
        self.assertEqual(expected['LATTICA_OWNED_HASHX_SEQUENCE_SOURCE_QUALIFICATION'], '1')
        self.assertEqual(expected['LATTICA_PROVING_POLICY'], 'cpu-required')
        self.assertFalse(any('GPU' in key for key in expected))
        self.assertNotIn('LATTICA_OWNED_HASHX_ROOT_OPENING_QUALIFICATION', expected)
        self.assertIsNone(plan['owned_hashx_root_opening_environment'])
        self.assertEqual(plan['memory_max_bytes'], 32 << 30)
        self.assertEqual(plan['memory_high_bytes'], 30 << 30)
        self.assertEqual(plan['fresh_memavailable_required_bytes'], 36 << 30)
        self.assertEqual(plan['cpu_quota'], '200%')
        self.assertFalse(plan['performance_qualified'])
        self.assertFalse(plan['launch'])

    def test_leading_separator_preserves_exact_selector(self):
        plan = runner.build_plan(arguments(command=['--', *arguments().command]))
        self.assertEqual(plan['command'], arguments().command)

    def test_capacity_keeps_profile_and_no_gpu_requirements(self):
        changes = [dict(profile=name) for name in ('build', 'smoke', 'full', 'direct-full')]
        changes += [dict(build_label=None), dict(expect_tests=False),
                    dict(device_uuid='GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c'),
                    dict(retained_tree_storage='host'), dict(public_hash_kernel='sbox-pair-v1')]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                runner.build_plan(arguments(**change))

    def test_mode_exclusion_precedes_source_environment_construction(self):
        for mode in ('owned_hashx_root_transport_test', 'owned_hashx_root_opening_test', 'owned_hashx_root_public_test',
                     'owned_hashx_leaf_test'):
            with self.subTest(mode=mode), patch.object(runner, 'source_shape_environment') as build:
                with self.assertRaisesRegex(ValueError, 'isolated qualification modes are exclusive'):
                    runner.build_plan(arguments(**{mode: 'gpu'}))
                build.assert_not_called()

    def test_physical_opening_selector_is_not_a_capacity_fallback(self):
        command = list(arguments().command)
        command[1] = PREFIX + 'opening::gpu_original_hashx_sequence_root_opening_recheck'
        with self.assertRaises(ValueError):
            runner.build_plan(arguments(command=command))

    def test_existing_cpu_modes_keep_their_own_receipts(self):
        for tail in ('transport::cpu_original_hashx_sequence_root_transport_capacity',
                     'cpu_original_hashx_sequence_capacity',
                     'cpu_original_hashx_sequence_root_public_capacity'):
            command = list(arguments().command)
            command[1] = PREFIX + tail
            with self.subTest(selector=tail):
                plan = runner.build_plan(arguments(command=command))
                self.assertEqual(plan['owned_source_shape_environment']['selector'], command[1])
                self.assertNotEqual(plan['owned_source_shape_environment']['schema'],
                                    guard.receipt(guard.expected_environment(str(runner.ROOT)))['schema'])
                self.assertNotIn('LATTICA_OWNED_HASHX_ROOT_OPENING_SOURCE_QUALIFICATION',
                                 plan['environment'])

    def test_dry_plan_carries_no_execution_result(self):
        plan = runner.build_plan(arguments(execute=False, exclusive_window=False))
        self.assertFalse(plan['launch'])
        self.assertFalse(plan['performance_qualified'])
        self.assertEqual(plan['environment'], guard.expected_environment(str(runner.ROOT)))
        self.assertNotIn('owned_hashx_root_opening_capacity_qualification', plan)

    def test_generic_test_success_cannot_qualify_capacity(self):
        plan = runner.build_plan(arguments())
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'output.log'
            log.write_text('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
                           '0 filtered out; finished in 0.01s\n')
            with self.assertRaises(ValueError):
                runner.validate_output(log, plan)


if __name__ == '__main__':
    unittest.main()
