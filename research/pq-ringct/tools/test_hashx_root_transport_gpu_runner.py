"""Synthetic routing policy tests; these never qualify a GPU proof."""
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
guard = module('hashx_root_transport_gpu_guard')
PREFIX = ('component_tree::owned_shake::request_merge::source::capture::acceptance::'
          'parent::production::sequence::qualification::')
SELECTOR = PREFIX + 'transport::gpu_original_hashx_sequence_root_transport_roundtrip'
UUID = 'GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c'


def arguments(**changes):
    values = dict(profile='full', label='root-transport-gpu-policy', seconds=60,
                  command=['/tmp/lattica_pq_ringct_research-recorded', SELECTOR,
                           '--exact', '--ignored', '--test-threads=1', '--nocapture'],
                  expect_tests=True, expect_result=False, expect_direct_result=False,
                  execute=True, exclusive_window=True, build_label='root-transport-gpu-build',
                  record_artifact=[], retained_tree_storage='host', public_hash_kernel='baseline',
                  device_uuid=UUID, owned_hashx_root_transport_test='gpu')
    values.update(changes)
    return argparse.Namespace(**values)


class RootTransportGpuRunnerTests(unittest.TestCase):
    def test_exact_mode_has_dedicated_environment_and_unchanged_limits(self):
        plan = runner.build_plan(arguments())
        expected = guard.expected_environment(str(runner.ROOT), UUID)
        self.assertEqual(SELECTOR, guard.SELECTOR)
        self.assertEqual(plan['command'], arguments().command)
        self.assertEqual(plan['environment'], expected)
        self.assertEqual(plan['owned_hashx_root_transport_environment'], guard.receipt(expected))
        self.assertEqual(expected['LATTICA_OWNED_HASHX_ROOT_TRANSPORT_QUALIFICATION'], '1')
        self.assertEqual(expected['LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION'], '1')
        for receipt in ('owned_hashx_root_public_environment', 'owned_hashx_sequence_refusal_environment',
                        'owned_hashx_sequence_environment', 'owned_hashx_leaf_environment',
                        'owned_source_shape_environment'):
            self.assertIsNone(plan[receipt])
        for flag in ('LATTICA_OWNED_HASHX_ROOT_PUBLIC_QUALIFICATION',
                     'LATTICA_OWNED_HASHX_SEQUENCE_REFUSAL_QUALIFICATION',
                     'LATTICA_OWNED_HASHX_FIRST_LEAF_QUALIFICATION',
                     'LATTICA_OWNED_HASHX_SEQUENCE_SOURCE_QUALIFICATION'):
            self.assertNotIn(flag, expected)
        self.assertEqual(plan['memory_max_bytes'], 47 << 30)
        self.assertEqual(plan['memory_high_bytes'], 45 << 30)
        self.assertEqual(plan['fresh_memavailable_required_bytes'], 49 << 30)
        self.assertEqual(plan['cpu_quota'], '800%')
        self.assertFalse(plan['performance_qualified'])
        self.assertFalse(plan['launch'])

    def test_leading_separator_preserves_the_exact_command(self):
        plan = runner.build_plan(arguments(command=['--', *arguments().command]))
        self.assertEqual(plan['command'], arguments().command)

    def test_global_mode_exclusion_precedes_transport_environment_construction(self):
        modes = dict(note_owned_proof=True, note_workflow_cpu=True,
                     owned_runtime_test='runtime', direct_ring_screen=True,
                     owned_source_shape_test=True, active_hashx_preflight=True,
                     owned_request_source_test='parent-sources', direct_ring_recursion_test='outer',
                     owned_native_hashx_test='sequence', owned_hashx_leaf_test='gpu',
                     owned_hashx_sequence_test='preissue', owned_hashx_root_public_test='gpu',
                     owned_hashx_sequence_refusal_test='after-preissue',
                     direct_ring_identity_test='receipt-v1')
        for key, value in modes.items():
            with self.subTest(mode=key), patch.object(runner, 'root_transport_gpu_environment') as build:
                with self.assertRaisesRegex(ValueError, 'isolated qualification modes are exclusive'):
                    runner.build_plan(arguments(**{key: value}))
                build.assert_not_called()

    def test_transport_mode_requires_full_recorded_profile(self):
        changes = [dict(profile=name) for name in ('build', 'smoke', 'direct-full', 'research-compile-large')]
        changes += [dict(build_label=None), dict(device_uuid=None), dict(expect_tests=False)]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                runner.build_plan(arguments(**change))

    def test_dry_plan_remains_unlaunched_and_unqualified(self):
        plan = runner.build_plan(arguments(execute=False, exclusive_window=False))
        self.assertFalse(plan['launch'])
        self.assertFalse(plan['performance_qualified'])
        self.assertEqual(plan['environment'], guard.expected_environment(str(runner.ROOT), UUID))
        self.assertNotIn('owned_hashx_root_transport_qualification', plan)

    def test_transport_mode_rejects_existing_physical_and_capacity_selectors(self):
        for tail in ('gpu_original_hashx_sequence_root_public_recheck',
                     'gpu_original_hashx_sequence_preissue',
                     'cpu_original_hashx_sequence_root_public_capacity',
                     'transport::cpu_original_hashx_sequence_root_transport_capacity',
                     'gpu_original_hashx_sequence_source_authenticated',
                     'gpu_original_hashx_sequence_refusal_after_preissue',
                     'gpu_original_hashx_sequence_refusal_before_first_start',
                     'gpu_original_hashx_sequence_refusal_after_first_producer',
                     'gpu_original_hashx_sequence_refusal_after_first_acceptance'):
            command = list(arguments().command)
            command[1] = PREFIX + tail
            with self.subTest(selector=tail), self.assertRaises(ValueError):
                runner.build_plan(arguments(command=command))

    def test_source_only_route_refuses_the_physical_transport_selector(self):
        with self.assertRaises(ValueError):
            runner.build_plan(arguments(profile='research-compile-large', device_uuid=None,
                                        owned_hashx_root_transport_test=None, owned_source_shape_test=True))

    def test_generic_libtest_success_does_not_bypass_transport_evidence(self):
        plan = runner.build_plan(arguments())
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'output.log'
            log.write_text('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
                           '0 filtered out; finished in 0.01s\n')
            with self.assertRaises(ValueError):
                runner.validate_output(log, plan)


if __name__ == '__main__':
    unittest.main()
