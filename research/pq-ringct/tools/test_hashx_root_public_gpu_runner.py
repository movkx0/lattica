"""Runner routing tests; synthetic plans do not qualify GPU work."""
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
guard = module('hashx_root_public_gpu_guard')
SELECTOR = ('component_tree::owned_shake::request_merge::source::capture::acceptance::'
            'parent::production::sequence::qualification::gpu_original_hashx_sequence_root_public_recheck')
UUID = 'GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c'


def arguments(**changes):
    values = dict(profile='full', label='root-public-gpu-policy', seconds=60,
                  command=['/tmp/lattica_pq_ringct_research-recorded', SELECTOR,
                           '--exact', '--ignored', '--test-threads=1', '--nocapture'],
                  expect_tests=True, expect_result=False, expect_direct_result=False,
                  execute=True, exclusive_window=True, build_label='root-public-gpu-build',
                  record_artifact=[], retained_tree_storage='host', public_hash_kernel='baseline',
                  device_uuid=UUID, owned_hashx_root_public_test='gpu')
    values.update(changes)
    return argparse.Namespace(**values)


class RootPublicGpuRunnerTests(unittest.TestCase):
    def test_exact_mode_routes_to_dedicated_environment(self):
        plan = runner.build_plan(arguments())
        expected = guard.expected_environment(str(runner.ROOT), UUID)
        self.assertEqual(plan['environment'], expected)
        self.assertEqual(plan['owned_hashx_root_public_environment'], guard.receipt(expected))
        self.assertEqual(plan['command'], arguments().command)
        self.assertIsNone(plan['owned_hashx_leaf_environment'])
        self.assertIsNone(plan['owned_hashx_sequence_environment'])
        self.assertEqual(expected['LATTICA_OWNED_HASHX_ROOT_PUBLIC_QUALIFICATION'], '1')
        self.assertEqual(expected['LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION'], '1')
        self.assertIsNone(plan['owned_source_shape_environment'])
        self.assertEqual(plan['memory_max_bytes'], 47 << 30)
        self.assertEqual(plan['memory_high_bytes'], 45 << 30)
        self.assertEqual(plan['fresh_memavailable_required_bytes'], 49 << 30)
        self.assertEqual(plan['cpu_quota'], '800%')
        self.assertFalse(plan['performance_qualified'])
        self.assertFalse(plan['launch'])
        for flag in ('LATTICA_OWNED_HASHX_FIRST_LEAF_QUALIFICATION',
                     'LATTICA_NATIVE_SPEND_QUALIFICATION',
                     'LATTICA_OWNED_HASHX_SEQUENCE_SOURCE_QUALIFICATION',
                     'LATTICA_OWNED_HASHX_SEQUENCE_REFUSAL_QUALIFICATION'):
            self.assertNotIn(flag, expected)

    def test_leading_separator_has_same_exact_command(self):
        plan = runner.build_plan(arguments(command=['--', *arguments().command]))
        self.assertEqual(plan['command'], arguments().command)

    def test_global_mode_exclusion_precedes_environment_construction(self):
        modes = dict(note_owned_proof=True, note_workflow_cpu=True,
                     owned_runtime_test='runtime', direct_ring_screen=True,
                     owned_source_shape_test=True, active_hashx_preflight=True,
                     owned_request_source_test='parent-sources',
                     direct_ring_recursion_test='outer', owned_native_hashx_test='sequence',
                     owned_hashx_leaf_test='gpu', owned_hashx_sequence_test='preissue',
                     direct_ring_identity_test='receipt-v1')
        for key, value in modes.items():
            with self.subTest(mode=key), patch.object(runner, 'root_public_gpu_environment') as build:
                with self.assertRaisesRegex(ValueError, 'isolated qualification modes are exclusive'):
                    runner.build_plan(arguments(**{key: value}))
                build.assert_not_called()

    def test_cpu_guard_refuses_all_physical_sequence_siblings(self):
        for tail in ('gpu_original_hashx_sequence_root_public_recheck',
                     'gpu_original_hashx_sequence_preissue',
                     'gpu_original_hashx_sequence_source_authenticated',
                     'gpu_original_hashx_sequence_refusal_after_preissue',
                     'gpu_original_hashx_sequence_refusal_before_first_start',
                     'gpu_original_hashx_sequence_refusal_after_first_producer',
                     'gpu_original_hashx_sequence_refusal_after_first_acceptance'):
            command = list(arguments().command)
            command[1] = SELECTOR.rsplit('::', 1)[0] + '::' + tail
            with self.subTest(selector=tail), self.assertRaises(ValueError):
                runner.build_plan(arguments(profile='research-compile-large',
                    device_uuid=None, retained_tree_storage='device',
                    owned_hashx_root_public_test=None, owned_source_shape_test=True, command=command))

    def test_other_sequence_and_refusal_siblings_are_not_selectable(self):
        for tail in ('gpu_original_hashx_sequence_preissue',
                     'cpu_original_hashx_sequence_root_public_capacity',
                     'gpu_original_hashx_sequence_source_authenticated',
                     'gpu_original_hashx_sequence_refusal_after_preissue',
                     'gpu_original_hashx_sequence_refusal_before_first_start',
                     'gpu_original_hashx_sequence_refusal_after_first_producer',
                     'gpu_original_hashx_sequence_refusal_after_first_acceptance'):
            command = list(arguments().command)
            command[1] = SELECTOR.rsplit('::', 1)[0] + '::' + tail
            with self.subTest(selector=tail), self.assertRaises(ValueError):
                runner.build_plan(arguments(command=command))

    def test_output_requires_the_dedicated_parser(self):
        plan = runner.build_plan(arguments())
        # Generic libtest success must not bypass missing source/terminal evidence.
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'output.log'
            log.write_text('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
                           '0 filtered out; finished in 0.01s\n')
            with self.assertRaises(ValueError):
                runner.validate_output(log, plan)


if __name__ == '__main__':
    unittest.main()
