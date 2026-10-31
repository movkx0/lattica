"""Synthetic routing checks; no physical cleanup or proving qualification."""
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
guard = module('hashx_sequence_refusal_guard')
UUID = 'GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c'
MODES = ('after-preissue', 'before-first-start', 'after-first-producer', 'after-first-acceptance')


def arguments(mode='after-preissue', **changes):
    values = dict(profile='full', label='sequence-refusal-policy', seconds=60,
                  command=['/tmp/lattica_pq_ringct_research-recorded', guard.selector(mode),
                           '--exact', '--ignored', '--test-threads=1', '--nocapture'],
                  expect_tests=True, expect_result=False, expect_direct_result=False,
                  execute=True, exclusive_window=True, build_label='sequence-refusal-build',
                  record_artifact=[], retained_tree_storage='host', public_hash_kernel='baseline',
                  device_uuid=UUID, owned_hashx_sequence_refusal_test=mode)
    values.update(changes)
    return argparse.Namespace(**values)


class SequenceRefusalRunnerTests(unittest.TestCase):
    def test_each_exact_mode_routes_to_dedicated_environment(self):
        for mode in MODES:
            with self.subTest(mode=mode):
                plan = runner.build_plan(arguments(mode))
                expected = guard.expected_environment(str(runner.ROOT), UUID)
                self.assertEqual(plan['environment'], expected)
                self.assertEqual(plan[guard.ENV_KEY], guard.receipt(mode, expected))
                self.assertEqual(plan['command'], arguments(mode).command)
                for key in ('owned_hashx_leaf_environment', 'owned_hashx_sequence_environment',
                            'owned_hashx_root_public_environment', 'owned_source_shape_environment'):
                    self.assertIsNone(plan[key])
                self.assertEqual(expected['LATTICA_OWNED_HASHX_SEQUENCE_REFUSAL_QUALIFICATION'], '1')
                self.assertEqual(expected['LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION'], '1')
                self.assertEqual(plan['memory_max_bytes'], 47 << 30)
                self.assertEqual(plan['memory_high_bytes'], 45 << 30)
                self.assertEqual(plan['fresh_memavailable_required_bytes'], 49 << 30)
                self.assertEqual(plan['cpu_quota'], '800%')
                self.assertFalse(plan['performance_qualified'])
                self.assertFalse(plan['launch'])
                for flag in ('LATTICA_OWNED_HASHX_FIRST_LEAF_QUALIFICATION',
                             'LATTICA_NATIVE_SPEND_QUALIFICATION',
                             'LATTICA_OWNED_HASHX_SEQUENCE_SOURCE_QUALIFICATION',
                             'LATTICA_OWNED_HASHX_ROOT_PUBLIC_QUALIFICATION'):
                    self.assertNotIn(flag, expected)

    def test_leading_separator_has_same_exact_command(self):
        for mode in MODES:
            plan = runner.build_plan(arguments(mode, command=['--', *arguments(mode).command]))
            self.assertEqual(plan['command'], arguments(mode).command)

    def test_global_mode_exclusion_precedes_environment_construction(self):
        modes = dict(note_owned_proof=True, note_workflow_cpu=True,
                     owned_runtime_test='runtime', direct_ring_screen=True,
                     owned_source_shape_test=True, active_hashx_preflight=True,
                     owned_request_source_test='parent-sources',
                     direct_ring_recursion_test='outer', owned_native_hashx_test='sequence',
                     owned_hashx_leaf_test='gpu', owned_hashx_sequence_test='preissue',
                     owned_hashx_root_public_test='gpu', direct_ring_identity_test='receipt-v1')
        for key, value in modes.items():
            with self.subTest(mode=key), patch.object(runner, 'sequence_refusal_environment') as build:
                with self.assertRaisesRegex(ValueError, 'isolated qualification modes are exclusive'):
                    runner.build_plan(arguments(**{key: value}))
                build.assert_not_called()

    def test_option_must_match_each_exact_selector(self):
        for mode in MODES:
            for other in MODES:
                if mode != other:
                    with self.subTest(mode=mode, selector=other), self.assertRaises(ValueError):
                        runner.build_plan(arguments(mode, command=arguments(other).command))

    def test_cpu_guard_refuses_all_physical_refusal_selectors(self):
        for mode in MODES:
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                runner.build_plan(arguments(mode, profile='research-compile-large',
                    device_uuid=None, retained_tree_storage='device',
                    owned_hashx_sequence_refusal_test=None, owned_source_shape_test=True))

    def test_non_refusal_siblings_are_not_selectable(self):
        prefix = guard.SELECTOR_PREFIX.rsplit('::', 1)[0] + '::'
        for tail in ('gpu_original_hashx_sequence_preissue',
                     'gpu_original_hashx_sequence_root_public_recheck',
                     'cpu_original_hashx_sequence_root_public_capacity',
                     'gpu_original_hashx_sequence_source_authenticated'):
            command = list(arguments().command)
            command[1] = prefix + tail
            with self.subTest(selector=tail), self.assertRaises(ValueError):
                runner.build_plan(arguments(command=command))

    def test_generic_success_cannot_bypass_refusal_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'output.log'
            log.write_text('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
                           '0 filtered out; finished in 0.01s\n')
            for mode in MODES:
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    runner.validate_output(log, runner.build_plan(arguments(mode)))


if __name__ == '__main__':
    unittest.main()
