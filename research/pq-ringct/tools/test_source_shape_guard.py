"""Exact CPU-only source-shape guard policy; does not launch proving."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import unittest
import tempfile

spec = importlib.util.spec_from_file_location('source_shape_guard', Path(__file__).with_name('opencl_private_spend_validate.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def arguments(**changes):
    values = dict(profile='research-compile-large', label='source-shape-policy', seconds=60,
                  command=['/tmp/lattica_pq_ringct_research-recorded', runner.OWNED_SOURCE_SHAPE_TEST,
                           '--exact', '--ignored', '--test-threads=1', '--nocapture'],
                  expect_tests=True, expect_result=False, expect_direct_result=False,
                  execute=True, exclusive_window=True, build_label='source-shape-build',
                  record_artifact=[], owned_source_shape_test=True)
    values.update(changes)
    return argparse.Namespace(**values)


class SourceShapeGuardTests(unittest.TestCase):
    def test_root_public_capacity_has_exact_two_cpu_opt_ins(self):
        command = ['/tmp/lattica_pq_ringct_research-recorded',
                   runner.ORIGINAL_HASHX_ROOT_PUBLIC_SOURCE_TEST,
                   '--exact', '--ignored', '--test-threads=1', '--nocapture']
        plan = runner.build_plan(arguments(command=command))
        base = runner.build_plan(arguments(command=command, owned_source_shape_test=False))
        expected = dict(base['environment'],
                        LATTICA_OWNED_HASHX_SEQUENCE_SOURCE_QUALIFICATION='1',
                        LATTICA_OWNED_HASHX_ROOT_PUBLIC_SOURCE_QUALIFICATION='1')
        self.assertEqual(plan['environment'], expected)
        self.assertEqual(expected['LATTICA_PROVING_POLICY'], 'cpu-required')
        self.assertFalse(any('GPU' in key for key in expected))
        self.assertNotIn('LATTICA_OWNED_SHAKE_QUALIFICATION', expected)
        self.assertNotIn('LATTICA_OWNED_HASHX_ROOT_PUBLIC_QUALIFICATION', expected)
        for key in ('memory_max_bytes', 'memory_high_bytes',
                    'fresh_memavailable_required_bytes', 'cpu_quota'):
            self.assertEqual(plan[key], base[key])
        receipt = plan['owned_source_shape_environment']
        self.assertEqual(receipt['selector'], runner.ORIGINAL_HASHX_ROOT_PUBLIC_SOURCE_TEST)
        encoded = b''.join((key + '=' + expected[key] + '\0').encode()
                           for key in sorted(expected))
        self.assertEqual(receipt['entry_count'], len(expected))
        self.assertEqual(receipt['serialized_bytes'], len(encoded))
        self.assertEqual(receipt['sha256_sorted_name_equals_value_nul'],
                         hashlib.sha256(encoded).hexdigest())
        for tail in ('gpu_original_hashx_sequence_root_public_recheck',
                     'gpu_original_hashx_sequence_preissue',
                     'gpu_original_hashx_sequence_source_authenticated',
                     'gpu_original_hashx_sequence_refusal_after_preissue'):
            changed = [command[0], command[1].rsplit('::', 1)[0] + '::' + tail, *command[2:]]
            with self.subTest(selector=tail), self.assertRaises(ValueError):
                runner.build_plan(arguments(command=changed))
        for changed in [command + ['--skip', command[1]], command[:-1],
                        [command[0], command[1] + 'other', *command[2:]]]:
            with self.subTest(command=changed), self.assertRaises(ValueError):
                runner.build_plan(arguments(command=changed))

    def test_root_public_capacity_requires_dedicated_evidence(self):
        command = ['/tmp/lattica_pq_ringct_research-recorded',
                   runner.ORIGINAL_HASHX_ROOT_PUBLIC_SOURCE_TEST,
                   '--exact', '--ignored', '--test-threads=1', '--nocapture']
        plan = runner.build_plan(arguments(command=command))
        plan['observation_before_validation_ns'] = 1000
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'output.log'
            log.write_text('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
                           '0 filtered out; finished in 0.01s\n')
            with self.assertRaises(ValueError):
                runner.validate_output(log, plan)

    def test_original_hashx_sequence_exact_cpu_selector(self):
        command = ['/tmp/lattica_pq_ringct_research-recorded',
                   runner.ORIGINAL_HASHX_SEQUENCE_SOURCE_TEST,
                   '--exact', '--ignored', '--test-threads=1', '--nocapture']
        plan = runner.build_plan(arguments(command=command))
        base = runner.build_plan(arguments(command=command, owned_source_shape_test=False))
        expected = dict(base['environment'], LATTICA_OWNED_HASHX_SEQUENCE_SOURCE_QUALIFICATION='1')
        self.assertEqual(plan['environment'], expected)
        self.assertEqual(plan['environment']['LATTICA_PROVING_POLICY'], 'cpu-required')
        self.assertNotIn('LATTICA_OWNED_SHAKE_QUALIFICATION', plan['environment'])
        self.assertNotIn('LATTICA_OWNED_SHAKE_BANK_SOURCE_QUALIFICATION', plan['environment'])
        self.assertNotIn('LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION', plan['environment'])
        self.assertFalse(any('GPU' in key for key in plan['environment']))
        for key in ('memory_max_bytes', 'memory_high_bytes',
                    'fresh_memavailable_required_bytes', 'cpu_quota'):
            self.assertEqual(plan[key], base[key])
        encoded = b''.join((key + '=' + expected[key] + '\0').encode()
                           for key in sorted(expected))
        receipt = plan['owned_source_shape_environment']
        self.assertEqual(receipt['selector'], runner.ORIGINAL_HASHX_SEQUENCE_SOURCE_TEST)
        self.assertEqual(receipt['entry_count'], len(expected))
        self.assertEqual(receipt['serialized_bytes'], len(encoded))
        self.assertEqual(receipt['sha256_sorted_name_equals_value_nul'],
                         hashlib.sha256(encoded).hexdigest())
        for key in ('gpu_dispatch', 'performance_qualified', 'complete_faithful_ringct_workflow'):
            self.assertFalse(receipt[key])
        gpu_selectors = [command[1].replace('cpu_original_hashx_sequence_capacity', suffix)
                         for suffix in ('gpu_original_hashx_sequence_preissue',
                                        'gpu_original_hashx_sequence_source_authenticated')]
        for changed in [[command[0], command[1] + 'other', *command[2:]],
                        ['/tmp/lattica_prover_p3-recorded', *command[1:]],
                        [word for word in command if word != '--ignored'],
                        [word for word in command if word != '--exact'],
                        command + ['--skip', runner.ORIGINAL_HASHX_SEQUENCE_SOURCE_TEST],
                        *[[command[0], gpu, *command[2:]] for gpu in gpu_selectors]]:
            with self.subTest(command=changed), self.assertRaises(ValueError):
                runner.build_plan(arguments(command=changed))

    def test_original_compiler_bank_exact_cpu_selector(self):
        command = ['/tmp/lattica_pq_ringct_research-recorded',
                   runner.ORIGINAL_COMPILER_BANK_SOURCE_TEST,
                   '--exact', '--ignored', '--test-threads=1', '--nocapture']
        plan = runner.build_plan(arguments(command=command))
        base = runner.build_plan(arguments(command=command, owned_source_shape_test=False))
        expected = dict(base['environment'], LATTICA_OWNED_SHAKE_BANK_SOURCE_QUALIFICATION='1')
        self.assertEqual(plan['environment'], expected)
        self.assertEqual(plan['environment']['LATTICA_PROVING_POLICY'], 'cpu-required')
        self.assertNotIn('LATTICA_OWNED_SHAKE_QUALIFICATION', plan['environment'])
        self.assertFalse(any('GPU' in key for key in plan['environment']))
        for key in ('memory_max_bytes', 'memory_high_bytes',
                    'fresh_memavailable_required_bytes', 'cpu_quota'):
            self.assertEqual(plan[key], base[key])
        encoded = b''.join((key + '=' + expected[key] + '\0').encode()
                           for key in sorted(expected))
        receipt = plan['owned_source_shape_environment']
        self.assertEqual(receipt['selector'], runner.ORIGINAL_COMPILER_BANK_SOURCE_TEST)
        self.assertEqual(receipt['entry_count'], len(expected))
        self.assertEqual(receipt['serialized_bytes'], len(encoded))
        self.assertEqual(receipt['sha256_sorted_name_equals_value_nul'],
                         hashlib.sha256(encoded).hexdigest())
        for key in ('gpu_dispatch', 'performance_qualified', 'complete_faithful_ringct_workflow'):
            self.assertFalse(receipt[key])
        for changed in [[command[0], command[1] + 'other', *command[2:]],
                        ['/tmp/lattica_prover_p3-recorded', *command[1:]],
                        [word for word in command if word != '--ignored'],
                        [word for word in command if word != '--exact'],
                        command + ['--skip', runner.ORIGINAL_COMPILER_BANK_SOURCE_TEST]]:
            with self.subTest(command=changed), self.assertRaises(ValueError):
                runner.build_plan(arguments(command=changed))

    def test_parent_actual_input_check_is_exact_and_cpu_only(self):
        command = ['/tmp/lattica_prover_p3-recorded', runner.PARENT_SOURCE_INPUT_TEST,
                   '--exact', '--ignored', '--test-threads=1', '--nocapture']
        plan = runner.build_plan(arguments(command=command))
        self.assertEqual(plan['owned_source_shape_environment']['selector'], runner.PARENT_SOURCE_INPUT_TEST)
        self.assertEqual(plan['environment']['LATTICA_OWNED_SHAKE_QUALIFICATION'], '1')
        self.assertEqual(plan['environment']['LATTICA_PROVING_POLICY'], 'cpu-required')
        self.assertFalse(any('GPU' in name for name in plan['environment']))
        for changed in [[command[0], command[1] + 'other', *command[2:]],
                        ['/tmp/lattica_pq_ringct_research-recorded', *command[1:]],
                        [word for word in command if word != '--ignored'],
                        [word for word in command if word != '--exact'],
                        command + ['--skip', runner.PARENT_SOURCE_INPUT_TEST]]:
            with self.subTest(command=changed), self.assertRaises(ValueError):
                runner.build_plan(arguments(command=changed))

    def test_exact_cpu_environment_and_existing_limits(self):
        plan = runner.build_plan(arguments())
        base = runner.build_plan(arguments(owned_source_shape_test=False))
        expected = dict(base['environment'], LATTICA_OWNED_SHAKE_QUALIFICATION='1')
        self.assertEqual(plan['environment'], expected)
        self.assertEqual(expected['LATTICA_PROVING_POLICY'], 'cpu-required')
        self.assertFalse(any('GPU' in key for key in expected))
        for key in ('memory_max_bytes', 'memory_high_bytes', 'fresh_memavailable_required_bytes', 'cpu_quota'):
            self.assertEqual(plan[key], base[key])
        encoded = b''.join((k + '=' + expected[k] + '\0').encode() for k in sorted(expected))
        receipt = plan['owned_source_shape_environment']
        self.assertEqual(receipt['selector'], runner.OWNED_SOURCE_SHAPE_TEST)
        self.assertEqual(receipt['entry_count'], len(expected))
        self.assertEqual(receipt['serialized_bytes'], len(encoded))
        self.assertEqual(receipt['sha256_sorted_name_equals_value_nul'], hashlib.sha256(encoded).hexdigest())
        for key in ('gpu_dispatch', 'performance_qualified', 'complete_faithful_ringct_workflow'):
            self.assertFalse(receipt[key])
        self.assertIsNone(base['owned_source_shape_environment'])
        self.assertNotIn('LATTICA_OWNED_SHAKE_QUALIFICATION', base['environment'])

    def test_refuses_other_profiles_modes_and_overrides(self):
        variants = [dict(profile=p) for p in runner.PROFILES if p != 'research-compile-large']
        variants += [dict(build_label=None), dict(expect_tests=False), dict(expect_result=True),
                     dict(expect_direct_result=True), dict(benchmark=True),
                     dict(device_uuid='GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c'),
                     dict(retained_tree_storage='host'), dict(public_hash_kernel='sbox-pair-v1'),
                     dict(note_owned_proof=True), dict(note_workflow_cpu=True),
                     dict(direct_ring_screen=True), dict(owned_runtime_test='native-shake')]
        for changes in variants:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner.build_plan(arguments(**changes))

    def test_refuses_nonexact_or_foreign_worker_commands(self):
        original = arguments().command
        variants = [original + ['extra'],
                    ['/tmp/lattica_prover_p3-recorded', *original[1:]],
                    [original[0], 'different_test', *original[2:]],
                    [word for word in original if word != '--exact'],
                    [word for word in original if word != '--ignored'],
                    [word.replace('--test-threads=1', '--test-threads=2') for word in original]]
        for command in variants:
            with self.subTest(command=command), self.assertRaises(ValueError):
                runner.build_plan(arguments(command=command))


if __name__ == '__main__':
    unittest.main()
