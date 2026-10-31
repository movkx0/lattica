"""Exact single-case receipt experiment isolation; no build or GPU execution."""
import argparse
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('identity_guard', Path(__file__).with_name('opencl_private_spend_validate.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def arguments(mode='baseline', **changes):
    values = dict(profile='direct-full', label='identity-policy', seconds=60,
        expect_tests=True, expect_result=False, expect_direct_result=False,
        execute=True, exclusive_window=True, build_label='identity-build', record_artifact=[],
        direct_ring_identity_test=mode, retained_tree_storage='host', public_hash_kernel='baseline',
        device_uuid='GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c',
        command=['/tmp/lattica_pq_direct_spend_research-recorded', runner.DIRECT_RING_IDENTITY_TESTS[mode],
                 '--exact', '--ignored', '--test-threads=1', '--nocapture'])
    values.update(changes)
    return argparse.Namespace(**values)


class DirectRingIdentityPolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        state = patch.object(runner, 'STATE', self.root)
        state.start()
        self.addCleanup(state.stop)

    def test_both_modes_preserve_limits_and_bind_mode_selector_environment(self):
        for mode in runner.DIRECT_RING_IDENTITY_TESTS:
            plan = runner.build_plan(arguments(mode))
            base = runner.build_plan(arguments(mode, direct_ring_identity_test=None))
            for key in ('memory_max_bytes', 'memory_high_bytes', 'fresh_memavailable_required_bytes', 'cpu_quota', 'profile'):
                self.assertEqual(plan[key], base[key])
            expected = dict(base['environment'], LATTICA_DIRECT_RING_IDENTITY_QUALIFICATION='1',
                LATTICA_DIRECT_RING_IDENTITY_OUTPUT_DIR=str(self.root/'artifacts'/'identity-policy'),
                LATTICA_DIRECT_RING_IDENTITY_MODE=mode)
            self.assertEqual(plan['environment'], expected)
            self.assertEqual(expected['LATTICA_V2_HOST_OUTPUT_BYTES'], str(32*runner.GIB))
            self.assertEqual(expected['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'], str(8*runner.GIB))
            self.assertEqual(plan['memory_max_bytes'],45*runner.GIB)
            self.assertEqual(plan['memory_high_bytes'],43*runner.GIB)
            self.assertEqual(plan['fresh_memavailable_required_bytes'],47*runner.GIB)
            receipt=plan['direct_ring_identity_environment']
            self.assertEqual(receipt['mode'],mode)
            self.assertEqual(receipt['selector'],runner.DIRECT_RING_IDENTITY_TESTS[mode])
            for key in ('performance_qualified','complete_faithful_ringct_workflow','n3_n4_aggregate_qualification','dispatch_authority'):
                self.assertFalse(receipt[key])
            self.assertIsNone(base['direct_ring_identity_environment'])
            self.assertNotIn('LATTICA_DIRECT_RING_SCREEN_QUALIFICATION',expected)

    def test_mode_selector_mismatch_and_argument_changes_refuse(self):
        for mode in runner.DIRECT_RING_IDENTITY_TESTS:
            argv=arguments(mode).command
            other=next(v for k,v in runner.DIRECT_RING_IDENTITY_TESTS.items() if k != mode)
            for command in ([argv[0],other,*argv[2:]],['/usr/bin/cargo',*argv[1:]],
                            [*argv,'--exact'],[s for s in argv if s!='--ignored'],
                            [s.replace('--test-threads=1','--test-threads=2') for s in argv],
                            [argv[0],*argv[2:],argv[1]]):
                with self.subTest(mode=mode,command=command),self.assertRaises(ValueError):
                    runner.build_plan(arguments(mode,command=command))

    def test_modes_are_exclusive_and_missing_identity_or_other_profiles_refuse(self):
        changes=[dict(profile=p) for p in runner.PROFILES if p!='direct-full']
        changes += [dict(build_label=None),dict(device_uuid=None),dict(expect_tests=False),
                    dict(retained_tree_storage='device'),dict(public_hash_kernel='sbox-pair-v1'),
                    dict(expect_result=True),dict(expect_direct_result=True),dict(benchmark=True),
                    dict(direct_ring_screen=True),dict(owned_source_shape_test=True),
                    dict(note_owned_proof=True),dict(note_workflow_cpu=True),dict(owned_runtime_test='native-to-outer'),
                    dict(direct_ring_identity_test='unknown')]
        for change in changes:
            with self.subTest(change=change),self.assertRaises(ValueError):
                runner.build_plan(arguments(**change))

    def test_existing_output_symlink_and_long_paths_refuse(self):
        directory=self.root/'artifacts';directory.mkdir()
        out=directory/'identity-policy';out.mkdir()
        with self.assertRaises(ValueError): runner.build_plan(arguments())
        out.rmdir();out.symlink_to(directory/'missing')
        with self.assertRaises(ValueError): runner.build_plan(arguments())
        long=self.root/('a'*220)/('b'*220)/('c'*220)/('d'*220)/('e'*220)
        with patch.object(runner,'STATE',long),self.assertRaises(ValueError): runner.build_plan(arguments())


if __name__=='__main__':
    unittest.main()
