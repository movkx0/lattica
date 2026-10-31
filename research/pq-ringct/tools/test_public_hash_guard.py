"""Execution-selector admission and evidence policy; never dispatches a GPU."""
import argparse
import json
from pathlib import Path
import tempfile
import unittest

import opencl_private_spend_validate as runner


def arguments(**changes):
    values = dict(profile='smoke', label='public-hash-policy', seconds=60,
                  command=['/tmp/recorded-tests', '--ignored', '--nocapture'],
                  expect_tests=True, expect_result=False, expect_direct_result=False,
                  build_label='recorded-build', record_artifact=[],
                  public_hash_kernel='sbox-pair-v1', retained_tree_storage='device')
    values.update(changes)
    return argparse.Namespace(**values)


class PublicHashGuardTests(unittest.TestCase):
    def test_candidate_preserves_limits_and_requires_gpu_recorded_execution(self):
        candidate = runner.build_plan(arguments())
        baseline = runner.build_plan(arguments(public_hash_kernel='baseline'))
        for key in ('memory_max_bytes', 'memory_high_bytes',
                    'fresh_memavailable_required_bytes', 'cpu_quota', 'runtime_seconds'):
            self.assertEqual(candidate[key], baseline[key])
        self.assertEqual(candidate['environment']['LATTICA_V2_GPU_PUBLIC_HASH'], 'sbox-pair-v1')
        self.assertEqual(baseline['environment']['LATTICA_V2_GPU_PUBLIC_HASH'], 'baseline')
        for changes in (
            {'profile': 'build'}, {'profile': 'research-compile'},
            {'public_hash_kernel': 'typo'}, {'build_label': None},
            {'command': ['/usr/bin/cargo', 'test']},
            {'expect_tests': False}, {'expect_result': True, 'expect_tests': False},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner.build_plan(arguments(**changes))

    def test_cpu_baseline_does_not_invent_gpu_selection(self):
        for profile in runner.CPU_PROFILES:
            plan = runner.build_plan(arguments(profile=profile, public_hash_kernel='baseline',
                                               build_label=None, command=['/usr/bin/cargo', 'test']))
            self.assertNotIn('LATTICA_V2_GPU_PUBLIC_HASH', plan['environment'])

    def accept(self, records, *, passing=True, kernel='sbox-pair-v1', environment=None):
        plan = runner.build_plan(arguments(public_hash_kernel=kernel))
        if environment is not None:
            plan['environment']['LATTICA_V2_GPU_PUBLIC_HASH'] = environment
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'result.log'
            log.write_text(''.join('PUBLIC_HASH_EXECUTION ' + json.dumps(record) + '\n'
                                   for record in records)
                           + ('test result: ok. 1 passed; 0 failed;\n' if passing else ''))
            runner.validate_output(log, plan)
        return plan

    def test_candidate_requires_matching_completed_execution_and_passing_tests(self):
        record = dict(kernel='sbox-pair-v1', gpu_tuning_compiled=True, nvidia_supported=True)
        self.assertEqual(self.accept([record])['public_hash_acceptance'], record)
        for changes in ({'kernel': 'baseline'}, {'gpu_tuning_compiled': False},
                        {'nvidia_supported': False}, {'gpu_tuning_compiled': 1}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.accept([{**record, **changes}])
        with self.assertRaises(ValueError):
            self.accept([])
        with self.assertRaises(ValueError):
            self.accept([record], passing=False)
        with self.assertRaises(ValueError):
            self.accept([record], environment='baseline')
        with self.assertRaises(ValueError):
            self.accept([record, {**record, 'kernel': 'baseline'}])

    def test_baseline_evidence_cannot_claim_an_unrequested_candidate(self):
        record = dict(kernel='baseline', gpu_tuning_compiled=True, nvidia_supported=True)
        self.assertEqual(self.accept([record], kernel='baseline')['public_hash_acceptance'], record)
        with self.assertRaises(ValueError):
            self.accept([{**record, 'kernel': 'sbox-pair-v1'}], kernel='baseline')

    def test_faithful_candidate_requires_full_profile_and_all_case_evidence(self):
        plan = runner.build_plan(arguments(profile='full', expect_tests=False, expect_result=True))
        record = dict(kernel='sbox-pair-v1', gpu_tuning_compiled=True, nvidia_supported=True)
        result = dict(context=dict(public_hash=record),
                      cases=[dict(public_hash=record), dict(public_hash=record)])
        self.assertEqual(runner.validate_faithful_public_hash(result, plan), record)
        for bad in (
            dict(context={}, cases=result['cases']),
            dict(context=result['context'], cases=[]),
            dict(context=result['context'], cases=[dict(public_hash=record), {}]),
            dict(context=result['context'], cases=[dict(public_hash={**record, 'kernel': 'baseline'})]),
            dict(context=result['context'], cases=[dict(public_hash={**record, 'gpu_tuning_compiled': 1})]),
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                runner.validate_faithful_public_hash(bad, plan)

    def test_faithful_baseline_also_binds_the_actual_kernel(self):
        plan = runner.build_plan(arguments(profile='full', expect_tests=False, expect_result=True,
                                           public_hash_kernel='baseline'))
        record = dict(kernel='baseline', gpu_tuning_compiled=True, nvidia_supported=True)
        result = dict(context=dict(public_hash=record), cases=[dict(public_hash=record)])
        self.assertEqual(runner.validate_faithful_public_hash(result, plan), record)
        different = {**record, 'kernel': 'sbox-pair-v1'}
        with self.assertRaises(ValueError):
            runner.validate_faithful_public_hash(
                dict(context=dict(public_hash=different), cases=[dict(public_hash=different)]), plan)


if __name__ == '__main__':
    unittest.main()
