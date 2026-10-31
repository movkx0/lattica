"""Correctness-runner policy tests; no compiler, prover or GPU is launched."""
import argparse
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('opt_validate', Path(__file__).with_name('opencl_opt_validate.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def arguments(**changes):
    values = dict(profile='build', label='policy-test', seconds=60,
                  command=['--', '/usr/bin/true'], expect_tests=False,
                  expect_result=False, execute=True, exclusive_window=True,
                  build_label=None, record_artifact=[])
    values.update(changes)
    return argparse.Namespace(**values)


class CorrectnessPolicyTests(unittest.TestCase):
    def result(self):
        family = dict(reads=0, hits=0, bypasses=1, proof_attempts=1, fresh_proofs=1)
        case = dict(count=3, fresh_distinct_transactions=3, complete_graphs_verified=3,
                    statement_digests=[[1], [2], [3]], changed_public_rejected_count=25,
                    changed_proof_rejected=True, distinct_reordering_rejected=True,
                    distinct_substitution_rejected=True, graph_proof_substitution_rejected=True,
                    decoded_verification_after_gpu_shutdown=True, merges=[dict(backend='opencl',
                        strict_gpu_request=True, native_parent_verification=True, cache_policy='fresh_only',
                        proof_cache_hit=False, aggregate_children=n,
                        recursive_witness_checks=[dict(altered_opening_rejected=True)] * n) for n in [0, 1]],
                    cache=dict(policy='fresh_only', families={name: family.copy() for name in
                         ['sources', 'algebra', 'crypto', 'auxiliary', 'outer']}))
        return dict(schema='pq-opencl-opt-correctness-v1', passed=True, comparison_baseline=False,
                    proving_scope='native_and_recursive_stark_proving', fixture_generation='cpu_native_matrict',
                    independent_verification='cpu', native_gpu_required=True, witness_preparation='gpu_required',
                    performance_qualified=False, fixture_pattern='fresh_distinct', original_profile=True,
                    hiding=True, num_queries=128, blowup=16, extension='Goldilocks cubic trinomial',
                    context=dict(session_closed=True, prepared_entries=0, maximum_prepared_entries=1,
                        metadata_cache_payload_bytes=1024, session_finish=dict(commits=3, allocations=3,
                        managed_peak_bytes=runner.GIB)), cases=[case])

    def test_results_require_fresh_work_tamper_checks_and_session_cleanup(self):
        result = self.result()
        runner.validate_result(result)
        mutations = [
            lambda r: r['context'].update(session_closed=False),
            lambda r: r['context'].update(metadata_cache_payload_bytes=(64 << 20) + 1),
            lambda r: r['cases'][0]['cache']['families']['sources'].update(reads=1),
            lambda r: r['cases'][0]['cache']['families']['outer'].update(proof_attempts=2),
            lambda r: r['cases'][0]['cache']['families']['auxiliary'].update(proof_attempts=0, fresh_proofs=0),
            lambda r: r['cases'][0].update(changed_public_rejected_count=24),
            lambda r: r['cases'][0].update(statement_digests=[[1], [1], [2]]),
            lambda r: r['cases'][0].update(decoded_verification_after_gpu_shutdown=False),
            lambda r: r.update(num_queries=64),
            lambda r: r['cases'][0]['merges'][1].update(recursive_witness_checks=[]),
        ]
        for mutate in mutations:
            changed = copy.deepcopy(result)
            mutate(changed)
            with self.assertRaises(ValueError):
                runner.validate_result(changed)

    def test_resource_profiles_preserve_separate_host_and_device_limits(self):
        for profile, expected in [('build', (8, 6, 10)), ('smoke', (16, 14, 20)), ('full', (47, 45, 49))]:
            plan = runner.build_plan(arguments(profile=profile))
            self.assertEqual(tuple(plan[key] // runner.GIB for key in
                                   ['memory_max_bytes', 'memory_high_bytes', 'fresh_memavailable_required_bytes']), expected)
            self.assertFalse(plan['comparison_baseline'])
            self.assertFalse(plan['performance_qualified'])
            if profile != 'build':
                self.assertEqual(plan['environment']['LATTICA_V2_GPU_MANAGED_BYTES'], str(8 * runner.GIB))
                self.assertEqual(plan['environment']['LATTICA_V2_GPU_CONTEXT_BYTES'], str(4 * runner.GIB))
                self.assertEqual(plan['environment']['LATTICA_V2_QUOTIENT_FUSION'], '1')

    def test_admission_arguments_are_bounded(self):
        for changes in [dict(label='../escape'), dict(command=['cargo']), dict(command=[]),
                        dict(seconds=0), dict(seconds=7201), dict(expect_tests=True, expect_result=True)]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner.build_plan(arguments(**changes))
        runner.build_plan(arguments(profile='full', seconds=86400))
        with self.assertRaises(ValueError):
            runner.build_plan(arguments(profile='full', seconds=86401))

    def test_plan_does_not_inspect_or_launch_workloads(self):
        with patch.object(runner.sys, 'argv', ['validate', '--profile', 'full', '--label', 'dry', '--', '/usr/bin/true']), \
             patch.object(runner, 'admission_helpers', side_effect=AssertionError('planning inspected host')), \
             patch.object(runner, 'command', side_effect=AssertionError('planning launched command')), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(runner.main(), 0)
        self.assertFalse(json.loads(output.getvalue())['launch'])

    def simulate(self, *, launch_failure=False, source_changed=False, reap_failure=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / 'state'
            args = arguments()
            plan = runner.build_plan(args)
            helper = types.SimpleNamespace(available=lambda: 100 * runner.GIB,
                                           conflicting_processes=lambda: {'conflicts': [], 'protected_non_workers': []})
            terminal = {'MainPID': '0', 'SubState': 'exited', 'Result': 'success',
                        'ExecMainCode': '1', 'ExecMainStatus': '0',
                        'MemoryMax': str(8 * runner.GIB), 'MemoryHigh': str(6 * runner.GIB), 'MemorySwapMax': '0'}
            after = {'LoadState': 'loaded', 'MainPID': '1', 'ControlPID': '0'} if reap_failure else {'LoadState': 'not-found'}
            states = [{'LoadState': 'not-found'}] + ([] if launch_failure else [terminal]) + [after]
            def invoke(argv):
                failed = launch_failure and argv[0] == '/usr/bin/systemd-run'
                if argv[0] == '/usr/bin/systemd-run' and not failed:
                    (state / 'runs/policy-test.log').write_text('')
                return types.SimpleNamespace(returncode=int(failed), stderr='simulated launch failure' if failed else '', stdout='')
            manifests = [{'source': 'old'}, {'source': 'new' if source_changed else 'old'}]
            with patch.object(runner, 'ROOT', root), patch.object(runner, 'STATE', state), \
                 patch.object(runner, 'admission_helpers', return_value=helper), \
                 patch.object(runner, 'systemd_state', side_effect=states), \
                 patch.object(runner, 'command', side_effect=invoke), \
                 patch.object(runner, 'source_manifest', side_effect=manifests), \
                 patch.object(runner.signal, 'signal'), contextlib.redirect_stdout(io.StringIO()):
                code = runner.execute(args, plan)
            saved = json.loads((state / 'runs/policy-test.json').read_text())
            return code, saved

    def test_success_requires_cleanup_and_preserved_sources(self):
        code, record = self.simulate()
        self.assertEqual(code, 0)
        self.assertTrue(record['all_subprocesses_terminal_and_reaped'])
        self.assertTrue(record['source_inputs_unchanged'])
        self.assertFalse(record['performance_qualified'])

    def test_launch_failure_is_recorded_and_cleanup_attempted(self):
        code, record = self.simulate(launch_failure=True)
        self.assertEqual(code, 1)
        self.assertTrue(record['service_stop_completed'])
        self.assertIn('launch failed', record['error'])

    def test_mutated_sources_or_unreaped_processes_cannot_pass(self):
        for changes in [dict(source_changed=True), dict(reap_failure=True)]:
            with self.subTest(changes=changes):
                code, record = self.simulate(**changes)
                self.assertEqual(code, 1)
                self.assertEqual(record['status'], 'failed_or_incomplete')


if __name__ == '__main__':
    unittest.main()
