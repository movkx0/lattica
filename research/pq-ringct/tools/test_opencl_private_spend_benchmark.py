"""Synthetic benchmark gate and wall-clock accounting tests; no GPU is launched."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    'opt_validate_benchmark', Path(__file__).with_name('opencl_private_spend_validate.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

GPU_FIELDS = ('witness_preparation_seconds', 'native_stark_proving_seconds',
              'recursive_stark_proving_seconds', 'registration_preprocessing_seconds',
              'native_private_spend_seconds')
CPU_FIELDS = ('cpu_input_fixture_setup_seconds', 'cpu_input_validation_decode_seconds',
              'cpu_post_shutdown_artifact_decode_verify_seconds')
LIMITS = ('--host-bytes', '--device-bytes', '--max-rows', '--native-bytes')


def arguments(**changes):
    argv = ['/synthetic/driver', '--counts', '3,4', '--host-bytes', '8589934592',
            '--device-bytes', '8589934592', '--max-rows', '65536',
            '--native-bytes', '1024', '--benchmark']
    values = dict(profile='full', label='benchmark-test', seconds=60, command=argv,
                  expect_tests=False, expect_result=True, execute=True,
                  exclusive_window=True, build_label='build-test', record_artifact=[],
                  benchmark=True, correctness_label='prior-test')
    values.update(changes)
    return argparse.Namespace(**values)


def gpu_wall(components):
    return dict(zip(GPU_FIELDS, components), sum_seconds=sum(components),
                clock='host_monotonic_wall', device_only=False,
                scope='serialized_gpu_required_calls_including_host_setup_and_waits',
                throughput_denominator=False)


def result_fixture(counts=(3, 4), benchmark=False):
    cases = []
    for count in counts:
        cases.append(dict(
            count=count, fresh_distinct_transactions=count, complete_graphs_verified=count,
            statement_digests=[[i] for i in range(count)], changed_public_rejected_count=25,
            changed_proof_rejected=True, distinct_reordering_rejected=True,
            distinct_substitution_rejected=True, graph_proof_substitution_rejected=True,
            decoded_verification_after_gpu_shutdown=True,
            merges=[dict(backend='opencl', strict_gpu_request=True,
                         native_parent_verification=True, cache_policy='fresh_only',
                         proof_cache_hit=False, aggregate_children=int(i > 0),
                         recursive_witness_checks=[dict(altered_opening_rejected=True)] * int(i > 0))
                    for i in range(count - 1)],
            cache=dict(policy='fresh_only', families={name: dict(
                reads=0, hits=0, bypasses=1, proof_attempts=1, fresh_proofs=1)
                for name in ('sources', 'algebra', 'crypto', 'auxiliary', 'outer')})))
    n = len(cases)
    proofs = sum(count - 1 for count in counts)
    result = dict(
        schema='pq-opencl-opt-correctness-v2', passed=True, comparison_baseline=False,
        performance_qualified=False, benchmark_measured=benchmark,
        proving_scope='native_private_spend_and_native_recursive_stark_proving', fixture_generation='cpu_ring_ask_inputs_only', native_private_spend_generation='gpu_required',
        independent_verification='cpu', native_gpu_required=True, witness_preparation='gpu_required',
        fixture_pattern='fresh_distinct', original_profile=True, hiding=True,
        num_queries=128, blowup=16, extension='Goldilocks cubic trinomial', cases=cases,
        context=dict(session_closed=True, prepared_entries=0, maximum_prepared_entries=1,
            metadata_cache_payload_bytes=1024, device={'name': 'synthetic GPU', 'vendor': 'synthetic'},
            session_finish=dict(commits=3, allocations=3, managed_peak_bytes=runner.GIB),
            policy='gpu_required', registrations=1, registration_seconds=4.0 * n,
            operations=dict(prove_calls=proofs, prove_succeeded=proofs,
                native_cpu_calls=0, native_cpu_succeeded=0, failures=[],
                native_gpu_calls=4 * n, native_gpu_succeeded=4 * n,
                native_gpu_complete_reports=4 * n, witness_preparation_calls=n,
                witness_preparation_succeeded=n, witness_preparation_complete_reports=n,
                witness_preparation_stage=dict(stage='witness_trace', completed_calls=n, device_calls=n),
                witness_preparation_seconds=1.0 * n, native_gpu_seconds=2.0 * n,
                prove_seconds=3.0 * n, native_spend_seconds=0.5 * n,
                native_spend_calls=sum(counts), native_spend_succeeded=sum(counts),
                native_spend_complete_reports=sum(counts), native_spend_stage=dict(
                    stage='witness_trace', completed_calls=sum(counts), device_calls=sum(counts)))))
    if benchmark:
        for case in cases:
            case['timing'] = dict(
                scope='fresh_case_with_fixtures_preparation_native_recursive_proving_verification_mutations_artifact_io',
                excludes='shared_session_setup_shutdown_and_other_cases',
                includes_internal_cpu_verification=True, includes_cpu_correctness_diagnostics=True,
                active_wall_seconds=20.0, active_workflow_transactions_per_hour=case['count'] * 180.0,
                gpu_operation_wall=gpu_wall([1.0, 2.0, 3.0, 4.0, 0.5]),
                **dict.fromkeys(CPU_FIELDS, 1.0))
        wall = 20.0 * n + 10.0
        result['measurement'] = dict(
            schema='pq-opencl-fresh-workflow-timing-v2',
            scope='single_serial_context_fresh_fixtures_preparation_native_recursive_proving_verification_mutations_artifact_io_shutdown',
            excludes='process_launch_and_final_result_serialization', clock='host_monotonic_wall',
            device_only=False, production_throughput=False, comparison_baseline=False,
            transactions=sum(counts), run_wall_seconds=wall,
            fresh_end_to_end_correctness_workflow_transactions_per_hour=sum(counts) * 3600.0 / wall,
            gpu_operation_wall=gpu_wall([float(n), 2.0 * n, 3.0 * n, 4.0 * n, 0.5 * n]))
    return result


def receipt(entry, scope):
    stages = ['public_values', 'witness_trace', 'preprocessing', 'transform', 'quotient',
              'randomness', 'hiding', 'commitment', 'opening', 'fri_fold', 'fri_query',
              'final_polynomial', 'scalar', 'transcript', 'grinding']
    if scope == 'preprocessing':
        stages = ['preprocessing', 'randomness', 'transform', 'commitment']
    elif scope == 'registered_proof':
        stages.remove('public_values')
        stages.append('lookup')
    elif scope == 'operation':
        stages = ['witness_trace']
    return dict(schema='lattica-proving-stages-v1', entry_point=entry, policy='gpu_required',
                succeeded=True, stage_coverage_complete=True, completion_rejected=False,
                observation_errors=0, components=[], capabilities=dict(
                    profile='matrict_n10' if entry == 'native_matrict_spend' else 'block_v2_cubic', scope=scope,
                    stages=[dict(stage=s, backend='open_cl') for s in stages]),
                observations=[dict(stage=s, backend='open_cl', calls=1,
                                   completed_calls=1, device_calls=1) for s in stages])


def log_fixture(result):
    reports = [receipt('block_v2_preprocessing', 'preprocessing')]
    reports += [receipt('block_v2_registered_program', 'registered_proof')
                for _ in range(result['context']['operations']['prove_calls'])]
    reports += [receipt('native_matrict_spend', 'operation')
                for _ in range(sum(case['count'] for case in result['cases']))]
    for _ in result['cases']:
        reports.append(receipt('pq_graph_witness_preparation', 'operation'))
        reports += [receipt(entry, 'proof_request') for entry in
                    ('pq_statement', 'matrict_affine_gpu', 'pq_aes_lane_native', 'pq_uniform_gpu')]
    return ''.join('proving_stage_report ' + json.dumps(r) + '\n' for r in reports) + \
        'OPENCL_OPT_RESULT ' + json.dumps(result) + '\n'


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        command = patch.object(runner, 'command', side_effect=AssertionError('unexpected command launch'))
        command.start()
        self.addCleanup(command.stop)
        self.plan = runner.build_plan(arguments())
        self.result = result_fixture(benchmark=True)
        self.plan['prior_correctness'] = {'device': copy.deepcopy(self.result['context']['device'])}

    def reject_result(self, mutate):
        result = copy.deepcopy(self.result)
        mutate(result)
        with self.assertRaises(ValueError):
            runner.validate_measurement(result, self.plan)

    def test_complete_synthetic_measurement_is_accepted(self):
        runner.validate_result(self.result)
        runner.validate_receipts(log_fixture(self.result), self.result)
        accepted = runner.validate_measurement(self.result, self.plan)
        self.assertEqual(accepted['transactions'], 7)
        self.assertEqual(accepted['transactions_per_hour'], 504.0)
        self.assertEqual(accepted['run_wall_seconds'], 50.0)
        self.assertFalse(accepted['production_throughput'])
        self.assertFalse(accepted['device_only'])

    def test_plan_requires_agreed_full_benchmark_mode_and_prior_pass(self):
        for changes in [dict(benchmark=False), dict(profile='smoke'), dict(expect_result=False),
                        dict(correctness_label=None), dict(correctness_label='../escape'),
                        dict(build_label=None), dict(command=arguments().command[:-1])]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner.build_plan(arguments(**changes))

    def test_counts_require_one_explicit_supported_value(self):
        for argv in [[], ['--counts'], ['--counts', '2'], ['--counts', '4,3'],
                     ['--counts', '3', '--counts', '4']]:
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                runner.requested_counts({'command': argv})
        self.assertEqual(runner.requested_counts({'command': ['--counts', '3,4']}), {3, 4})

    def test_limits_require_one_positive_value_each_and_normalize_integers(self):
        expected = runner.driver_limits(self.plan)
        for option in LIMITS:
            index = self.plan['command'].index(option)
            for replacement in [[], [option], [option, '0'], [option, '-1'],
                                [option, 'bad'], [option, '1', option, '1']]:
                plan = copy.deepcopy(self.plan)
                plan['command'][index:index + 2] = replacement
                with self.subTest(option=option, replacement=replacement), self.assertRaises(ValueError):
                    runner.driver_limits(plan)
            plan = copy.deepcopy(self.plan)
            plan['command'][index + 1] = '0' + str(expected[option])
            self.assertEqual(runner.driver_limits(plan), expected)

    def test_correctness_mode_rejects_measurement_and_mode_mismatch(self):
        plain = result_fixture()
        self.assertIsNone(runner.validate_measurement(plain, {'benchmark': False}))
        for result, plan in [(plain, self.plan), (self.result, {'benchmark': False}),
                             (dict(plain, measurement={}), {'benchmark': False})]:
            with self.assertRaises(ValueError):
                runner.validate_measurement(result, plan)

    def test_scope_cannot_claim_device_only_or_production_throughput(self):
        for field, value in [('device_only', True), ('production_throughput', True),
                             ('comparison_baseline', True), ('clock', 'device_event'),
                             ('scope', 'gpu_only'), ('excludes', 'cpu_work')]:
            with self.subTest(field=field):
                self.reject_result(lambda r: r['measurement'].update({field: value}))
        for field, value in [('device_only', True), ('throughput_denominator', True),
                             ('scope', 'device_events'), ('clock', 'device_event')]:
            with self.subTest(gpu_field=field):
                self.reject_result(lambda r: r['cases'][0]['timing']['gpu_operation_wall'].update({field: value}))

    def test_case_scope_requires_cpu_verification_and_diagnostics(self):
        for field, value in [('includes_internal_cpu_verification', False),
                             ('includes_cpu_correctness_diagnostics', False),
                             ('scope', 'gpu_only'), ('excludes', 'all_cpu_work')]:
            with self.subTest(field=field):
                self.reject_result(lambda r: r['cases'][0]['timing'].update({field: value}))

    def test_counts_and_both_rate_denominators_are_checked(self):
        mutations = [lambda r: r['cases'].pop(),
                     lambda r: r['measurement'].update(transactions=6),
                     lambda r: r['measurement'].update(transactions=7.0),
                     lambda r: r['measurement'].update(fresh_end_to_end_correctness_workflow_transactions_per_hour=1260.0),
                     lambda r: r['cases'][0]['timing'].update(active_workflow_transactions_per_hour=1080.0)]
        for mutate in mutations:
            with self.subTest(mutation=mutations.index(mutate)):
                self.reject_result(mutate)

    def test_invalid_numeric_timing_is_rejected(self):
        for value in [float('nan'), float('inf'), float('-inf'), -1.0, True, '1', None]:
            for location in ['wall', 'cpu', 'gpu', 'counter', 'rate']:
                def mutate(r):
                    if location == 'wall':
                        r['measurement']['run_wall_seconds'] = value
                    elif location == 'cpu':
                        r['cases'][0]['timing'][CPU_FIELDS[0]] = value
                    elif location == 'gpu':
                        r['cases'][0]['timing']['gpu_operation_wall'][GPU_FIELDS[0]] = value
                    elif location == 'counter':
                        r['context']['operations']['native_gpu_seconds'] = value
                    else:
                        r['measurement']['fresh_end_to_end_correctness_workflow_transactions_per_hour'] = value
                with self.subTest(value=value, location=location):
                    self.reject_result(mutate)
        self.reject_result(lambda r: r['measurement'].update(run_wall_seconds=0))
        self.reject_result(lambda r: r['cases'][0]['timing'].update(active_wall_seconds=0))

    def test_cpu_and_gpu_durations_fit_active_case_wall(self):
        for field in CPU_FIELDS:
            with self.subTest(field=field):
                self.reject_result(lambda r: r['cases'][0]['timing'].update({field: 21.0}))
        self.reject_result(lambda r: r['cases'][0]['timing'].update(gpu_operation_wall=gpu_wall([6.0] * 5)))

    def test_disjoint_cpu_and_gpu_stages_cannot_collectively_exceed_case_wall(self):
        # Every CPU duration is individually legal, but attribution is impossible.
        self.reject_result(lambda r: r['cases'][0]['timing'].update(**dict.fromkeys(CPU_FIELDS, 9.0)))
        # CPU and GPU subtotals both fit separately, but their disjoint sum does not.
        self.reject_result(lambda r: r['cases'][0]['timing'].update(**dict.fromkeys(CPU_FIELDS, 4.0)))

    def test_gpu_diagnostics_match_case_sums_and_context_counters(self):
        global_sum = self.result['measurement']['gpu_operation_wall']['sum_seconds']
        case_sum = self.result['cases'][0]['timing']['gpu_operation_wall']['sum_seconds']
        self.reject_result(lambda r: r['measurement']['gpu_operation_wall'].update(sum_seconds=global_sum + 1.0))
        self.reject_result(lambda r: r['cases'][0]['timing']['gpu_operation_wall'].update(sum_seconds=case_sum + 1.0))
        self.reject_result(lambda r: r['cases'][0]['timing'].update(gpu_operation_wall=gpu_wall([0.0, 2.0, 3.0, 4.0, 0.5])))
        for field in ['witness_preparation_seconds', 'native_gpu_seconds', 'prove_seconds', 'native_spend_seconds']:
            with self.subTest(field=field):
                self.reject_result(lambda r: r['context']['operations'].update({field: 99.0}))
        self.reject_result(lambda r: r['context'].update(registration_seconds=99.0))

    def test_active_cases_cannot_exceed_total_wall_even_with_consistent_rate(self):
        self.reject_result(lambda r: r['measurement'].update(run_wall_seconds=30.0,
            fresh_end_to_end_correctness_workflow_transactions_per_hour=840.0))

    def test_device_identity_must_match_prior_pass(self):
        self.reject_result(lambda r: r['context'].update(device={'name': 'different GPU'}))


class PriorCorrectnessTests(unittest.TestCase):
    def setUp(self):
        command = patch.object(runner, 'command', side_effect=AssertionError('unexpected command launch'))
        command.start()
        self.addCleanup(command.stop)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.runs = Path(directory.name)
        self.plan = runner.build_plan(arguments())
        self.sources = {'source.rs': 'synthetic-source-sha'}
        self.build = self.runs / 'build-test.json'
        self.build.write_text('{"synthetic_build": true}\n')
        self.executable = dict(path='/synthetic/driver', resolved_path='/synthetic/driver',
                               sha256='synthetic-executable-sha', build_record=str(self.build),
                               build_record_sha256=runner.sha(self.build))
        self.result = result_fixture()
        self.content = log_fixture(self.result)
        self.log = self.runs / 'prior-test.log'
        self.record_path = self.runs / 'prior-test.json'
        self.record = dict(copy.deepcopy(self.plan), label='prior-test', benchmark=False,
                           correctness_label=None, status='passed', error=None,
                           source_inputs_unchanged=True, executable_unchanged=True,
                           all_subprocesses_terminal_and_reaped=True, input_sha256=self.sources,
                           executable_provenance=self.executable, raw_log=str(self.log),
                           correctness_result=self.result,
                           receipt_acceptance=runner.validate_receipts(self.content, self.result))
        self.record['command'].remove('--benchmark')
        self.save()

    def save(self, record=None, content=None):
        record = copy.deepcopy(self.record if record is None else record)
        self.log.write_text(self.content if content is None else content)
        record['raw_log_sha256'] = runner.sha(self.log)
        self.record_path.write_text(json.dumps(record))

    def validate(self):
        return runner.prior_correctness(self.plan, self.sources, self.executable, self.runs)

    def test_full_pass_accepts_exact_provenance_and_count_subset(self):
        for counts in ['3,4', '3', '4']:
            self.plan['command'][self.plan['command'].index('--counts') + 1] = counts
            accepted = self.validate()
            self.assertEqual(accepted['validated_counts'], [3, 4])
            self.assertEqual(accepted['driver_limits'], runner.driver_limits(self.plan))
            self.assertEqual(accepted['device'], self.result['context']['device'])
            self.assertEqual(accepted['record_sha256'], runner.sha(self.record_path))
            self.assertEqual(accepted['log_sha256'], runner.sha(self.log))

    def test_prior_requires_complete_full_correctness_mode(self):
        for field, value in [('schema', 'other'), ('status', 'failed'), ('error', 'failed'),
                             ('profile', 'smoke'), ('profile', 'build'), ('expect_result', False),
                             ('benchmark', True), ('source_inputs_unchanged', False),
                             ('executable_unchanged', False), ('all_subprocesses_terminal_and_reaped', False)]:
            self.save(dict(self.record, **{field: value}))
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.validate()

    def test_changed_source_executable_and_build_identity_are_rejected(self):
        mutations = [lambda r: r['input_sha256'].update(extra='source'),
                     lambda r: r['executable_provenance'].update(sha256='different'),
                     lambda r: r['executable_provenance'].update(build_record_sha256='different'),
                     lambda r: r['executable_provenance'].update(resolved_path='/different/driver')]
        for mutate in mutations:
            record = copy.deepcopy(self.record)
            mutate(record)
            self.save(record)
            with self.subTest(mutation=mutations.index(mutate)), self.assertRaises(ValueError):
                self.validate()
        self.save()
        self.build.write_text('{"synthetic_build": "changed"}\n')
        with self.assertRaises(ValueError):
            self.validate()

    def test_changed_limits_and_thread_environment_are_rejected(self):
        for option in LIMITS:
            record = copy.deepcopy(self.record)
            index = record['command'].index(option)
            record['command'][index + 1] = str(int(record['command'][index + 1]) + 1)
            self.save(record)
            with self.subTest(option=option), self.assertRaises(ValueError):
                self.validate()
        record = copy.deepcopy(self.record)
        record['environment']['RAYON_NUM_THREADS'] = '999'
        self.save(record)
        with self.assertRaises(ValueError):
            self.validate()

    def test_raw_log_digest_and_result_identity_are_checked(self):
        self.log.write_text(self.content + 'changed\n')
        with self.assertRaises(ValueError):
            self.validate()
        for content in [self.content + 'OPENCL_OPT_RESULT ' + json.dumps(self.result) + '\n',
                        self.content.replace('"num_queries": 128', '"num_queries": 64'),
                        self.content.replace('OPENCL_OPT_RESULT ', 'MISSING_RESULT ')]:
            self.save(content=content)
            with self.assertRaises(ValueError):
                self.validate()

    def test_acceptance_is_replayed_despite_coherent_log_and_record(self):
        changed = copy.deepcopy(self.result)
        changed['cases'][0]['changed_proof_rejected'] = False
        record = dict(self.record, correctness_result=changed)
        self.save(record, log_fixture(changed))
        with self.assertRaises(ValueError):
            self.validate()
        self.save(content=self.content.replace('"device_calls": 1', '"device_calls": 0'))
        with self.assertRaises(ValueError):
            self.validate()
        self.save(dict(self.record, receipt_acceptance={}))
        with self.assertRaises(ValueError):
            self.validate()

    def test_prior_benchmark_result_cannot_qualify_another_benchmark(self):
        changed = result_fixture(benchmark=True)
        self.save(dict(self.record, correctness_result=changed), log_fixture(changed))
        with self.assertRaises(ValueError):
            self.validate()

    def test_three_only_correctness_does_not_qualify_four(self):
        changed = result_fixture(counts=(3,))
        content = log_fixture(changed)
        self.save(dict(self.record, correctness_result=changed,
                       receipt_acceptance=runner.validate_receipts(content, changed)), content)
        with self.assertRaises(ValueError):
            self.validate()
        self.plan['command'][self.plan['command'].index('--counts') + 1] = '3'
        self.assertEqual(self.validate()['validated_counts'], [3])


if __name__ == '__main__':
    unittest.main()
