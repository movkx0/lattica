import argparse
import copy
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from gpu_aggregation_profile import AggregationBudget, selection, validate, qualification, environment
from test_opencl_private_spend_validate import arguments, runner


class AggregationAcceptance(unittest.TestCase):
    def test_graph_architecture_requires_verified_gpu_proofs_and_exact_count(self):
        argv = self.argv()
        argv[1] = 'architecture-graph'
        argv += ['--native-source', 'revalidate-archive', '--group-width', '8']
        selected = selection(self.args(), argv)
        self.assertEqual(selected['values']['--screen-family'], 'graph')
        self.assertEqual(selected['values']['--recursion-backend'], 'typed')
        for extra in (['--request', '1'], ['--screen-family', 'aes'], ['--leaves', '9']):
            with self.assertRaises(RuntimeError): selection(self.args(), argv + extra)
        with self.assertRaises(RuntimeError): selection(self.args(), self.argv()[:1] + ['architecture-graph'] + self.argv()[2:])
        row = self.report()
        row['options']['command'] = 'architecture-graph'
        m = dict(verified=True, proof_json_bytes=100, backend_report=dict(stage_coverage_complete=True))
        row['report'] = dict(scope='recursion-graph-subtree-screen', verified=True, complete_aggregation=False,
            complete_graph=False, backend='typed', native_proofs_generated=0, archive_files_rewritten=0,
            current_cache_entries_created=0, groups=[[4,8]], session=dict(session_closed=True,completion_claimed=False),
            samples=[dict(verified=True,public_mutation_rejected=True,recursive_proofs=1,
                independent_cpu_verification=True,gpu_backend_only=True,seconds=10,measurements=[dict(measurement=m)])])
        validate('GPU_AGGREGATION_PROFILE '+json.dumps(row),selected)
        for change in ('count','gpu','complete'):
            bad=copy.deepcopy(row)
            if change=='count': bad['report']['samples'][0]['recursive_proofs']=3
            if change=='gpu': bad['report']['samples'][0]['measurements'][0]['measurement']['backend_report']['stage_coverage_complete']=False
            if change=='complete': bad['report']['complete_graph']=True
            with self.assertRaises(RuntimeError): validate('GPU_AGGREGATION_PROFILE '+json.dumps(bad),selected)

    def test_aes_reference_is_confined_to_singleton_archive_request(self):
        argv = self.argv()
        argv[1] = 'architecture-request'
        argv[argv.index('--case') + 1] = 'n4'
        args = self.args(host_profile='expanded-36')
        extra = ['--request', '4', '--screen-family', 'aes', '--native-source', 'revalidate-archive',
                 '--compiler-policy', 'typed-batch', '--group-width', '1', '--recursion-backend', 'machine']
        selected = selection(args, argv + extra)
        self.assertEqual(selected['values']['--recursion-backend'], 'machine')
        for option, bad_value in [('--group-width', '4'), ('--screen-family', 'shake'), ('--native-source', 'current')]:
            bad = extra.copy()
            bad[bad.index(option) + 1] = bad_value
            with self.subTest(option=option), self.assertRaises(RuntimeError):
                selection(args, argv + bad)
        for command in ('run', 'screen', 'architecture-proof'):
            bad = argv.copy()
            bad[1] = command
            with self.subTest(command=command), self.assertRaises(RuntimeError):
                selection(args, bad + extra)

    def test_aes_reference_requires_all_verified_leaves_and_parents(self):
        argv = self.argv()
        argv[1] = 'architecture-request'
        selected = selection(self.args(), argv + ['--request', '2', '--screen-family', 'aes',
            '--native-source', 'revalidate-archive', '--group-width', '1', '--recursion-backend', 'machine'])
        sample = dict(complete_request=True, public_mutation_rejected=True, order_mutation_rejected=True,
            leaves=[dict(verified=True, seconds=1)] * 3, parents=[dict(verified=True, seconds=1)] * 2)
        row = self.report()
        row['options']['command'] = 'architecture-request'
        row['report'] = dict(scope='recursion-architecture-request-screen', complete_request=True, verified=True,
            complete_aggregation=False, native_proofs_generated=0, proofs_generated=5, native_components=3,
            session=dict(session_closed=True, completion_claimed=False), proof_profile=dict(backend='machine',
                complete_request=True, independent_cpu_verification=True, gpu_backend_only=True,
                native_groups=3, samples=[sample]))
        validate('GPU_AGGREGATION_PROFILE ' + json.dumps(row), selected)
        for change in ('parent', 'verification', 'backend', 'count'):
            bad = copy.deepcopy(row)
            profile = bad['report']['proof_profile']
            if change == 'parent': profile['samples'][0]['parents'].pop()
            if change == 'verification': profile['samples'][0]['leaves'][0]['verified'] = False
            if change == 'backend': profile['backend'] = 'typed'
            if change == 'count': bad['report']['proofs_generated'] = 4
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                validate('GPU_AGGREGATION_PROFILE ' + json.dumps(bad), selected)

    def test_consuming_costs_require_paired_cpu_lookahead_baseline(self):
        from gpu_aggregation_select import matched_cost
        def record(candidate):
            return dict(status='passed', environment=dict(LATTICA_GPU_DEVICE_UUID='gpu'),
                gpu_aggregation_acceptance=dict(options=dict(command='screen',
                    profile='grouped-v3' if candidate else 'grouped-v2', identity='cpu', parallel=True,
                    transactions=4, workload=0, family='graph'),
                report=dict(verified=True, complete_aggregation=False, scope='native-graph-subtree-screen',
                    input_sha3='input', source_sha3='source', first_leaf=4, leaves=8,
                    width=4 if candidate else 2, admitted_maximum_group=4 if candidate else 2,
                    samples=[dict(repetition=i, verified=True, seconds=8 if candidate else 10,
                        process_state='first-request' if i == 0 else 'warm-request') for i in range(4)])))
        baseline, candidate = record(False), record(True)
        self.assertEqual(matched_cost(baseline, candidate)[2]['candidate'], [8, 8, 8])
        for section, key, value in [('options', 'identity', 'gpu-batched'),
                ('options', 'parallel', False), ('report', 'width', 1),
                ('report', 'source_sha3', 'other'), ('report', 'input_sha3', 'other')]:
            bad = copy.deepcopy(baseline)
            bad['gpu_aggregation_acceptance'][section][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                matched_cost(bad, candidate)

    def test_budget_extension_preserves_attempts_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            budget = AggregationBudget(Path(directory) / 'budget.json')
            value = budget.read()
            value['attempts'] = [dict(label='previous', status='failed', wall_seconds=3216.0)]
            budget.save(value)
            extended = budget.extend('approved-round-two', 1800)
            self.assertEqual(extended['attempts'], value['attempts'])
            self.assertEqual(budget.remaining(), 2184.0)
            self.assertEqual(budget.extend('approved-round-two', 1800), extended)
            with self.assertRaises(RuntimeError): budget.extend('approved-round-two', 3600)
            altered = copy.deepcopy(extended); altered['limit_seconds'] += 1
            budget.save(altered)
            with self.assertRaises(RuntimeError): budget.read()

    def test_budget_extension_never_reconciles_a_running_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            budget = AggregationBudget(Path(directory) / 'budget.json')
            value = budget.read(); value['attempts'] = [dict(status='running', reserved_seconds=600)]
            budget.save(value)
            with self.assertRaises(RuntimeError): budget.extend('approved-round-two', 1800)
            with self.assertRaises(RuntimeError): budget.remaining()

    def args(self, **changes):
        return arguments(**dict(dict(gpu_aggregation=True, profile='full', build_label='aggregation-build', seconds=600,
            device_uuid='GPU-279a9bfd-fd33-cd25-430a-4ceec2f63615', retained_tree_storage='host', host_profile='standard'), **changes))

    def argv(self):
        return ['/tmp/pq-ringct-gpu-aggregate', 'screen', '--case', 'n3', '--input-bundle', '/tmp/bundle']

    def report(self):
        return dict(schema='ringct-gpu-aggregation-v1', complete_fresh_workflow=False, performance_qualified=False,
            controller_wall_seconds=12.0, options=dict(command='screen', profile='grouped-v5', transactions=3),
            report=dict(verified=True, complete_aggregation=False, session=dict(session_closed=True)))

    def test_default_run_needs_no_experimental_flags_or_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            argv = self.argv()
            argv[1] = 'run'
            selected = selection(self.args(), argv + ['--output', str(Path(directory)/'aggregate')])
            self.assertEqual(selected['profile'], 'grouped-v5')
            env = environment(selected)
            self.assertEqual(env['LATTICA_V2_GPU_NTT_PROFILE'], 'smalltile')
            self.assertEqual(env['LATTICA_V2_GPU_TUNING'], 'events,witness,programs,queries')
            self.assertEqual(env['LATTICA_V2_GPU_COMPILER_POLICY'], 'standard')

    def test_archive_inputs_only_admit_readonly_bounded_preflight(self):
        argv = self.argv(); argv[1] = 'preflight-groups'
        suffix = ['--request', '1', '--native-source', 'revalidate-archive']
        selection(self.args(), argv + suffix)
        for command in ('run', 'screen', 'prepare-inputs', 'plan'):
            bad = argv.copy(); bad[1] = command
            with self.subTest(command=command), self.assertRaises(RuntimeError):
                selection(self.args(), bad + suffix)
        for extra in (['--screen-family', 'graph'], ['--group-width', '8']):
            with self.assertRaises(RuntimeError):
                selection(self.args(), argv + suffix + extra)
        with self.assertRaises(RuntimeError):
            selection(self.args(), argv + ['--request','1','--native-source','skip-verification'])

    def test_n4_typed_defaults_and_explicit_machine_compatibility(self):
        with tempfile.TemporaryDirectory() as directory:
            argv = self.argv(); argv[1] = 'run'
            argv[argv.index('--case') + 1] = 'n4'
            argv += ['--output', str(Path(directory) / 'aggregate')]
            args = self.args(host_profile='expanded-36')
            selected = selection(args, argv)
            self.assertEqual(selected['values']['--recursion-backend'], 'typed')
            self.assertEqual(selected['values']['--group-width'], '16')
            self.assertEqual(environment(selected)['LATTICA_V2_GPU_COMPILER_POLICY'], 'typed-batch')
            legacy = selection(args, argv + ['--recursion-backend', 'machine'])
            self.assertEqual(environment(legacy)['LATTICA_V2_GPU_COMPILER_POLICY'], 'standard')
            with self.assertRaises(RuntimeError):
                selection(args, argv + ['--recursion-backend', 'machine', '--group-width', '16'])

    def test_scope_timeout_and_envelope_are_explicit(self):
        selection(self.args(), self.argv())
        for changes in [dict(seconds=601), dict(profile='cpu-proof'), dict(build_label=None),
                        dict(device_uuid=None), dict(retained_tree_storage='device'), dict(host_profile='expanded-36')]:
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                selection(self.args(**changes), self.argv())
        with self.assertRaises(RuntimeError):
            selection(self.args(), self.argv() + ['--case', 'n4'])

    def test_guard_pins_cpu_gpu_and_resource_envelope(self):
        with patch.object(runner, 'identity_physical_cpus', return_value=list(range(16))):
            plan = runner.build_plan(self.args(command=self.argv() + ['--profile', 'grouped-v2']))
        self.assertEqual(plan['cpu_quota'], '1600%')
        self.assertEqual(plan['environment']['LATTICA_V2_GPU_TUNING'], 'events,witness,programs')
        self.assertEqual(plan['memory_max_bytes'], 47 << 30)
        self.assertEqual(plan['environment']['LATTICA_V2_GPU_MANAGED_BYTES'], str(8 << 30))
        self.assertEqual(plan['environment']['LATTICA_V2_HOST_OUTPUT_BYTES'], str(16 << 30))
        with self.assertRaises(ValueError):
            runner.build_plan(self.args(command=self.argv(), expect_tests=True))

    def test_v5_kernel_and_wide_policies_are_explicit_and_case_bounded(self):
        argv = self.argv() + ['--profile','grouped-v5','--pipeline','lookahead','--ntt-profile','split8']
        plan = runner.build_plan(self.args(command=argv))
        self.assertEqual(plan['environment']['LATTICA_V2_GPU_NTT_PROFILE'], 'split8')
        with self.assertRaises(RuntimeError):
            selection(self.args(), argv + ['--compiler-policy','wide-memory'])
        for bad in ['unknown', 'ntt-all']:
            with self.assertRaises(RuntimeError):
                selection(self.args(), self.argv()+['--profile','grouped-v5','--ntt-profile',bad])

    def test_architecture_proof_requires_gpu_coverage_and_cpu_verification(self):
        argv = self.argv(); argv[1] = 'architecture-proof'
        selected = selection(self.args(), argv + ['--request', '6', '--native-source', 'revalidate-archive'])
        row = self.report()
        row['options']['command'] = 'architecture-proof'
        row['report'] = dict(scope='recursion-architecture-proof-screen', proofs_generated=1,
            native_proofs_generated=0, verified=True, complete_aggregation=False,
            session=dict(session_closed=True, completion_claimed=False),
            proof_profile=dict(independent_cpu_verification=True, gpu_backend_only=True,
                samples=[dict(measurement=dict(verified=True, proof_json_bytes=100,
                    backend_report=dict(stage_coverage_complete=True)))]))
        validate('GPU_AGGREGATION_PROFILE ' + json.dumps(row), selected)
        for mutate in [lambda r: r['report'].update(verified=False),
                       lambda r: r['report']['session'].update(completion_claimed=True),
                       lambda r: r['report']['proof_profile']['samples'][0]['measurement']['backend_report'].update(stage_coverage_complete=False)]:
            bad = copy.deepcopy(row); mutate(bad)
            with self.assertRaises(RuntimeError):
                validate('GPU_AGGREGATION_PROFILE ' + json.dumps(bad), selected)
        with self.assertRaises(RuntimeError):
            selection(self.args(), argv + ['--request', '6'])
        with self.assertRaises(RuntimeError):
            selection(self.args(), argv + ['--request', '6', '--native-source', 'revalidate-archive', '--repetitions', '4'])

    def test_architecture_parent_requires_constrained_and_verified_parent(self):
        argv = self.argv(); argv[1] = 'architecture-parent'
        selected = selection(self.args(), argv + ['--request', '6', '--native-source', 'revalidate-archive'])
        row = self.report(); row['options']['command'] = 'architecture-parent'
        measurement = dict(verified=True, proof_json_bytes=100,
                           backend_report=dict(stage_coverage_complete=True))
        row['report'] = dict(scope='recursion-architecture-proof-screen', proofs_generated=2,
            native_proofs_generated=0, verified=True, complete_aggregation=False,
            session=dict(session_closed=True, completion_claimed=False),
            proof_profile=dict(independent_cpu_verification=True, gpu_backend_only=True,
                parent_geometry=dict(tables=[{}]), parent_template_identity='trusted',
                samples=[dict(measurement=measurement, parent=dict(
                    constrained_child_verification=True, measurement=copy.deepcopy(measurement)))]))
        validate('GPU_AGGREGATION_PROFILE ' + json.dumps(row), selected)
        for change in ['verified', 'constrained_child_verification', 'stage_coverage_complete']:
            bad = copy.deepcopy(row)
            parent = bad['report']['proof_profile']['samples'][0]['parent']
            if change == 'verified': parent['measurement'][change] = False
            elif change == 'stage_coverage_complete': parent['measurement']['backend_report'][change] = False
            else: parent[change] = False
            with self.assertRaises(RuntimeError):
                validate('GPU_AGGREGATION_PROFILE ' + json.dumps(bad), selected)

    def test_architecture_request_requires_complete_verified_coverage(self):
        argv = self.argv(); argv[1] = 'architecture-request'
        selected = selection(self.args(), argv + ['--request','6','--native-source','revalidate-archive'])
        item = dict(measurement=dict(verified=True, proof_json_bytes=100,
                    backend_report=dict(stage_coverage_complete=True)))
        sample = dict(complete_request=True, public_mutation_rejected=True, order_mutation_rejected=True,
                      leaves=[copy.deepcopy(item),copy.deepcopy(item)], root=copy.deepcopy(item))
        row = self.report(); row['options']['command'] = 'architecture-request'
        row['report'] = dict(scope='recursion-architecture-request-screen', complete_request=True,
            verified=True, complete_aggregation=False, native_proofs_generated=0, proofs_generated=3,
            session=dict(session_closed=True,completion_claimed=False),
            proof_profile=dict(complete_request=True,independent_cpu_verification=True,gpu_backend_only=True,
                               native_groups=2,samples=[sample]))
        validate('GPU_AGGREGATION_PROFILE ' + json.dumps(row),selected)
        for mutation in [lambda r:r['report'].update(complete_request=False),
                         lambda r:r['report'].update(proofs_generated=2),
                         lambda r:r['report']['proof_profile']['samples'][0].update(order_mutation_rejected=False),
                         lambda r:r['report']['proof_profile']['samples'][0]['root']['measurement'].update(verified=False)]:
            bad=copy.deepcopy(row);mutation(bad)
            with self.assertRaises(RuntimeError):validate('GPU_AGGREGATION_PROFILE '+json.dumps(bad),selected)

    def test_direct_request_omits_parent_and_large_batches_are_architecture_only(self):
        argv = self.argv(); argv[1] = 'architecture-request'
        argv += ['--request', '6', '--native-source', 'revalidate-archive', '--group-width', '16']
        selected = selection(self.args(), argv)
        item = dict(measurement=dict(verified=True, proof_json_bytes=100,
            backend_report=dict(stage_coverage_complete=True)))
        sample = dict(complete_request=True, public_mutation_rejected=True, order_mutation_rejected=True,
            leaves=[item], root=None, direct_native_batch=True)
        row = self.report(); row['options']['command'] = 'architecture-request'
        row['report'] = dict(scope='recursion-architecture-request-screen', complete_request=True,
            verified=True, complete_aggregation=False, native_components=10, native_proofs_generated=0,
            proofs_generated=1, session=dict(session_closed=True, completion_claimed=False),
            proof_profile=dict(complete_request=True, independent_cpu_verification=True, gpu_backend_only=True,
                native_groups=1, direct_native_batch=True, samples=[sample]))
        validate('GPU_AGGREGATION_PROFILE ' + json.dumps(row), selected)
        for mutation in [lambda r:r['report'].update(proofs_generated=2),
            lambda r:r['report']['proof_profile']['samples'][0].update(root=item),
            lambda r:r['report']['proof_profile'].update(direct_native_batch=False)]:
            bad = copy.deepcopy(row); mutation(bad)
            with self.assertRaises(RuntimeError): validate('GPU_AGGREGATION_PROFILE ' + json.dumps(bad), selected)
        argv[1] = 'screen'
        with self.assertRaises(RuntimeError): selection(self.args(), argv)

    def test_proof_free_preflight_requires_cleanup_without_completion(self):
        row = self.report()
        row['options']['command'] = 'preflight-groups'
        row['report'] = dict(proofs_generated=0, source_and_backend_checked=True,
            session=dict(session_closed=True, completion_claimed=False))
        selected = dict(command='preflight-groups',profile='grouped-v5',transactions=3)
        validate('GPU_AGGREGATION_PROFILE '+json.dumps(row),selected)
        row['report']['session']['completion_claimed'] = True
        with self.assertRaises(RuntimeError):
            validate('GPU_AGGREGATION_PROFILE '+json.dumps(row),selected)

    def test_screens_and_incomplete_reports_cannot_qualify_full_run(self):
        chosen = selection(self.args(), self.argv())
        valid = self.report()
        validate('GPU_AGGREGATION_PROFILE ' + json.dumps(valid), chosen)
        for mutate in [lambda r:r.update(complete_fresh_workflow=True), lambda r:r.update(controller_wall_seconds=600),
                       lambda r:r['report'].update(complete_aggregation=True),
                       lambda r:r['report']['session'].update(session_closed=False)]:
            bad = copy.deepcopy(valid); mutate(bad)
            with self.assertRaises(RuntimeError):
                validate('GPU_AGGREGATION_PROFILE ' + json.dumps(bad), chosen)
        records = [dict(status='passed', gpu_aggregation_acceptance=valid) for _ in range(6)]
        self.assertFalse(qualification(records)['performance_qualified'])

    def test_three_runs_of_each_case_required(self):
        records = []
        for case in (3, 4):
            for i in range(3):
                row = self.report()
                row['options'].update(command='run', transactions=case, identity='cpu', parallel=True,
                    group_width=4, workload=0)
                row['report'].update(scope='aggregation-from-native-components', complete=True,
                    native_proofs_created=0, recursive_proofs=1, final_cpu_verified=True,
                    artifact_round_trip=True, public_mutation_rejected=True, proof_mutation_rejected=True,
                    order_mutation_rejected=True, under_ten_minutes=True, aggregation_seconds=599,
                    input_sha3=f'input{case}', source_sha3='source', selection_sha3=None,
                    artifact_sha3=f'artifact{case}-{i}')
                records.append(dict(status='passed', label=f'run{case}-{i}', source_inputs_unchanged=True,
                    executable_unchanged=True, all_subprocesses_terminal_and_reaped=True,
                    executable_provenance=dict(sha256='binary'), environment=dict(LATTICA_GPU_DEVICE_UUID='gpu'),
                    gpu_aggregation_acceptance=row))
        self.assertTrue(qualification(records)['performance_qualified'])
        self.assertFalse(qualification(records[:-1])['performance_qualified'])
        self.assertFalse(qualification(records[:1]*3 + records[3:])['performance_qualified'])
        for change in ('source_sha3', 'input_sha3', 'artifact_sha3'):
            altered = copy.deepcopy(records)
            altered[-1]['gpu_aggregation_acceptance']['report'][change] = 'changed' if change != 'artifact_sha3' else 'artifact4-0'
            self.assertFalse(qualification(altered)['performance_qualified'])
        altered = copy.deepcopy(records)
        for record in altered[3:]: record['environment']['LATTICA_GPU_DEVICE_UUID'] = 'other-device'
        self.assertFalse(qualification(altered)['performance_qualified'])
        records[-1]['gpu_aggregation_acceptance']['report']['aggregation_seconds'] = 600
        self.assertFalse(qualification(records)['performance_qualified'])

    def test_gpu_budget_cannot_read_or_reset_a_cpu_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'budget.json'
            budget = AggregationBudget(path)
            self.assertEqual(budget.job_seconds, 600)
            self.assertEqual(budget.remaining(), 3600)
            value = budget.read(); value['schema'] = 'cpu-proof-test-budget-v1'; budget.save(value)
            with self.assertRaises(RuntimeError): budget.remaining()

    def test_layout_costs_require_matched_native_inputs_and_real_admitted_width(self):
        from gpu_aggregation_select import matched_cost
        def record(candidate):
            return dict(status='passed',environment=dict(LATTICA_GPU_DEVICE_UUID='gpu'),gpu_aggregation_acceptance=dict(
                options=dict(command='screen',profile='grouped-v2' if candidate else 'legacy',transactions=3,workload=0,family='shake'),
                report=dict(verified=True,complete_aggregation=False,scope='complete-shake-request-screen',input_sha3='in',source_sha3='src',request=1,
                    width=4 if candidate else 2,admitted_maximum_group=4 if candidate else 2,
                    samples=[dict(repetition=i,verified=True,seconds=8 if candidate else 10,process_state='first-request' if i==0 else 'warm-request') for i in range(4)])))
        baseline,candidate=record(False),record(True)
        self.assertEqual(matched_cost(baseline,candidate)[2]['candidate'],[8,8,8])
        for key,value in [('input_sha3','changed'),('admitted_maximum_group',2),('samples',[])]:
            bad=copy.deepcopy(candidate);bad['gpu_aggregation_acceptance']['report'][key]=value
            with self.assertRaises(RuntimeError):matched_cost(baseline,bad)


if __name__ == '__main__':
    unittest.main()
