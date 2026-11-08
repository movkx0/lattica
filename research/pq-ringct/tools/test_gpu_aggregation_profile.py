import argparse
import copy
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from gpu_aggregation_profile import AggregationBudget, selection, validate, qualification
from test_opencl_private_spend_validate import arguments, runner


class AggregationAcceptance(unittest.TestCase):
    def args(self, **changes):
        return arguments(**dict(dict(gpu_aggregation=True, profile='full', build_label='aggregation-build', seconds=600,
            device_uuid='GPU-279a9bfd-fd33-cd25-430a-4ceec2f63615', retained_tree_storage='host', host_profile='standard'), **changes))

    def argv(self):
        return ['/tmp/pq-ringct-gpu-aggregate', 'screen', '--case', 'n3', '--input-bundle', '/tmp/bundle']

    def report(self):
        return dict(schema='ringct-gpu-aggregation-v1', complete_fresh_workflow=False, performance_qualified=False,
            controller_wall_seconds=12.0, options=dict(command='screen', profile='legacy', transactions=3),
            report=dict(verified=True, complete_aggregation=False, session=dict(session_closed=True)))

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
