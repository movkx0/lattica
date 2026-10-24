"""Synthetic receipt/provenance tests; no service, compiler or GPU is launched.

Uses the sibling runner by default. Set OPENCL_PRIVATE_SPEND_VALIDATE_RUNNER to review a
runner in another worktree without copying or changing that worktree's sources.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


RUNNER_PATH = Path(os.environ.get(
    'OPENCL_PRIVATE_SPEND_VALIDATE_RUNNER',
    str(Path(__file__).with_name('opencl_private_spend_validate.py')),
))
spec = importlib.util.spec_from_file_location('opt_validate_acceptance', RUNNER_PATH)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def receipt(entry, scope):
    stages = ['public_values', 'witness_trace', 'preprocessing', 'transform',
              'quotient', 'randomness', 'hiding', 'commitment', 'opening',
              'fri_fold', 'fri_query', 'final_polynomial', 'scalar',
              'transcript', 'grinding']
    if scope == 'preprocessing':
        stages = ['preprocessing', 'randomness', 'transform', 'commitment']
    elif scope == 'operation':
        stages = ['witness_trace']
    elif scope == 'registered_proof':
        stages.remove('public_values')
        stages.append('lookup')
    return {
        'schema': 'lattica-proving-stages-v1', 'entry_point': entry,
        'policy': 'gpu_required', 'succeeded': True,
        'stage_coverage_complete': True, 'completion_rejected': False,
        'observation_errors': 0, 'components': [],
        'capabilities': {
            'profile': 'matrict_n10' if entry == 'native_matrict_spend' else 'block_v2_cubic', 'scope': scope,
            'stages': [{'stage': stage, 'backend': 'open_cl'} for stage in stages],
        },
        'observations': [{
            'stage': stage, 'backend': 'open_cl',
            'calls': 2, 'completed_calls': 2, 'device_calls': 2,
        } for stage in stages],
    }


class ReceiptAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.command = patch.object(
            runner, 'command', side_effect=AssertionError('unexpected command launch'))
        self.command.start()
        self.addCleanup(self.command.stop)
        self.reports = [
            receipt('block_v2_preprocessing', 'preprocessing'),
            receipt('block_v2_registered_program', 'registered_proof'),
            receipt('pq_statement', 'proof_request'),
            receipt('pq_graph_witness_preparation', 'operation'),
            receipt('native_matrict_spend', 'operation'),
        ]
        self.result = {'cases': [{'count': 1, 'cache': {'families': {'sources': {'fresh_proofs': 1}}}}], 'context': {
            'policy': 'gpu_required', 'registrations': 1,
            'operations': {
                'witness_preparation_calls': 1, 'witness_preparation_succeeded': 1,
                'witness_preparation_complete_reports': 1,
                'witness_preparation_stage': {'stage': 'witness_trace', 'completed_calls': 2, 'device_calls': 2},
                'prove_calls': 1, 'prove_succeeded': 1,
                'native_cpu_calls': 0, 'native_cpu_succeeded': 0, 'failures': [],
                'native_spend_calls': 1, 'native_spend_succeeded': 1, 'native_spend_complete_reports': 1,
                'native_spend_stage': {'stage': 'witness_trace', 'completed_calls': 2, 'device_calls': 2},
                'native_gpu_calls': 1, 'native_gpu_succeeded': 1, 'native_gpu_complete_reports': 1,
            },
        }}

    def validate(self, reports=None):
        if reports is None:
            reports = self.reports
        content = '\n'.join('proving_stage_report ' + json.dumps(report)
                            for report in reports)
        return runner.validate_receipts(content, self.result)

    def reject_mutation(self, mutate):
        reports = copy.deepcopy(self.reports)
        mutate(reports)
        with self.assertRaises(ValueError):
            self.validate(reports)

    def test_completed_gpu_receipts_are_accepted(self):
        accepted = self.validate()
        self.assertTrue(accepted['completed_stage_receipts_checked'])
        self.assertEqual(accepted['machine_gpu_reports'], {
            'block_v2_preprocessing': 1, 'block_v2_registered_program': 1,
        })

    def test_native_cpu_policy_is_rejected(self):
        self.reject_mutation(lambda reports: reports[2].update(policy='cpu_required'))

    def test_all_native_implementation_names_are_accepted(self):
        families = {
            'sources': ['pq_statement', 'pq_private_source'],
            'algebra': ['matrict_affine_gpu', 'matrict_ntt_gpu', 'matrict_mul_gpu',
                        'matrict_g_bound_gpu', 'matrict_permutation_gpu', 'matrict_linear_map_gpu'],
            'crypto': ['pq_aes_lane_native', 'pq_shake_segment_native',
                       'pq_aes_wide_native', 'pq_shake_wide_native'],
            'auxiliary': ['pq_uniform_gpu', 'pq_sparse_gpu', 'pq_transcript_source'],
        }
        for family, entries in families.items():
            for entry in entries:
                with self.subTest(entry=entry):
                    reports = copy.deepcopy(self.reports)
                    reports[2]['entry_point'] = entry
                    self.result['cases'][0]['cache']['families'] = {family: {'fresh_proofs': 1}}
                    self.assertEqual(self.validate(reports)['native_gpu_reports'], 1)

    def test_unknown_native_entry_is_rejected(self):
        for entry in ['pq_unregistered', 'matrict_unregistered', 'explicit_native']:
            with self.subTest(entry=entry):
                self.reject_mutation(lambda reports: reports[2].update(entry_point=entry))

    def test_shortened_machine_inventories_are_rejected(self):
        for index in range(2):
            with self.subTest(entry=self.reports[index]['entry_point']):
                reports = copy.deepcopy(self.reports)
                # Capability and observation agree, and success flags still
                # claim completion. The independent contract must reject it.
                reports[index]['capabilities']['stages'].pop()
                reports[index]['observations'].pop()
                with self.assertRaises(ValueError):
                    self.validate(reports)

    def test_machine_substituted_stage_is_rejected(self):
        for index, stage in [(0, 'lookup'), (1, 'public_values')]:
            with self.subTest(entry=self.reports[index]['entry_point']):
                reports = copy.deepcopy(self.reports)
                reports[index]['capabilities']['stages'][0]['stage'] = stage
                reports[index]['observations'][0]['stage'] = stage
                with self.assertRaises(ValueError):
                    self.validate(reports)

    def test_machine_extra_stage_is_rejected(self):
        for index, stage in [(0, 'witness_trace'), (1, 'public_values')]:
            with self.subTest(entry=self.reports[index]['entry_point']):
                reports = copy.deepcopy(self.reports)
                reports[index]['capabilities']['stages'].append({'stage': stage, 'backend': 'open_cl'})
                reports[index]['observations'].append({
                    'stage': stage, 'backend': 'open_cl', 'calls': 1,
                    'completed_calls': 1, 'device_calls': 1,
                })
                with self.assertRaises(ValueError):
                    self.validate(reports)

    def test_preparation_requires_matching_operation_receipts(self):
        for field in ['witness_preparation_calls', 'witness_preparation_succeeded',
                      'witness_preparation_complete_reports']:
            with self.subTest(field=field):
                self.result['context']['operations'][field] = 0
                with self.assertRaises(ValueError):
                    self.validate()
                self.result['context']['operations'][field] = 1
        for field in ['completed_calls', 'device_calls']:
            self.result['context']['operations']['witness_preparation_stage'][field] = 3
            with self.assertRaises(ValueError):
                self.validate()
            self.result['context']['operations']['witness_preparation_stage'][field] = 2

    def test_preparation_cannot_masquerade_as_native_proof(self):
        self.reject_mutation(lambda reports: reports[3]['capabilities'].update(scope='proof_request'))
        self.reject_mutation(lambda reports: reports[3].update(policy='cpu_required'))
        self.reject_mutation(lambda reports: reports[3]['observations'][0].update(device_calls=0))
        self.reject_mutation(lambda reports: reports.pop())

    def test_native_missing_stage_is_rejected(self):
        self.reject_mutation(lambda reports: reports[2]['capabilities']['stages'].pop())

    def test_native_missing_receipt_is_rejected(self):
        self.reject_mutation(lambda reports: reports[2]['observations'].pop())

    def test_cpu_native_context_call_is_rejected(self):
        self.result['context']['operations']['native_cpu_calls'] = 1
        with self.assertRaises(ValueError):
            self.validate()

    def test_missing_native_proof_inventory_is_rejected(self):
        self.result['cases'][0]['cache']['families']['sources']['fresh_proofs'] = 2
        with self.assertRaises(ValueError):
            self.validate()

    def test_all_cases_and_native_families_are_counted_but_outer_is_not(self):
        self.result['cases'] = [
            {'count': 1, 'cache': {'families': {
                'sources': {'fresh_proofs': 1}, 'algebra': {'fresh_proofs': 1},
                'outer': {'fresh_proofs': 20},
            }}},
            {'count': 1, 'cache': {'families': {
                'crypto': {'fresh_proofs': 1}, 'auxiliary': {'fresh_proofs': 1},
                'outer': {'fresh_proofs': 30},
            }}},
        ]
        reports = self.reports[:2] + self.reports[3:] + [
            receipt(entry, 'proof_request') for entry in
            ['pq_statement', 'matrict_affine_gpu', 'pq_aes_lane_native', 'pq_uniform_gpu']
        ]
        reports.append(receipt('native_matrict_spend', 'operation'))
        operations = self.result['context']['operations']
        for counter in ['native_gpu_calls', 'native_gpu_succeeded', 'native_gpu_complete_reports']:
            operations[counter] = 4
        for counter in ['native_spend_calls', 'native_spend_succeeded', 'native_spend_complete_reports']:
            operations[counter] = 2
        operations['native_spend_stage'].update(completed_calls=4, device_calls=4)
        self.assertEqual(self.validate(reports)['native_gpu_reports'], 4)
        with self.assertRaisesRegex(ValueError, 'private-spend receipts'):
            self.validate(reports[:-1])
        for index, case in enumerate(self.result['cases']):
            with self.subTest(missing_transaction_count=index):
                del case['count']
                with self.assertRaisesRegex(ValueError, 'private-spend receipts'):
                    self.validate(reports)
                case['count'] = 1
        for case, family in [(0, 'sources'), (0, 'algebra'), (1, 'crypto'), (1, 'auxiliary')]:
            with self.subTest(family=family):
                counts = self.result['cases'][case]['cache']['families'][family]
                counts['fresh_proofs'] = 2
                with self.assertRaisesRegex(ValueError, 'fresh proof inventory'):
                    self.validate(reports)
                counts['fresh_proofs'] = 1

    def test_machine_cpu_policy_is_rejected(self):
        self.reject_mutation(lambda reports: reports[0].update(policy='cpu_required'))

    def test_incomplete_calls_are_rejected(self):
        self.reject_mutation(lambda reports:
                             reports[1]['observations'][0].update(completed_calls=1))

    def test_missing_device_execution_is_rejected(self):
        self.reject_mutation(lambda reports:
                             reports[1]['observations'][0].update(device_calls=0))

    def test_cpu_observation_is_rejected(self):
        self.reject_mutation(lambda reports:
                             reports[1]['observations'][0].update(backend='cpu'))

    def test_observation_errors_are_rejected(self):
        self.reject_mutation(lambda reports: reports[1].update(observation_errors=1))

    def test_changed_proof_profile_is_rejected(self):
        self.reject_mutation(lambda reports:
                             reports[0]['capabilities'].update(profile='legacy_quadratic'))

    def test_wrong_operation_scope_is_rejected(self):
        self.reject_mutation(lambda reports:
                             reports[1]['capabilities'].update(scope='operation'))

    def test_missing_promised_stage_is_rejected(self):
        self.reject_mutation(lambda reports: reports[0]['capabilities']['stages'].append(
            {'stage': 'commitment', 'backend': 'open_cl'}))

    def test_compatible_policy_is_rejected(self):
        self.reject_mutation(lambda reports: reports[1].update(policy='compatible'))

    def test_missing_proof_receipt_is_rejected(self):
        with self.assertRaises(ValueError):
            self.validate(self.reports[:1])

    def test_duplicate_worker_receipts_are_rejected(self):
        with self.assertRaises(ValueError):
            self.validate(self.reports + self.reports)

    def test_explicit_native_cpu_work_is_rejected(self):
        native = receipt('explicit_native', 'proof_request')
        native['policy'] = 'cpu_required'
        with self.assertRaises(ValueError):
            self.validate(self.reports + [native])


    def test_private_spend_receipt_is_required_and_separate(self):
        self.assertEqual(self.validate()['native_private_spend_gpu_reports'], 1)
        self.reject_mutation(lambda reports: reports.pop(4))
        self.reject_mutation(lambda reports: reports[4].update(policy='cpu_required'))
        self.reject_mutation(lambda reports: reports[4]['capabilities'].update(profile='block_v2_cubic'))
        self.reject_mutation(lambda reports: reports[4]['capabilities'].update(scope='proof_request'))
        self.reject_mutation(lambda reports: reports[4].pop('components'))
        self.reject_mutation(lambda reports: reports[4].update(components=[{'backend': 'cpu'}]))
        self.reject_mutation(lambda reports: reports.append(copy.deepcopy(reports[4])))

    def test_private_spend_count_matches_fresh_transactions(self):
        for field in ('native_spend_calls', 'native_spend_succeeded', 'native_spend_complete_reports'):
            saved = self.result['context']['operations'][field]
            self.result['context']['operations'][field] = 0
            with self.assertRaises(ValueError):
                self.validate()
            self.result['context']['operations'][field] = saved
        self.result['cases'][0]['count'] = 2
        with self.assertRaises(ValueError):
            self.validate()


class ScopeContractTests(unittest.TestCase):
    def setUp(self):
        self.command = patch.object(
            runner, 'command', side_effect=AssertionError('unexpected command launch'))
        self.command.start()
        self.addCleanup(self.command.stop)
        merge = {
            'backend': 'opencl', 'strict_gpu_request': True,
            'native_parent_verification': True, 'cache_policy': 'fresh_only',
            'proof_cache_hit': False,
        }
        self.result = {
            'schema': 'pq-opencl-opt-correctness-v2', 'passed': True,
            'comparison_baseline': False, 'performance_qualified': False,
            'fixture_pattern': 'fresh_distinct',
            'proving_scope': 'native_private_spend_and_native_recursive_stark_proving',
            'fixture_generation': 'cpu_ring_ask_inputs_only',
            'native_private_spend_generation': 'gpu_required',
            'independent_verification': 'cpu', 'native_gpu_required': True,
            'witness_preparation': 'gpu_required',
            'original_profile': True, 'hiding': True, 'num_queries': 128,
            'blowup': 16, 'extension': 'Goldilocks cubic trinomial',
            'context': {
                'session_closed': True, 'prepared_entries': 0, 'maximum_prepared_entries': 1,
                'metadata_cache_payload_bytes': 0,
                'session_finish': {'commits': 1, 'allocations': 1, 'managed_peak_bytes': 1},
            },
            'cases': [{
                'count': 3, 'fresh_distinct_transactions': 3, 'complete_graphs_verified': 3,
                'statement_digests': [[0] * 4, [1] * 4, [2] * 4],
                'changed_public_rejected_count': 25, 'changed_proof_rejected': True,
                'distinct_reordering_rejected': True, 'distinct_substitution_rejected': True,
                'graph_proof_substitution_rejected': True,
                'decoded_verification_after_gpu_shutdown': True,
                'cache': {'policy': 'fresh_only', 'families': {
                    family: {'reads': 0, 'hits': 0, 'fresh_proofs': 1, 'proof_attempts': 1}
                    for family in ['sources', 'algebra', 'crypto', 'auxiliary', 'outer']
                }},
                'merges': [
                    dict(merge, aggregate_children=0, recursive_witness_checks=[]),
                    dict(merge, aggregate_children=1,
                         recursive_witness_checks=[{'altered_opening_rejected': True}]),
                ],
            }],
        }

    def test_explicit_cpu_fixture_and_gpu_stark_scope_is_accepted(self):
        runner.validate_result(self.result)

    def test_missing_scope_contract_fields_are_rejected(self):
        for field in ['proving_scope', 'fixture_generation',
                      'independent_verification', 'native_gpu_required']:
            with self.subTest(field=field):
                result = copy.deepcopy(self.result)
                del result[field]
                with self.assertRaises(ValueError):
                    runner.validate_result(result)

    def test_scope_overclaims_and_cpu_proving_are_rejected(self):
        replacements = {
            'proving_scope': 'all_transaction_compute',
            'fixture_generation': 'gpu_native_matrict',
            'independent_verification': 'gpu',
            'native_gpu_required': False,
        }
        for field, value in replacements.items():
            with self.subTest(field=field):
                result = copy.deepcopy(self.result)
                result[field] = value
                with self.assertRaises(ValueError):
                    runner.validate_result(result)


    def test_v1_cpu_spend_workflow_cannot_qualify_v2(self):
        old = copy.deepcopy(self.result)
        old.update(schema='pq-opencl-opt-correctness-v1',
                   fixture_generation='cpu_native_matrict',
                   proving_scope='native_and_recursive_stark_proving')
        old.pop('native_private_spend_generation', None)
        with self.assertRaises(ValueError):
            runner.validate_result(old)


class ExecutableProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.command = patch.object(
            runner, 'command', side_effect=AssertionError('unexpected command launch'))
        self.command.start()
        self.addCleanup(self.command.stop)
        self.directory = tempfile.TemporaryDirectory(prefix='opt-validator-test-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.executable = self.root / 'driver'
        self.executable.write_bytes(b'synthetic executable identity; never executed')
        self.executable.chmod(0o700)
        self.sources = {'source.rs': 'source-digest'}
        self.record = self.root / 'build-fixture.json'
        self.record.write_text(json.dumps({
            'status': 'passed', 'profile': 'build', 'source_inputs_unchanged': True,
            'all_subprocesses_terminal_and_reaped': True, 'input_sha256': self.sources,
            'built_artifact_sha256': {str(self.executable): runner.sha(self.executable)},
        }))
        self.plan = {'command': [str(self.executable)], 'build_label': 'build-fixture'}

    def test_matching_build_and_executable_are_accepted(self):
        accepted = runner.executable_provenance(self.plan, self.sources, self.root)
        self.assertEqual(accepted['sha256'], runner.sha(self.executable))
        self.assertEqual(accepted['build_record_sha256'], runner.sha(self.record))

    def test_changed_build_sources_are_rejected(self):
        with self.assertRaises(ValueError):
            runner.executable_provenance(
                self.plan, {'source.rs': 'different-source-digest'}, self.root)

    def test_replaced_executable_is_rejected(self):
        self.executable.write_bytes(b'replaced executable identity; never executed')
        with self.assertRaises(ValueError):
            runner.executable_provenance(self.plan, self.sources, self.root)


if __name__ == '__main__':
    unittest.main()
