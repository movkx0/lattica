import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import owned_preprocessing_campaign as campaign


def args(configuration='baseline'):
    return SimpleNamespace(label='test-sample', seed='01' * 32, context='02' * 32,
                           seconds=86400, configuration=configuration, device_uuid='GPU-test',
                           build_label='test-build', execute=False)


def matrix_rows():
    return [dict(schema='ringct-cpu-identity-source-matrix-v1', transactions=n, fixture_count=n,
                 first_fixture=0 if n == 3 else 3, layout='singleton',
                 identity_cpu={'requested_workers': width, 'max_streams': width},
                 compiled_source_fingerprint=[1] * 32, worker_host_bytes=32 << 30,
                 managed_device_bytes=8 << 30, terminal_empty=True, complete_workflow_admitted=False,
                 gpu_dispatches=0, stark_proofs=0, source_claim_peak_host_bytes=1000,
                 compiler_construction_ceiling_bytes=2 << 30, peak_retained_compiler_host_bytes=500,
                 peak_prefix_incremental_host_bytes=0 if width == 1 else 200,
                 peak_prefix_borrowed_program_host_bytes=0 if width == 1 else 400,
                 peak_compilers=width, source_lifetimes_admitted=True, refusal=None, requests=n)
            for n in (3, 4) for width in campaign.SOURCE_SCHEDULES[campaign.SELECTOR]]


class CampaignTests(unittest.TestCase):
    def test_plans_exact_sequential_cases_without_execution(self):
        for config, selected in campaign.CONFIGURATIONS.items():
            commands = campaign.commands(args(config))
            self.assertEqual(len(commands), 2)
            for case, command in zip(('n3', 'n4'), commands):
                self.assertNotIn('--execute', command)
                self.assertNotIn('--exclusive-window', command)
                self.assertEqual(command[command.index('--case') + 1], case)
                self.assertEqual(command[command.index('--identity-cpu-workers') + 1], str(selected['identity_cpu_workers']))
                self.assertEqual(command[command.index('--metadata-cpu-workers') + 1], 'auto')
                self.assertEqual(command[command.index('--planning-cache') + 1], selected['planning_cache'])
                self.assertIn('--full-workflow-case', command)
                self.assertNotIn('--benchmark', command)

    def test_execution_stays_in_existing_guard(self):
        selected = args('cpu-4')
        selected.execute = True
        for command in campaign.commands(selected):
            self.assertIn('--execute', command)
            self.assertIn('--exclusive-window', command)
            self.assertEqual(Path(command[1]).name, 'opencl_private_spend_validate.py')

    def test_combined_launch_requires_independent_comparisons_before_reading_runs(self):
        self.assertEqual(campaign.combination_prerequisites([], campaign.CONFIGURATIONS['baseline'],
                                                           'build', 'GPU-test', '01' * 32, '02' * 32), [])
        with self.assertRaisesRegex(ValueError, 'two independent'):
            campaign.combination_prerequisites([], campaign.CONFIGURATIONS['geometry-cpu-2'],
                                              'build', 'GPU-test', '01' * 32, '02' * 32)

    def test_invalid_sample_labels_inputs_and_runtime_refuse(self):
        for key, value in [('label', '../bad'), ('label', 'x' * 53), ('seed', 'aa'),
                           ('context', 'AF' * 32), ('seconds', 86401)]:
            selected = args()
            setattr(selected, key, value)
            with self.subTest(key=key), self.assertRaises(ValueError):
                campaign.commands(selected)

    def audit(self, rows, selected='cpu-2', selector=campaign.SELECTOR):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / 'source.log'
            log.write_text('\n'.join('IDENTITY_SOURCE_MATRIX ' + json.dumps(r) for r in rows)
                           + '\ntest result: ok. 1 passed; 0 failed; 0 ignored\n')
            terminal = dict(status='passed', error=None, source_inputs_unchanged=True,
                            executable_unchanged=True, service_stop_completed=True,
                            all_subprocesses_terminal_and_reaped=True, terminal_state=dict(
                                Result='success', ExecMainStatus='0', MainPID='0', ControlPID='0'))
            build_log = root / 'build.log'
            build_log.write_text('synthetic')
            build = dict(terminal, profile='build', input_sha256={'source': 'hash'},
                         built_artifact_sha256={'/test-binary': 'binary'},
                         raw_log=str(build_log), raw_log_sha256=campaign.guard.sha(build_log))
            (root / 'runs').mkdir()
            build_path = root / 'runs/build.json'
            build_path.write_text(json.dumps(build))
            record = dict(terminal, profile='research-compile-large', expect_tests=True,
                          environment={'LATTICA_PROVING_POLICY': 'cpu-required'},
                          command=['/test-binary', selector, '--exact', '--ignored', '--nocapture', '--test-threads=1'],
                          input_sha256=build['input_sha256'], raw_log=str(log), raw_log_sha256=campaign.guard.sha(log),
                          executable_provenance=dict(build_record=str(build_path), sha256='binary',
                                                      build_record_sha256=campaign.guard.sha(build_path)))
            record_path = root / 'record.json'
            record_path.write_text(json.dumps(record))
            with patch.object(campaign.guard, 'STATE', root), patch.object(campaign.guard, 'source_manifest', return_value=build['input_sha256']):
                return campaign.source_matrix(record_path, campaign.CONFIGURATIONS[selected], 'build')

    def test_source_screen_preserves_partial_scope_and_refusals(self):
        rows = matrix_rows()
        rows[3].update(source_lifetimes_admitted=False, refusal='source memory refused')
        result = self.audit(rows)
        self.assertFalse(result['complete_workflow_admitted'])
        self.assertEqual(len(result['selected_rows']), 2)
        with self.assertRaisesRegex(ValueError, 'selected source geometry was refused'):
            self.audit(rows, 'cpu-8')

    def test_source_matrix_missing_reordered_or_scope_mutations_refuse(self):
        for change in ('missing', 'order', 'proof', 'complete', 'fingerprint', 'peak', 'cleanup'):
            rows = matrix_rows()
            if change == 'missing': rows.pop()
            elif change == 'order': rows.reverse()
            else:
                key, value = {'proof': ('stark_proofs', 1), 'complete': ('complete_workflow_admitted', True),
                              'fingerprint': ('compiled_source_fingerprint', [2] * 32),
                              'peak': ('source_claim_peak_host_bytes', (32 << 30) + 1),
                              'cleanup': ('terminal_empty', False)}[change]
                rows[3][key] = value
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.audit(rows)

    def test_width_eight_requires_both_source_rows_and_preserves_refusal(self):
        rows = matrix_rows()
        result = self.audit(rows, 'cpu-8')
        self.assertEqual([row['transactions'] for row in result['selected_rows']], [3, 4])
        self.assertTrue(all(row['identity_cpu']['max_streams'] == 8
                            for row in result['selected_rows']))
        next(row for row in rows if row['transactions'] == 4 and row['identity_cpu']['max_streams'] == 8).update(
            source_lifetimes_admitted=False, refusal='source memory refused')
        with self.assertRaisesRegex(ValueError, 'selected source geometry was refused'):
            self.audit(rows, 'cpu-8')
        # A refused wider cohort does not disqualify an independently admitted width.
        self.assertEqual(len(self.audit(rows, 'cpu-4')['selected_rows']), 2)

    def test_source_memory_census_must_preserve_construction_and_original_owners(self):
        for field, value in (
            ('compiler_construction_ceiling_bytes', 1 << 30),
            ('peak_retained_compiler_host_bytes', 1001),
            ('peak_prefix_borrowed_program_host_bytes', 501),
            ('peak_prefix_incremental_host_bytes', 25 << 30),
            ('peak_prefix_incremental_host_bytes', 0),
        ):
            rows = matrix_rows()
            row = next(row for row in rows if row['transactions'] == 3
                       and row['identity_cpu'] == {'requested_workers': 16, 'max_streams': 16})
            row[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.audit(rows, 'cpu-16')

    def test_partial_matrix_cannot_supply_missing_width_eight_evidence(self):
        rows = [row for row in matrix_rows() if row['identity_cpu']['max_streams'] != 8]
        with self.assertRaisesRegex(ValueError, f'all {2 * len(campaign.SOURCE_SCHEDULES[campaign.SELECTOR])} rows'):
            self.audit(rows, 'cpu-8')

    def test_focused_wide_screens_bind_their_selector_and_both_cases(self):
        for width, selector in ((16, campaign.SIXTEEN_SELECTOR),):
            rows = [row for row in matrix_rows() if row['identity_cpu']['max_streams'] == width]
            result = self.audit(rows, f'cpu-{width}', selector)
            self.assertEqual([row['transactions'] for row in result['selected_rows']], [3, 4])
            with self.assertRaisesRegex(ValueError, 'does not cover selected width'):
                self.audit(rows, 'cpu-8', selector)
            with self.assertRaisesRegex(ValueError, 'all 2 rows'):
                self.audit(rows[:1], f'cpu-{width}', selector)
            rows[1].update(source_lifetimes_admitted=False, refusal='source memory refused')
            with self.assertRaisesRegex(ValueError, 'selected source geometry was refused'):
                self.audit(rows, f'cpu-{width}', selector)


if __name__ == '__main__':
    unittest.main()
