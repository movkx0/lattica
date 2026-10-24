"""Experiment provenance checks; these synthetic tests launch no GPU work."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_opencl_private_spend_benchmark import arguments, result_fixture, runner


class ExperimentSelectionTests(unittest.TestCase):
    def test_source_manifest_includes_new_research_crates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prover = root / 'lattica-prover-p3'
            prover.mkdir()
            for name in ('Cargo.toml', 'Cargo.lock', 'build.rs'):
                (prover / name).write_text('fixture')
            crate = root / 'research/pq-direct-spend'
            (crate / 'src').mkdir(parents=True)
            (crate / 'src/lib.rs').write_text('source')
            (crate / 'Cargo.lock').write_text('lock')
            (crate / 'target').mkdir()
            (crate / 'target/output').write_text('not a source input')
            with patch.object(runner, 'ROOT', root):
                manifest = runner.source_manifest()
            self.assertIn('research/pq-direct-spend/src/lib.rs', manifest)
            self.assertIn('research/pq-direct-spend/Cargo.lock', manifest)
            self.assertNotIn('research/pq-direct-spend/target/output', manifest)

    def test_defaults_preserve_historical_baseline(self):
        plan = runner.build_plan(arguments())
        self.assertEqual(runner.experiment_selection(plan), {
            'metadata_capacity': 256, 'registration_telemetry': 'off',
            'shake_wrappers': 'singleton', 'prepared_reuse': 'single_entry',
        })
        runner.validate_experiments(result_fixture(benchmark=True), plan)

    def test_options_select_independently(self):
        args = arguments()
        args.command += ['--metadata-capacity', '512', '--shake-wrappers', 'paired-v1']
        selection = runner.experiment_selection(runner.build_plan(args))
        self.assertEqual(selection['metadata_capacity'], 512)
        self.assertEqual(selection['shake_wrappers'], 'paired-v1')
        self.assertEqual(selection['registration_telemetry'], 'off')

    def test_malformed_selection_rejected_before_dispatch(self):
        for extra in (
            ['--metadata-capacity', '1024'], ['--metadata-capacity=512'],
            ['--metadata-capacity', '512', '--metadata-capacity', '256'],
            ['--shake-wrappers', 'paired-v2'], ['--registration-telemetry'],
            ['--registration-telemetry', 'unbounded'],
        ):
            with self.subTest(extra=extra):
                args = arguments()
                args.command += extra
                with self.assertRaises(ValueError):
                    runner.build_plan(args)

    def candidate(self):
        args = arguments()
        args.command += ['--metadata-capacity', '512']
        plan = runner.build_plan(args)
        result = result_fixture(benchmark=True)
        result['experiments'] = runner.experiment_selection(plan)
        result['context']['maximum_metadata_entries'] = 512
        result['context']['registration_telemetry'] = {'enabled': False}
        result['context']['prepared_reuse_mode'] = 'single_entry'
        for case in result['cases']:
            case['experiments'] = dict(result['experiments'])
        return plan, result

    def test_candidate_must_report_selected_experiment(self):
        plan, result = self.candidate()
        runner.validate_experiments(result, plan)
        del result['experiments']
        with self.assertRaises(ValueError):
            runner.validate_experiments(result, plan)

    def test_context_or_case_fallback_rejected(self):
        plan, result = self.candidate()
        changed = copy.deepcopy(result)
        changed['context']['maximum_metadata_entries'] = 256
        with self.assertRaisesRegex(ValueError, 'context metadata'):
            runner.validate_experiments(changed, plan)
        changed = copy.deepcopy(result)
        changed['cases'][1]['experiments']['metadata_capacity'] = 256
        with self.assertRaisesRegex(ValueError, 'case experiment'):
            runner.validate_experiments(changed, plan)

    def test_trace_instrumentation_is_part_of_trial_identity(self):
        plan, result = self.candidate()
        plan['command'] += ['--registration-telemetry', 'bounded']
        with self.assertRaisesRegex(ValueError, 'differs from command'):
            runner.validate_experiments(result, plan)

    def test_context_telemetry_must_match_selected_mode(self):
        for mode in ('off', 'bounded'):
            plan, result = self.candidate()
            plan['command'] += ['--registration-telemetry', mode]
            result['experiments']['registration_telemetry'] = mode
            for case in result['cases']:
                case['experiments']['registration_telemetry'] = mode
            enabled = mode == 'bounded'
            result['context']['registration_telemetry']['enabled'] = enabled
            runner.validate_experiments(result, plan)
            for wrong in (not enabled, None, int(enabled), str(enabled)):
                with self.subTest(mode=mode, wrong=wrong):
                    result['context']['registration_telemetry']['enabled'] = wrong
                    with self.assertRaisesRegex(ValueError, 'context registration telemetry'):
                        runner.validate_experiments(result, plan)

    def test_context_prepared_reuse_cannot_silently_differ(self):
        for mode in ('multi_entry', None):
            plan, result = self.candidate()
            result['context']['prepared_reuse_mode'] = mode
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(ValueError, 'context prepared reuse'):
                    runner.validate_experiments(result, plan)


if __name__ == '__main__':
    unittest.main()
