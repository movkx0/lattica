import copy
import datetime
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import opencl_workflow_comparison as comparison


def run(index, candidate=False, wall=None, cases=None):
    selected = comparison.guard.experiment_selection({'command': []})
    if candidate:
        selected['shake_wrappers'] = 'paired-v1'
    start = datetime.datetime(2026, 10, 24, index, tzinfo=datetime.timezone.utc)
    record = {
        'started_utc': start.isoformat(),
        'finished_utc': (start + datetime.timedelta(minutes=20)).isoformat(),
        'command': ['driver', '--counts', '3,4', '--benchmark', '--shake-wrappers',
                    selected['shake_wrappers'], '--output-dir', f'output-{index}'],
        'input_sha256': {'source.rs': 'source-hash'},
        'executable_provenance': {'sha256': 'binary-hash'},
        'environment': {'RAYON_NUM_THREADS': '8', 'CARGO_BUILD_JOBS': '2',
                        'LATTICA_PROVING_POLICY': 'gpu-required'},
        'cpu_quota': '800%', 'memory_high_bytes': 43 << 30,
        'raw_log_sha256': f'log-hash-{index}',
        'correctness_result': {'experiments': selected, 'context': {'device': {
            'name': 'NVIDIA GeForce RTX 5080', 'uuid': 'gpu-one'}}},
    }
    times = cases if cases is not None else ([423, 470] if candidate else [450, 500])
    report = {
        'experiments': selected,
        'measurement': {'transactions': 7, 'run_wall_seconds': wall if wall is not None else (940 if candidate else 1000)},
        'cases': [{'transactions': count, 'active_workflow_seconds': times[i],
                   'fresh_proofs_by_family': {'shake': 100 * count, 'aes': count, 'outer': (327 if candidate else 445) * count}}
                  for i, count in enumerate((3, 4))],
        'memory': {'driver_limits': {'--host-bytes': 32 << 30, '--device-bytes': 8 << 30,
                                    '--native-bytes': 24 << 30, '--max-rows': 1 << 20},
                   'process_cap_bytes': 47 << 30, 'gpu_context_reserve_bytes': str(4 << 30),
                   'cgroup_swap_limit_bytes': '0'},
        'provenance': {'envelope_sha256': f'envelope-hash-{index}', 'guard_sha256': f'guard-hash-{index}'},
    }
    return {'path': f'envelope-{index}.json', 'guard_sha256': f'guard-hash-{index}',
            'report': report, 'record': record}


def fixture():
    return run(0, True), [
        {'baseline': run(1), 'candidate': run(2, True)},
        {'baseline': run(4), 'candidate': run(3, True)},
        {'baseline': run(5), 'candidate': run(6, True)},
    ]


class ComparisonTests(unittest.TestCase):
    def test_three_alternating_pairs_pass_only_timing_gate(self):
        report = comparison.compare(*fixture())
        self.assertTrue(report['timing_criteria_passed'])
        self.assertFalse(report['performance_qualified'])
        self.assertEqual(report['median_workflow_seconds'], {'baseline': 1000, 'candidate': 940})
        self.assertEqual(report['pair_orders'], [['baseline', 'candidate'], ['candidate', 'baseline'], ['baseline', 'candidate']])
        self.assertEqual(len(report['evidence']), 7)

    def test_complete_wall_median_controls_gate_not_proof_counts_or_one_fast_run(self):
        screen, pairs = fixture()
        for pair, time in zip(pairs, [500, 951, 970]):
            pair['candidate']['report']['measurement']['run_wall_seconds'] = time
        report = comparison.compare(screen, pairs)
        self.assertFalse(report['timing_criteria_passed'])
        self.assertEqual(report['median_workflow_seconds']['candidate'], 951)
        pairs[1]['candidate']['report']['measurement']['run_wall_seconds'] = 950
        self.assertTrue(comparison.compare(screen, pairs)['timing_criteria_passed'])

    def test_case_median_regression_blocks_faster_total(self):
        screen, pairs = fixture()
        for pair in pairs:
            pair['candidate']['report']['cases'][0]['active_workflow_seconds'] = 460
        report = comparison.compare(screen, pairs)
        self.assertTrue(report['at_least_five_percent_faster'])
        self.assertFalse(report['timing_criteria_passed'])
        for pair in pairs:
            pair['candidate']['report']['cases'][0]['active_workflow_seconds'] = 459
        self.assertTrue(comparison.compare(screen, pairs)['timing_criteria_passed'])

    def test_repetition_reuse_missing_pairs_overlap_and_non_alternation_refuse(self):
        for mutation in ('reuse', 'log_reuse', 'missing', 'overlap', 'non_alternating', 'screen_after_pair'):
            with self.subTest(mutation=mutation):
                screen, pairs = fixture()
                if mutation == 'reuse':
                    pairs[0]['candidate']['guard_sha256'] = screen['guard_sha256']
                elif mutation == 'log_reuse':
                    pairs[0]['candidate']['record']['raw_log_sha256'] = screen['record']['raw_log_sha256']
                elif mutation == 'missing':
                    pairs.pop()
                elif mutation == 'overlap':
                    pairs[0]['candidate']['record']['started_utc'] = pairs[0]['baseline']['record']['started_utc']
                elif mutation == 'non_alternating':
                    for key in ('started_utc', 'finished_utc'):
                        a, b = pairs[1]['baseline']['record'], pairs[1]['candidate']['record']
                        a[key], b[key] = b[key], a[key]
                else:
                    screen['record']['finished_utc'] = pairs[0]['candidate']['record']['finished_utc']
                with self.assertRaises(ValueError):
                    comparison.compare(screen, pairs)

    def test_changed_source_binary_device_resources_and_native_work_refuse(self):
        mutations = [
            lambda x: x['record']['input_sha256'].update({'source.rs': 'changed'}),
            lambda x: x['record']['executable_provenance'].update(sha256='changed'),
            lambda x: x['record']['correctness_result']['context']['device'].update(uuid='other'),
            lambda x: x['record']['environment'].update(RAYON_NUM_THREADS='9'),
            lambda x: x['record']['environment'].update(LATTICA_PROVING_POLICY='cpu'),
            lambda x: x['report']['memory'].update(process_cap_bytes=48 << 30),
            lambda x: x['report']['memory'].update(cgroup_swap_limit_bytes='1'),
            lambda x: x['report']['memory']['driver_limits'].update({'--max-rows': 1 << 21}),
            lambda x: x['report']['cases'][0]['fresh_proofs_by_family'].update(shake=299),
            lambda x: x['record']['command'].extend(['--unknown-experiment', '1']),
        ]
        for mutation in mutations:
            screen, pairs = fixture()
            mutation(pairs[1]['candidate'])
            with self.assertRaises(ValueError):
                comparison.compare(screen, pairs)

    def test_no_combined_redesign_telemetry_or_changed_screening_candidate(self):
        for field, value in [('metadata_capacity', 512), ('registration_telemetry', 'bounded'),
                             ('profile', 'private-note')]:
            screen, pairs = fixture()
            for item in [screen] + [p['candidate'] for p in pairs]:
                item['report']['experiments'][field] = value
            with self.assertRaises(ValueError):
                comparison.compare(screen, pairs)
        screen, pairs = fixture()
        screen['report']['experiments']['shake_wrappers'] = 'singleton'
        with self.assertRaises(ValueError):
            comparison.compare(screen, pairs)

    def test_partial_cases_and_invalid_timing_refuse(self):
        for value in (0, -1, float('nan'), float('inf'), True):
            screen, pairs = fixture()
            pairs[2]['candidate']['report']['measurement']['run_wall_seconds'] = value
            with self.assertRaises(ValueError):
                comparison.compare(screen, pairs)
        screen, pairs = fixture()
        pairs[0]['baseline']['report']['cases'].pop()
        with self.assertRaises(ValueError):
            comparison.compare(screen, pairs)

    def test_loader_requires_terminal_source_and_explicit_selection(self):
        for missing in ('source_inputs_unchanged', 'executable_unchanged',
                        'service_stop_completed', 'experiments'):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                item = run(0, True)
                record = copy.deepcopy(item['record'])
                for key in ('source_inputs_unchanged', 'executable_unchanged', 'service_stop_completed'):
                    record[key] = True
                if missing == 'experiments':
                    del record['correctness_result']['experiments']
                else:
                    record[missing] = False
                path = Path(directory) / 'guard.json'
                path.write_text(json.dumps(record))
                envelope = Path(directory) / 'envelope.json'
                envelope.write_text(json.dumps({'guard': str(path)}))
                item['report']['provenance']['guard_sha256'] = comparison.guard.sha(path)
                with mock.patch.object(comparison.metrics, 'audited_metrics', return_value=item['report']):
                    with self.assertRaises(ValueError):
                        comparison.load_run(envelope)


if __name__ == '__main__':
    unittest.main()
