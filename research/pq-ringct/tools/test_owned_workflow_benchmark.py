"""Synthetic timing/receipt tests; fixtures establish no cryptographic result."""
import copy
import datetime
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import owned_workflow_benchmark as bench
import test_full_workflow_case_integration as case_fixtures


def sample(index, candidate=False, times=None):
    selected = dict(bench.BASELINE, planning_cache='geometry-v1') if candidate else dict(bench.BASELINE)
    times = times or ([90, 90] if candidate else [100, 100])
    result = []
    for offset, name in enumerate(('n3', 'n4')):
        start = datetime.datetime(2026, 10, 24, tzinfo=datetime.timezone.utc) + datetime.timedelta(hours=3 * index + offset)
        result.append({'metrics': {
            'case': name, 'selection': selected.copy(), 'complete_workflow_ns': times[offset],
            'memory': {'worker_host_peak_bytes': 100, 'process_peak_bytes': 200},
            'proof_counts': {'native': 20, 'recursive': 10}, 'proof_rows': {'rows': 42},
            'evidence': {'guard_sha256': f'g-{index}-{name}', 'raw_log_sha256': f'l-{index}-{name}'}},
            'start': start, 'end': start + datetime.timedelta(minutes=30),
            'inputs': {'seed': name}, 'fixed': {'source': 'same', 'device': 'same'}})
    return result


def campaign():
    return sample(0, True), [
        {'baseline': sample(1), 'candidate': sample(2, True)},
        {'baseline': sample(4), 'candidate': sample(3, True)},
        {'baseline': sample(5), 'candidate': sample(6, True)},
    ]


class TimingTests(unittest.TestCase):
    def test_three_alternating_pairs_use_complete_case_medians(self):
        result = bench.compare(*campaign())
        self.assertTrue(result['timing_criteria_passed'])
        self.assertFalse(result['performance_qualified'])
        self.assertEqual(result['median_workflow_ns'], {'baseline': 200, 'candidate': 180})
        self.assertEqual(result['pair_orders'], [['baseline', 'candidate'], ['candidate', 'baseline'], ['baseline', 'candidate']])
        self.assertEqual(len(result['evidence']), 14)

    def test_one_fast_sample_cannot_hide_slow_median(self):
        screening, pairs = campaign()
        for p, value in zip(pairs, (20, 96, 100)):
            for c in p['candidate']:
                c['metrics']['complete_workflow_ns'] = value
        self.assertFalse(bench.compare(screening, pairs)['timing_criteria_passed'])
        for c in pairs[1]['candidate']:
            c['metrics']['complete_workflow_ns'] = 95
        self.assertTrue(bench.compare(screening, pairs)['timing_criteria_passed'])

    def test_case_regression_blocks_combined_gain(self):
        screening, pairs = campaign()
        for p in pairs:
            p['candidate'][0]['metrics']['complete_workflow_ns'] = 103
            p['candidate'][1]['metrics']['complete_workflow_ns'] = 60
        result = bench.compare(screening, pairs)
        self.assertTrue(result['at_least_five_percent_faster'])
        self.assertFalse(result['timing_criteria_passed'])
        for p in pairs:
            p['candidate'][0]['metrics']['complete_workflow_ns'] = 102
        self.assertTrue(bench.compare(screening, pairs)['timing_criteria_passed'])

    def test_mismatched_or_reused_evidence_refuses(self):
        mutations = {
            'source': lambda c: c['fixed'].update(source='other'),
            'device': lambda c: c['fixed'].update(device='other'),
            'inputs': lambda c: c['inputs'].update(seed='other'),
            'counts': lambda c: c['metrics']['proof_counts'].update(native=19),
            'rows': lambda c: c['metrics']['proof_rows'].update(rows=41),
            'selector': lambda c: c['metrics']['selection'].update(planning_cache='off'),
            'overlap': lambda c: c.update(start=datetime.datetime(2026, 10, 24, tzinfo=datetime.timezone.utc)),
            'log': lambda c: c['metrics']['evidence'].update(raw_log_sha256='l-0-n3'),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                screening, pairs = campaign()
                mutate(pairs[0]['candidate'][0])
                with self.assertRaises(ValueError):
                    bench.compare(screening, pairs)

    def test_tie_prefers_lower_memory_then_width(self):
        def candidate(time, memory, width):
            return dict(timing_criteria_passed=True, comparison_identity='same',
                        median_workflow_ns={'candidate': time}, peak_host_bytes=memory,
                        selection=dict(bench.BASELINE, identity_cpu_workers=width))
        fastest = candidate(100, 400, 4)
        smaller = candidate(102, 200, 2)
        too_slow = candidate(103, 100, 1)
        self.assertIs(bench.select_candidate([fastest, smaller, too_slow]), smaller)
        narrow = candidate(101, 200, 1)
        self.assertIs(bench.select_candidate([fastest, smaller, narrow]), narrow)
        with self.assertRaises(ValueError):
            bench.select_candidate([dict(fastest, timing_criteria_passed=False)])

    def test_combination_requires_independent_qualified_manifests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            screening, pairs = campaign()
            combined = dict(bench.BASELINE, planning_cache='geometry-v1', identity_cpu_workers=2)
            for s in [screening] + [p['candidate'] for p in pairs]:
                for c in s:
                    c['metrics']['selection'] = combined.copy()
            manifest = {'schema': bench.SCHEMA, 'screening': 'screen', 'pairs': [
                {'baseline': 'b0', 'candidate': 'c0'}, {'baseline': 'b1', 'candidate': 'c1'},
                {'baseline': 'b2', 'candidate': 'c2'}]}
            path = root / 'combined.json'
            path.write_text(json.dumps(manifest))
            with patch.object(bench, 'load_sample', side_effect=[screening] + [p[r] for p in pairs for r in ('baseline', 'candidate')]):
                with self.assertRaisesRegex(ValueError, 'independent qualified'):
                    bench.compare_manifest(path)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.fixture = case_fixtures.CompleteCaseIntegrationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def make_record(self, count=3):
        events, envelope, plan, artifact, packet = self.fixture.case(count)
        root = artifact.parent
        raw = root / 'case.log'
        # The artifact guard requires its directory to contain only the packet.
        artifact_dir = root / 'artifact'
        artifact_dir.mkdir()
        artifact.rename(artifact_dir / artifact.name)
        plan[bench.case_guard.KEY]['output_directory'] = str(artifact_dir)
        raw.write_text(self.fixture.content(events, envelope))
        acceptance = bench.case_guard.validate_log(raw.read_text(), plan, bench.guard.collect_gpu_receipts)
        state = dict(Result='success', ExecMainStatus='0', MainPID='0', ControlPID='0',
                     MemorySwapMax='0', MemoryMax=str(47 << 30), MemoryHigh=str(45 << 30), MemoryPeak='65536')
        terminal = dict(status='passed', error=None, source_inputs_unchanged=True,
                        executable_unchanged=True, service_stop_completed=True,
                        all_subprocesses_terminal_and_reaped=True, terminal_state=state)
        executable = '/repo/.tools/target-opencl/release/pq-ringct-full-workflow'
        build_log = root / 'build.log'
        build_log.write_text('synthetic build fixture')
        build = dict(terminal, profile='build', input_sha256={'src': 'hash'},
                     built_artifact_sha256={executable: 'binary'}, raw_log=str(build_log),
                     raw_log_sha256=bench.guard.sha(build_log))
        build_path = root / 'build.json'
        build_path.write_text(json.dumps(build))
        environment = {
            'LATTICA_PROVING_POLICY': 'gpu-required', 'RAYON_NUM_THREADS': '8', 'CARGO_BUILD_JOBS': '2',
            'LATTICA_RINGCT_HOST_PROFILE': 'standard', 'LATTICA_V2_GPU_MANAGED_BYTES': str(8 << 30),
            'LATTICA_V2_GPU_CONTEXT_BYTES': str(4 << 30), 'LATTICA_V2_HOST_OUTPUT_BYTES': str(24 << 30),
            'LATTICA_V2_GPU_RETAINED_TREE_STORAGE': 'host', 'LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES': str(8 << 30),
            'LATTICA_V2_GPU_LDE_WORKSPACE_BYTES': '0', 'LATTICA_V2_GPU_PUBLIC_HASH': 'baseline',
            'LATTICA_GPU_DEVICE_UUID': 'GPU-test',
        }
        record = dict(plan, **terminal, schema='pq-opencl-optimization-correctness-job-v2',
                      profile='full', environment=environment, memory_max_bytes=47 << 30,
                      memory_high_bytes=45 << 30, fresh_memavailable_required_bytes=49 << 30,
                      cpu_quota='1600%', public_hash_kernel='baseline', identity_physical_cpus=list(range(16)), observed_identity_cpu_affinity=list(range(16)),
                      full_workflow_device=dict(name='NVIDIA GeForce RTX 5080', uuid='GPU-test',
                                                driver_version='test-driver', memory_total_mib=16303),
                      command=[executable, '--case', f'n{count}', '--layout', 'singleton',
                               '--seed', bytes(envelope['setup_seed']).hex(), '--context', bytes(envelope['context']).hex(), '--identity-cpu-workers', '1'],
                      input_sha256=build['input_sha256'], executable_provenance=dict(
                          sha256='binary', build_record=str(build_path), build_record_sha256=bench.guard.sha(build_path)),
                      raw_log=str(raw), raw_log_sha256=bench.guard.sha(raw), full_workflow_case_acceptance=acceptance,
                      started_utc='2026-10-24T00:00:00Z', finished_utc='2026-10-24T00:00:10Z',
                      wall_seconds=10, runtime_seconds=86400)
        path = root / 'record.json'
        path.write_text(json.dumps(record))
        return path, record, artifact_dir / artifact.name

    def test_replays_n3_n4_receipts_and_artifacts(self):
        for count in (3, 4):
            path, record, _ = self.make_record(count)
            result = bench.load_case(path)
            self.assertEqual(result['metrics']['case'], f'n{count}')
            self.assertEqual(result['metrics']['complete_workflow_ns'], record['full_workflow_case_acceptance']['report']['complete_workflow_ns'])
            self.assertFalse(result['metrics']['performance_qualified'])

    def test_cancelled_run_missing_device_and_changed_resources_refuse(self):
        path, record, _ = self.make_record()
        for key, value in [('status', 'failed_or_incomplete'), ('full_workflow_device', {}),
                           ('memory_max_bytes', 51 << 30), ('all_subprocesses_terminal_and_reaped', None)]:
            with self.subTest(key=key):
                bad = dict(record, **{key: value})
                path.write_text(json.dumps(bad))
                with self.assertRaises(ValueError):
                    bench.load_case(path)

    def test_changed_log_artifact_or_cached_acceptance_refuses(self):
        path, record, artifact = self.make_record()
        raw = Path(record['raw_log'])
        content = raw.read_text()
        raw.write_text(content + '\n')
        with self.assertRaisesRegex(ValueError, 'case log changed'):
            bench.load_case(path)
        raw.write_text(content)
        bad = copy.deepcopy(record)
        bad['full_workflow_case_acceptance']['report']['native_proofs'] += 1
        path.write_text(json.dumps(bad))
        with self.assertRaisesRegex(ValueError, 'stored case acceptance'):
            bench.load_case(path)
        path.write_text(json.dumps(record))
        packet = bytearray(artifact.read_bytes())
        packet[208] = 1
        artifact.write_bytes(packet)
        with self.assertRaisesRegex(ValueError, 'digest or EOF'):
            bench.load_case(path)

    def test_command_cannot_disagree_with_experiment_receipt(self):
        path, record, _ = self.make_record()
        record['command'] += ['--planning-cache', 'geometry-v1']
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, 'planning cache'):
            bench.load_case(path)

    def test_wide_preset_selectors_are_bound_and_other_widths_remain_outside_campaign(self):
        _, baseline, _ = self.make_record()
        for width in (2, 4, 8, 16):
            record = copy.deepcopy(baseline)
            record['command'][-1] = str(width)
            record[bench.case_guard.KEY]['identity_cpu'] = {'requested_workers': width, 'max_streams': width}
            self.assertEqual(bench.selection(record), dict(bench.BASELINE, identity_cpu_workers=width))
            record[bench.case_guard.KEY]['identity_cpu']['max_streams'] = 3
            with self.assertRaisesRegex(ValueError, 'CPU worker selection'):
                bench.selection(record)
        for width in (9, 17, 25):
            record['command'][-1] = str(width)
            record[bench.case_guard.KEY]['identity_cpu']['max_streams'] = width
            with self.assertRaisesRegex(ValueError, 'CPU worker selection'):
                bench.selection(record)

    def test_metadata_workers_cannot_confound_identity_comparisons(self):
        _, record, _ = self.make_record()
        record['command'] += ['--metadata-cpu-workers', '1']
        with self.assertRaisesRegex(ValueError, 'metadata workers'):
            bench.selection(record)
        record['command'][-1] = 'auto'
        record[bench.case_guard.KEY]['metadata_cpu'] = {'requested_workers': None, 'max_workers': 16}
        record['command'] += ['--planning-cache', 'off']
        self.assertEqual(bench.selection(record), bench.BASELINE)
        record[bench.case_guard.KEY]['metadata_cpu']['requested_workers'] = 1
        with self.assertRaisesRegex(ValueError, 'metadata workers'):
            bench.selection(record)

    def test_device_inventory_is_pinned_and_read_only(self):
        from types import SimpleNamespace
        uuid = 'GPU-00000000-0000-0000-0000-000000000000'
        response = SimpleNamespace(returncode=0, stdout=f'{uuid}, NVIDIA GeForce RTX 5080, 615.78.08, 16303\n', stderr='')
        with patch.object(bench.guard, 'command', return_value=response) as command:
            result = bench.guard.full_workflow_device_identity({'LATTICA_GPU_DEVICE_UUID': uuid})
            self.assertEqual(result['memory_total_mib'], 16303)
            self.assertIn('--id=' + uuid, command.call_args.args[0])
        response.stdout += response.stdout
        with patch.object(bench.guard, 'command', return_value=response):
            with self.assertRaises(ValueError):
                bench.guard.full_workflow_device_identity({'LATTICA_GPU_DEVICE_UUID': uuid})


if __name__ == '__main__':
    unittest.main()
