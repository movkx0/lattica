#!/usr/bin/env python3
"""Admission tests for context measurements from complete shared-owner trials."""

import copy
import importlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

S = importlib.import_module('block-v2-typed-shared-gpu-run')
C = S.Calibration


class SharedCalibration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.gpu, self.cpu = self.root/'gpu', self.root/'cpu'
        self.gpu.write_bytes(b'synthetic GPU binary')
        self.cpu.write_bytes(b'synthetic CPU binary')
        self.workload = self.root/'block-v2-multi-gpu-direct-readback-workload.json'
        self.workload.write_bytes(Path(__file__).with_name(self.workload.name).read_bytes())
        self.profile = S.T.resource_profile(self.workload, 'paired', 'compact')
        self.plan = dict(construction='typed-paired-v1', count=8, registry_keys=12,
                         fresh_proofs=8, tasks=[
                             dict(mode=mode, count=count, file=name) for mode, count, name in [
                                 (4, 2, 'node.1.0'), (4, 2, 'node.1.2'),
                                 (8, 2, 'node.1.1'), (8, 2, 'node.1.3'),
                                 (3, 4, 'node.2.0'), (3, 4, 'node.2.1'),
                                 (3, 8, 'node.3.0'), (12, 8, 'node.6.0')]])
        self.assignment = dict(schema='lattica-typed-fleet-assignment-v1', limits_by_gpu={})
        self.sources = [self.make_trial('trial-a', 'GPU-a'), self.make_trial('trial-b', 'GPU-b')]

    def save(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def change(self, source, name, change):
        value = S.read(source/name)
        change(value)
        self.save(source/name, value)

    def result_change(self, source, change):
        self.change(source, 'owner/result.json', change)
        self.change(source, 'summary.json', lambda s: s.update(result=S.read(source/'owner/result.json')))

    def make_trial(self, name, uuid):
        source = self.root/name
        budget = dict(unit='worker-'+name, gpu=dict(uuid=uuid, managed_bytes=4096,
                      context_bytes=2048, total_bytes=6144, bootstrap=True),
                      cpu=dict(rayon_threads=2, quota_percent='200%'),
                      host=dict(worker_bytes=8192, spill_bytes=1024, coordinator_bytes=512),
                      detected_gpu=dict(nvidia=dict(driver='driver'), opencl=dict(driver='runtime')))
        worker = dict(gpu_uuid=uuid, unit=budget['unit'], budget=budget,
                      directory=str(source/'workers/gpu-01'))
        termination = dict(gpu_uuid=uuid, unit=budget['unit'], worker_pid=123, coordinator_pid=122,
                           exit_code=0, gpu_teardown_confirmed=True, workspace_released=True,
                           process_and_cgroup_quiescent=True, cache_setups=6, cache_hits=2)
        execution = dict(status='proved_cpu_audit_pending', root_file='node.6.0',
                         execution_backend='typed_shared_process_dag_v1', shared_dag_owner=True,
                         count=8, construction='typed-paired-v1', fresh_proofs=8,
                         cpu_verified_nodes=8, worker_processes_exited=True,
                         workspace_released_after_gpu_teardown=True, arrival_backend_integrated=False,
                         durable_host_applied=False, production_ready=False, workers=[termination],
                         coordinator_pid=122, maximum_active_jobs=1)
        self.save(source/'owner/root-only/node.6.0', {'synthetic': 'audited root'})
        artifacts = {'node.6.0': S.G.digest(source/'owner/root-only/node.6.0')}
        result = dict(status='succeeded', construction='paired', count=8, cpu_audited=True,
                      execution_backend='typed-shared-process-dag', fresh_proofs=8, reused_proofs=0,
                      failed_workers=0, preseal_only=False, binary_sha256=S.G.digest(self.gpu),
                      execution_result=execution, artifacts=artifacts)
        accounting = {'memory.events': 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0',
                      'memory.peak': '256'}
        measurement = dict(uuid=uuid, peak_context_bytes=200, samples=1)
        summary_worker = dict(gpu_uuid=uuid, budget=budget, worker_failed=False, fresh_proofs=8,
                              termination=termination, accounting=accounting,
                              context_measurement=measurement)
        summary = dict(schema='lattica-typed-shared-gpu-v1', count=8, status='succeeded', result=result,
                       workers=[summary_worker], owner_accounting=accounting,
                       parent_memory_event_deltas=dict(max=0, oom=0, oom_kill=0))
        config = dict(count=8, preseal_only=False, recover_from=None, reuse_preseal=[], workers=[worker],
                      gpu_binary=str(self.gpu), cpu_binary=str(self.cpu),
                      pins=dict(S.T.pin(p) for p in [self.gpu, self.cpu, self.workload]))
        for filename, value in [('config.json', config), ('summary.json', summary),
                                ('owner/result.json', result), ('proof-plan.json', self.plan),
                                ('fleet-plan.json', {'workers': [worker]}),
                                ('owner/accounting.json', accounting),
                                ('workers/gpu-01/accounting.json', accounting),
                                ('workers/gpu-01/budget.json', budget),
                                ('owner/proofs/execution/worker-0-start.json',
                                 dict(worker_pid=123, unit=budget['unit'], assignment=budget))]:
            self.save(source/filename, value)
        (source/'owner/audit.log').write_text('synthetic audit transcript\n')
        row = dict(uuid=uuid, pid=123, limit_bytes=6144, context_bytes=200,
                   process_bytes=1200, managed_live_bytes=1000)
        (source/'workers/gpu-01/prove.log').write_text('bounded_gpu_context '+json.dumps(row)+'\n')
        limits = C.normalized_limits(S, budget)
        limits['gpu'].update(context_bytes=512, total_bytes=4608, bootstrap=False)
        self.assignment['limits_by_gpu'][uuid] = limits
        return source

    def load(self, sources=None, **changes):
        kwargs = dict(shared=S, gpu_sha=S.G.digest(self.gpu), cpu_sha=S.G.digest(self.cpu),
                      profile=self.profile, count=8, assignment=self.assignment,
                      uuids=['GPU-a', 'GPU-b'], target_plan=self.plan)
        kwargs.update(changes)
        return C.load(self.sources if sources is None else sources, **kwargs)

    def test_complete_roots_supply_per_device_peaks_and_pins(self):
        calibrations, pins = self.load()
        self.assertEqual(set(calibrations), {'GPU-a', 'GPU-b'})
        self.assertEqual(calibrations['GPU-a']['peak_context_bytes'], 200)
        self.assertEqual(calibrations['GPU-a']['samples'], 1)
        self.assertIn(str(self.sources[0]/'owner/root-only/node.6.0'), pins)
        self.assertEqual(C.source_pins(self.sources, S), pins)
        S.T.check_pins(pins)

    def test_multiple_distinct_trials_use_peak_and_total_samples(self):
        another = self.make_trial('trial-a2', 'GPU-a')
        path = another/'workers/gpu-01/prove.log'
        row = json.loads(path.read_text().split(' ', 1)[1])
        row.update(context_bytes=300, process_bytes=1300)
        path.write_text('bounded_gpu_context '+json.dumps(row)+'\n')
        self.change(another, 'summary.json', lambda s: s['workers'][0]['context_measurement'].update(
            peak_context_bytes=300))
        cal, _ = self.load(self.sources+[another])
        self.assertEqual(cal['GPU-a']['peak_context_bytes'], 300)
        self.assertEqual(cal['GPU-a']['samples'], 2)

    def test_prefix_requires_explicit_task_coverage(self):
        target = copy.deepcopy(self.plan)
        target.update(count=4, fresh_proofs=4, tasks=[self.plan['tasks'][i] for i in [0, 2, 4]])
        target['tasks'].append(dict(mode=12, count=4, file='node.6.0'))
        cal, _ = self.load(count=4, preseal=True, target_plan=target)
        self.assertTrue(cal['GPU-a']['preseal_only'])
        target['tasks'][0] = dict(mode=4, count=4, file='node.1.0')
        with self.assertRaises(ValueError):
            self.load(count=4, preseal=True, target_plan=target)

    def test_complete_target_cannot_use_different_source_count(self):
        target = dict(self.plan, count=4)
        with self.assertRaises(ValueError):
            self.load(count=4, target_plan=target)
        with self.assertRaisesRegex(ValueError, 'target plan count'):
            self.load(count=4)

    def test_incomplete_gpu_coverage_and_duplicate_trials_are_rejected(self):
        for sources in [[], self.sources[:1], self.sources+self.sources[:1]]:
            with self.subTest(sources=sources), self.assertRaises(ValueError):
                self.load(sources)

    def test_target_requires_exact_assignment_and_all_devices(self):
        for assignment in [None, {}, dict(self.assignment, limits_by_gpu={})]:
            with self.subTest(assignment=assignment), self.assertRaises(ValueError):
                self.load(assignment=assignment)
        with self.assertRaises(ValueError):
            self.load(uuids=['GPU-a', 'GPU-a'])

    def test_resources_and_drivers_cannot_change(self):
        for section, field, value in [('gpu', 'managed_bytes', 5000), ('gpu', 'uuid', 'GPU-c'),
                                      ('gpu', 'bootstrap', True), ('cpu', 'rayon_threads', 3),
                                      ('cpu', 'quota_percent', '300%'), ('host', 'worker_bytes', 9000),
                                      ('host', 'spill_bytes', 2048), ('drivers', 'nvidia', 'new')]:
            assignment = copy.deepcopy(self.assignment)
            assignment['limits_by_gpu']['GPU-a'][section][field] = value
            with self.subTest(section=section, field=field), self.assertRaises(ValueError):
                self.load(assignment=assignment)

    def test_binary_and_profile_must_match(self):
        for changes in [dict(gpu_sha='wrong'), dict(cpu_sha='wrong'),
                        dict(profile=dict(self.profile, name='different workload'))]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.load(**changes)

    def test_equivalent_duplicate_workload_pins_are_accepted(self):
        duplicate = self.root/'previous-runtime'/self.workload.name
        duplicate.parent.mkdir()
        duplicate.write_bytes(self.workload.read_bytes())
        self.change(self.sources[0], 'config.json', lambda c: c['pins'].update(dict([S.T.pin(duplicate)])))
        calibrations, pins = self.load()
        self.assertEqual(calibrations['GPU-a']['samples'], 1)
        self.assertIn(str(duplicate), pins)

    def test_explicit_workload_disambiguates_retained_calibration_inputs(self):
        duplicate = self.root/'previous-runtime'/self.workload.name
        profile = S.read(self.workload)
        profile['geometry']['opening_denominator_cache'] = True
        self.save(duplicate, profile)
        self.change(self.sources[0], 'config.json', lambda c: c['pins'].update(dict([S.T.pin(duplicate)])))
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            self.load()
        self.change(self.sources[0], 'config.json', lambda c: c.update(
            workload_path=str(self.workload), workload_profile=self.profile))
        self.load()
        self.change(self.sources[0], 'config.json', lambda c: c.update(workload_profile={}))
        with self.assertRaisesRegex(ValueError, 'recorded workload differs'):
            self.load()

    def test_workload_path_and_worker_options_must_be_pinned_consistently(self):
        config = S.read(self.sources[0]/'config.json')
        with self.assertRaisesRegex(ValueError, 'not pinned'):
            C.source_profile(dict(config, workload_path='/unrelated/workload.json'), S)
        self.change(self.sources[0], 'config.json', lambda c: c['workers'][0]['budget'].update(
            opening_denominator_cache=True))
        with self.assertRaisesRegex(ValueError, 'worker options differ'):
            self.load()

    def test_partial_reused_failed_and_unaudited_sources_are_rejected(self):
        for key, value in [('status', 'failed'), ('cpu_audited', False), ('fresh_proofs', 7),
                           ('reused_proofs', 1), ('failed_workers', 1), ('preseal_only', True),
                           ('count', 4), ('construction', 'reference')]:
            source = self.make_trial('invalid-'+key, 'GPU-a')
            self.result_change(source, lambda r: r.update({key: value}))
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.load([source, self.sources[1]])

    def test_recovery_prefix_multiple_worker_and_memory_event_sources_are_rejected(self):
        for key, value in [('recover_from', '/old'), ('preseal_only', True), ('reuse_preseal', ['/old'])]:
            source = self.make_trial('config-'+key, 'GPU-a')
            self.change(source, 'config.json', lambda c: c.update({key: value}))
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.load([source, self.sources[1]])
        source = self.sources[0]
        self.change(source, 'config.json', lambda c: c['workers'].append(c['workers'][0]))
        with self.assertRaises(ValueError):
            self.load()
        source = self.make_trial('memory-events', 'GPU-a')
        self.change(source, 'summary.json', lambda s: s['parent_memory_event_deltas'].update(oom=1))
        with self.assertRaises(ValueError):
            self.load([source, self.sources[1]])

    def test_bad_context_samples_are_rejected(self):
        path = self.sources[0]/'workers/gpu-01/prove.log'
        row = json.loads(path.read_text().split(' ', 1)[1])
        for key, value in [('uuid', 'GPU-c'), ('pid', 124), ('pid', 123.0), ('limit_bytes', 6144.0),
                           ('limit_bytes', 8000), ('context_bytes', -1), ('context_bytes', True),
                           ('context_bytes', 200.0), ('context_bytes', 201),
                           ('process_bytes', -1), ('managed_live_bytes', 4097)]:
            path.write_text('bounded_gpu_context '+json.dumps(dict(row, **{key: value}))+'\n')
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.load()
        path.write_text('no measurements\n')
        with self.assertRaises(ValueError):
            self.load()

    def test_changed_root_or_pinned_input_is_rejected(self):
        (self.sources[0]/'owner/root-only/node.6.0').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'audited artifact changed'):
            self.load()
        self.cpu.write_bytes(b'changed CPU binary')
        with self.assertRaises(ValueError):
            C.source_pins(self.sources, S)

    def test_accounting_budget_and_launch_identity_must_agree(self):
        for name, field, value in [('workers/gpu-01/accounting.json', 'memory.peak', '257'),
                                   ('owner/accounting.json', 'memory.peak', '257'),
                                   ('workers/gpu-01/budget.json', 'unit', 'other'),
                                   ('owner/proofs/execution/worker-0-start.json', 'worker_pid', 124),
                                   ('owner/proofs/execution/worker-0-start.json', 'unit', 'other')]:
            source = self.make_trial('changed-'+field, 'GPU-a')
            self.change(source, name, lambda x: x.update({field: value}))
            with self.subTest(name=name, field=field), self.assertRaises(ValueError):
                self.load([source, self.sources[1]])

    def test_parent_pins_observations_before_launch(self):
        args = ['runner', '--gpu-binary', str(self.gpu), '--cpu-binary', str(self.cpu),
                '--fixture', str(self.root), '--evidence', str(self.root/'run'),
                '--calibration-trial', str(self.sources[0])]
        with mock.patch.object(sys, 'argv', args), mock.patch.object(S.T, 'fixture_files', return_value=[]), \
                mock.patch.object(S.Controller, 'launch') as launch:
            S.main()
        expected = C.source_pins([self.sources[0]], S)
        pins = launch.call_args.args[2]
        self.assertEqual({path: pins[path] for path in expected}, expected)


if __name__ == '__main__':
    unittest.main()
