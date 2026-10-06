#!/usr/bin/env python3
"""Typed report semantics, with synthetic public metadata only."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from benchmark_report import typed
from benchmark_report.history import apply_metadata, classify, discover
from benchmark_report.measurements import collect, unpack
from benchmark_report.model import blank_run, digest, validate_run, transaction_rate


class TypedReport(unittest.TestCase):
    def add_seal_timestamps(self, record):
        base = datetime(2026, 10, 6, tzinfo=timezone.utc)
        wall_ns = int(base.timestamp()) * 10**9 + 123
        def stamp(seconds):
            return dict(monotonic_ns=10_000_000_000_000_123 + seconds * 10**9,
                        wall_time_ns=wall_ns + seconds * 10**9,
                        utc=(base + timedelta(seconds=seconds)).isoformat())
        record.update(repetition=3, pipeline_interval=dict(started_at=stamp(0), finished_at=stamp(30)),
                      seal_interval=dict(started_at=stamp(10), finished_at=stamp(11), seconds=1),
                      seal_start_to_controller_exit_seconds=20, seal_end_to_controller_exit_seconds=19)

    def test_native_pipeline_preserves_exact_seal_timestamps_in_browser_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run, record = self.pipeline_evidence(root, 'shared')
            self.add_seal_timestamps(record)
            (root/'pipeline-qualification.json').write_text(json.dumps(record))
            typed.native_pipeline(run, root, root)
            normalized = run['configuration']['native_pipeline']
            for interval in ['pipeline_interval', 'seal_interval']:
                for boundary in ['started_at', 'finished_at']:
                    for clock in ['monotonic_ns', 'wall_time_ns']:
                        self.assertEqual(normalized[interval][boundary][clock],
                                         str(record[interval][boundary][clock]))
            self.assertEqual(normalized['seal_start_to_controller_exit_seconds'], 20)
            self.assertIn('upper bound on host-ready time', run['limitations'][-1])
            self.assertNotIn('Repeated timing trials remain pending', run['limitations'][-1])

    def test_native_pipeline_rejects_incomplete_or_inconsistent_seal_boundaries(self):
        mutations = [
            lambda r: r.pop('seal_end_to_controller_exit_seconds'),
            lambda r: r.update(seal_start_to_controller_exit_seconds=19),
            lambda r: r['seal_interval'].update(seconds=float('nan')),
            lambda r: r['seal_interval']['finished_at'].update(monotonic_ns=0),
            lambda r: r['pipeline_interval']['started_at'].update(wall_time_ns=1.0),
            lambda r: r['pipeline_interval']['started_at'].update(wall_time_ns=True),
            lambda r: r['pipeline_interval']['started_at'].update(wall_time_ns='001'),
            lambda r: r['pipeline_interval']['started_at'].update(wall_time_ns=2**64),
            lambda r: r['pipeline_interval']['started_at'].update(utc='2026-10-06T00:00:00'),
            lambda r: r.update(repetition=True),
            lambda r: [r.pop(k) for k in ['pipeline_interval', 'seal_interval',
                                         'seal_start_to_controller_exit_seconds',
                                         'seal_end_to_controller_exit_seconds']],
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run, record = self.pipeline_evidence(root, 'shared')
                self.add_seal_timestamps(record)
                mutate(record)
                (root/'pipeline-qualification.json').write_text(json.dumps(record))
                with self.assertRaises(ValueError):
                    typed.native_pipeline(run, root, root)

    def pipeline_evidence(self, root, case):
        (root/'summary.json').write_text('{"status":"succeeded"}')
        source = typed.reference(root/'summary.json', root)
        staged = case == 'staged'
        fresh, reused = (5, 3) if staged else (8, 0)
        record = dict(status='passed', case=case, count=8, native_blocks_applied=1,
            duplicate_applications=0, matched_repetitions_completed=1, summary=source, sources=[source],
            proving_seconds=8, owner_seconds=10, controller_invocation_seconds=12,
            sealed_application_seconds=13, pipeline_seconds=30, prefix_invocation_seconds=10 if staged else 0,
            fresh_recursive_proofs=fresh, reused_recursive_proofs=reused)
        run = blank_run('pipeline', 'pipeline')
        run.update(status='succeeded', measurement_scope='typed_native_candidate_application')
        run['verification'].update(cpu_audited=True, native_applied=True, durable_intake_applied=True)
        run['timing'].update(elapsed_seconds=10, recursive_seconds=8)
        run['workload']['user_transactions'] = 6
        run['configuration']['recorded_fresh_proofs'] = fresh
        if staged:
            run['configuration']['preseal_reuse'] = dict(count=3)
        return run, record

    def cache_pipeline_evidence(self, root, mode='cache', phase='shared'):
        case = 'single-laptop' if phase in ('bootstrap', 'reduced-single') else 'shared'
        run, record = self.pipeline_evidence(root, case)
        self.add_seal_timestamps(record)
        record.update(qualification_mode=mode, context_phase=phase,
                      opening_denominator_cache=mode == 'cache',
                      performance_comparison=phase == 'matched',
                      matched_repetitions_completed=int(phase == 'matched'))
        if phase == 'matched':
            record['comparison_cycle'] = 2
        run['configuration']['shared_fleet'] = dict(workers=[
            dict(budget=dict(opening_denominator_cache=mode == 'cache',
                             gpu=dict(bootstrap=phase == 'bootstrap')))
            for _ in range(2 if case == 'shared' else 1)])
        return run, record

    def test_opening_cache_resource_qualification_is_not_a_matched_comparison(self):
        for mode in ('baseline', 'cache'):
            for phase in ('bootstrap', 'reduced-single', 'shared', 'matched'):
                with self.subTest(mode=mode, phase=phase), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    run, record = self.cache_pipeline_evidence(root, mode, phase)
                    (root/'pipeline-qualification.json').write_text(json.dumps(record))
                    typed.native_pipeline(run, root, root)
                    self.assertEqual(run['timing']['elapsed_seconds'], 30)
                    self.assertEqual(run['configuration']['native_pipeline']['performance_comparison'],
                                     phase == 'matched')
                    self.assertEqual('does not establish a matched performance comparison' in run['limitations'][-1],
                                     phase != 'matched')
                    if phase == 'matched':
                        self.assertIn('comparison cycle 2', run['limitations'][-1])

    def test_opening_cache_pipeline_rejects_inconsistent_mode_and_worker_evidence(self):
        mutations = [
            lambda r, p: p.pop('performance_comparison'),
            lambda r, p: p.update(performance_comparison=True),
            lambda r, p: p.update(performance_comparison=0),
            lambda r, p: p.update(qualification_mode='unknown'),
            lambda r, p: p.update(opening_denominator_cache=False),
            lambda r, p: p.update(opening_denominator_cache=1),
            lambda r, p: p.update(context_phase='bootstrap'),
            lambda r, p: p.update(matched_repetitions_completed=1),
            lambda r, p: p.update(comparison_cycle=1),
            lambda r, p: r['configuration']['shared_fleet']['workers'].pop(),
            lambda r, p: r['configuration']['shared_fleet']['workers'][0]['budget'].update(
                opening_denominator_cache=False),
            lambda r, p: r['configuration']['shared_fleet']['workers'][0]['budget']['gpu'].update(
                bootstrap=True),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run, record = self.cache_pipeline_evidence(root)
                mutate(run, record)
                (root/'pipeline-qualification.json').write_text(json.dumps(record))
                with self.assertRaises(ValueError):
                    typed.native_pipeline(run, root, root)

    def test_matched_opening_cache_pipeline_requires_a_valid_pair_cycle(self):
        for cycle in (None, 0, True, '2', 10000):
            with self.subTest(cycle=cycle), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run, record = self.cache_pipeline_evidence(root, phase='matched')
                if cycle is None:
                    record.pop('comparison_cycle')
                else:
                    record['comparison_cycle'] = cycle
                (root/'pipeline-qualification.json').write_text(json.dumps(record))
                with self.assertRaises(ValueError):
                    typed.native_pipeline(run, root, root)

    def test_opening_denominator_cache_counters_survive_measurement_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root/'worker.log'
            log.write_text('bounded_gpu_opening_denominator_cache_checkpoint '
                           'label="typed persistent GPU workspace" counters=cumulative '
                           'enabled=true calls=8 saved_upload_bytes=28991029248 '
                           'peak_bytes=201326592 skipped_groups=0\n')
            measurements, sources, warnings, _ = collect([log], root)
            self.assertEqual(warnings, [])
            self.assertEqual(sources, [typed.reference(log, root)])
            table, = measurements['tables']
            self.assertEqual(table['kind'], 'bounded_gpu_opening_denominator_cache_checkpoint')
            row, = unpack(table)
            self.assertEqual({key: row[key] for key in (
                'enabled', 'calls', 'saved_upload_bytes', 'peak_bytes', 'skipped_groups')},
                dict(enabled=True, calls=8, saved_upload_bytes=28991029248,
                     peak_bytes=201326592, skipped_groups=0))

    def test_native_pipeline_uses_full_interval_and_preserves_staged_work(self):
        for case in ('single-laptop', 'single-desktop', 'shared', 'staged'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run, record = self.pipeline_evidence(root, case)
                (root/'pipeline-qualification.json').write_text(json.dumps(record))
                typed.native_pipeline(run, root, root)
                self.assertEqual(run['timing']['elapsed_seconds'], 30)
                self.assertEqual(run['timing']['recursive_seconds'], 8)
                self.assertEqual(transaction_rate(run), 12)
                self.assertEqual(run['configuration']['native_pipeline'], record)

    def test_native_pipeline_rejects_incomplete_or_misleading_timing_and_reuse(self):
        for field, value in [('pipeline_seconds', 9), ('pipeline_seconds', float('nan')),
                             ('owner_seconds', 11), ('native_blocks_applied', 0),
                             ('duplicate_applications', 1), ('matched_repetitions_completed', 5),
                             ('reused_recursive_proofs', 0), ('prefix_invocation_seconds', 0),
                             ('summary', {}), ('sources', [])]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run, record = self.pipeline_evidence(root, 'staged')
                record[field] = value
                (root/'pipeline-qualification.json').write_text(json.dumps(record))
                with self.assertRaises(ValueError):
                    typed.native_pipeline(run, root, root)

    def supervision_evidence(self, root, case='all-workers'):
        count = 2 if case == 'all-workers' else 1
        attempts = [dict(number=i, directory=str(root),
                         action='succeeded' if i == count else 'recover')
                    for i in range(1, count+1)]
        result = dict(status='succeeded', record_type='typed_native_supervision',
                      attempts=attempts, retries=count-1, current_invocation_seconds=1)
        (root/'supervisor-result.json').write_text(json.dumps(result))
        (root/'invocation-exit.json').write_text(json.dumps(dict(returncode=0, seconds=30)))
        source = typed.reference(root/'supervisor-result.json', root)
        exit_source = typed.reference(root/'invocation-exit.json', root)
        run = blank_run('supervised', 'supervised')
        run.update(status='succeeded', measurement_scope='typed_native_candidate_application')
        run['verification'].update(cpu_audited=True, native_applied=True, durable_intake_applied=True)
        run['timing'].update(elapsed_seconds=10, recursive_seconds=8)
        run['workload']['user_transactions'] = 3
        if count == 2:
            run['configuration']['coordinator_recovery'] = dict(reused_proofs=1)
        record = dict(status='passed', case=case, native_blocks_applied=1,
            intake_application_events=1, duplicate_applications=0, accepted_proofs_preserved=1,
            controller_attempts=count, controller_retries=count-1,
            supervisor_invocations=1 if count == 2 else 2,
            automatic_recovery=count == 2, live_controller_adopted=count == 1,
            invocation_seconds=30, owner_seconds=10, proving_seconds=8,
            supervisor_result=source, invocation_exit=exit_source, sources=[source, exit_source])
        return run, record

    def test_supervision_uses_full_invocation_for_rate_and_retains_final_attempt_times(self):
        for case in ('all-workers', 'supervisor-crash'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run, record = self.supervision_evidence(root, case)
                (root/'supervision-qualification.json').write_text(json.dumps(record))
                typed.supervision(run, root, root)
                self.assertEqual(run['timing']['elapsed_seconds'], 30)
                self.assertEqual(run['timing']['recursive_seconds'], 8)
                self.assertEqual(run['configuration']['supervision']['owner_seconds'], 10)
                self.assertEqual(transaction_rate(run), 6)
                self.assertEqual(run['measurement_scope'], 'typed_native_supervised_candidate_application')

    def test_supervision_rejects_unpinned_inconsistent_or_incomplete_evidence(self):
        for defect in ('changed-source', 'missing-result-pin', 'wrong-final-directory',
                       'short-invocation', 'nonfinite-invocation', 'wrong-owner-time',
                       'wrong-retry-count', 'unaudited', 'duplicate-application',
                       'lost-proof', 'wrong-invocation-count', 'adoption-mismatch'):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run, record = self.supervision_evidence(root)
                if defect == 'changed-source':
                    (root/'invocation-exit.json').write_text('{}')
                elif defect == 'missing-result-pin':
                    record['sources'].remove(record['supervisor_result'])
                elif defect == 'wrong-final-directory':
                    result = json.loads((root/'supervisor-result.json').read_text())
                    result['attempts'][-1]['directory'] = str(root/'other')
                    (root/'supervisor-result.json').write_text(json.dumps(result))
                    record['supervisor_result'] = typed.reference(root/'supervisor-result.json', root)
                    record['sources'][0] = record['supervisor_result']
                elif defect in ('short-invocation', 'nonfinite-invocation'):
                    seconds = 5 if defect == 'short-invocation' else float('nan')
                    (root/'invocation-exit.json').write_text(json.dumps(dict(returncode=0, seconds=seconds)))
                    record['invocation_exit'] = typed.reference(root/'invocation-exit.json', root)
                    record['sources'][1] = record['invocation_exit']
                    record['invocation_seconds'] = seconds
                elif defect == 'wrong-owner-time':
                    record['owner_seconds'] = 9
                elif defect == 'wrong-retry-count':
                    record['controller_retries'] = 0
                elif defect == 'unaudited':
                    run['verification']['cpu_audited'] = False
                elif defect == 'duplicate-application':
                    record['duplicate_applications'] = 1
                elif defect == 'lost-proof':
                    run['configuration']['coordinator_recovery']['reused_proofs'] = 0
                elif defect == 'wrong-invocation-count':
                    record['supervisor_invocations'] = 2
                else:
                    record['live_controller_adopted'] = True
                (root/'supervision-qualification.json').write_text(json.dumps(record))
                with self.assertRaises(ValueError):
                    typed.supervision(run, root, root)

    def resource_fault_evidence(self, root, kind):
        source = root / 'observed.json'
        source.write_text('{"retained":true}\n')
        failure = ({'kind': kind, 'kernel_signal': 'SIGBUS',
                    'filesystem': {'exhausted': {'free_bytes': 0}}}
                   if kind == 'private_spill_capacity_exhaustion' else
                   {'kind': kind, 'opencl_error': 'CL_MEM_OBJECT_ALLOCATION_FAILURE',
                    'pressure': {'status': 'succeeded', 'selected_uuid': 'gpu-a',
                                 'allocated_bytes': 13 * 1024**3,
                                 'free_status': 0, 'destroy_status': 0}})
        record = dict(status='passed', failure=failure, target_gpu_uuid='gpu-a',
                      native_blocks_applied=1, intake_application_events=1,
                      duplicate_applications=0, accepted_proofs_preserved=1,
                      sources=[typed.reference(source, root)])
        run = blank_run('physical-fault', 'physical-fault')
        run['configuration']['worker_failover'] = {'terminations': [{'gpu_uuid': 'gpu-a'}]}
        run['verification'].update(cpu_audited=True, native_applied=True)
        return run, record

    def test_physical_resource_fault_retains_kind_and_pinned_observations(self):
        for kind in ('private_spill_capacity_exhaustion', 'gpu_vram_exhaustion'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run, record = self.resource_fault_evidence(root, kind)
                (root/'fault-qualification.json').write_text(json.dumps(record))
                typed.resource_exhaustion(run, root, root)
                self.assertEqual(run['configuration']['resource_exhaustion'], record)
                self.assertEqual(len(run['sources']), 2)
                self.assertEqual(run['stages'][-1]['status'], 'passed')

    def test_physical_resource_fault_rejects_wrong_device_cause_cleanup_and_source(self):
        for defect in ('wrong-device', 'host-allocation', 'unreleased', 'changed-source',
                       'duplicate', 'no-failover', 'spill-not-full', 'wrong-signal'):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                kind = 'private_spill_capacity_exhaustion' if defect in ('spill-not-full', 'wrong-signal') else 'gpu_vram_exhaustion'
                run, record = self.resource_fault_evidence(root, kind)
                if defect == 'wrong-device':
                    record['target_gpu_uuid'] = 'gpu-b'
                elif defect == 'host-allocation':
                    record['failure']['opencl_error'] = 'CL_OUT_OF_HOST_MEMORY'
                elif defect == 'unreleased':
                    record['failure']['pressure']['free_status'] = 1
                elif defect == 'changed-source':
                    (root/'observed.json').write_text('changed')
                elif defect == 'duplicate':
                    record['duplicate_applications'] = 1
                elif defect == 'no-failover':
                    run['configuration'].pop('worker_failover')
                elif defect == 'spill-not-full':
                    record['failure']['filesystem']['exhausted']['free_bytes'] = 1
                else:
                    record['failure']['kernel_signal'] = 'SIGKILL'
                (root/'fault-qualification.json').write_text(json.dumps(record))
                with self.assertRaises(ValueError):
                    typed.resource_exhaustion(run, root, root)

    def stale_evidence(self, root):
        binding = dict(head_token=[17]*32, generation=0)
        change = dict(expected_head_token='11'*32, observed_head_token='22'*32,
            expected_generation=0, observation_is_native_validation=False,
            observed_monotonic_ns=100, quiescent_monotonic_ns=200, owner_and_workers_quiescent=True)
        selection = dict(status='cancelled', application=None, selection_id='selection', native_host_binding=binding)
        controller = dict(schema=typed.SHARED_SCHEMA, status='failed', native_head_change=change,
            stale_selection=selection, arrival_selection='selection',
            fleet_plan=dict(native_host=binding, workers=[{'assignment': {'workload_kind': 'typed-paired-depth-six-bootstrap-v1'}}]))
        (root/'stale-head.json').write_text(json.dumps({k:v for k,v in change.items()
            if k not in ('quiescent_monotonic_ns','owner_and_workers_quiescent')}))
        (root/'stale-selection.json').write_text(json.dumps(selection))
        path = root/'summary.json'
        path.write_text(json.dumps(controller))
        return controller, path

    def test_stale_controller_without_owner_result_retains_failure_and_accepted_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); controller,path=self.stale_evidence(root)
            (root/'owner').mkdir()
            node=dict(event='fresh_typed_node',level=1,index=0,mode=4,count=2,bytes=8,seconds=3)
            (root/'owner/prove.log').write_text(json.dumps(node)+'\n')
            runs=list(discover(root,[root],[]))
            self.assertEqual(len(runs),1)
            run=runs[0]
            self.assertEqual(run['status'],'failed')
            self.assertEqual(run['configuration']['construction'],'paired')
            self.assertEqual(len(run['proofs']),1)
            self.assertTrue(run['configuration']['native_head_change']['cancellation_qualified'])
            self.assertIsNone(transaction_rate(run))
            self.assertIsNone(run['verification']['cpu_audited'])
            validate_run(run)
            (root/'owner/result.json').write_text('{}')
            self.assertIsNone(typed.classify(controller,path))

    def test_stale_report_rejects_applied_or_unconfirmed_cancellation(self):
        for fault in ('applied','indeterminate','live','token','selection','time'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root=Path(directory);controller,path=self.stale_evidence(root);data={}
                if fault=='applied': data['native_blocks_applied']=1
                elif fault=='indeterminate': data['native_application_status']='indeterminate'
                elif fault=='live': controller['native_head_change']['owner_and_workers_quiescent']=False
                elif fault=='token': controller['native_head_change']['observed_head_token']='11'*32
                elif fault=='selection': controller['stale_selection']['application']={}
                else: controller['native_head_change']['quiescent_monotonic_ns']=99
                with self.assertRaises(ValueError):
                    typed.stale_candidate(blank_run('stale','stale'),data,controller,root,root)

    def test_stale_cleanup_failure_remains_unqualified(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);controller,path=self.stale_evidence(root)
            controller.pop('stale_selection');controller['cleanup_failure']='retained failure'
            run=blank_run('stale','stale')
            typed.stale_candidate(run,{},controller,root,root)
            self.assertFalse(run['configuration']['native_head_change']['cancellation_qualified'])
            self.assertIsNone(transaction_rate(run))

    def recovery_fixture(self, root):
        old = root / 'interrupted/owner/proofs'
        current = root / 'resumed/owner/proofs'
        old.mkdir(parents=True)
        current.mkdir(parents=True)
        receipt = dict(source=str(old), durable_runtime=str(old / 'execution'),
                       previous_epoch=1, recovery_epoch=2,
                       previous_coordinator_pid=100, coordinator_pid=200,
                       old_coordinator_quiescent=True, old_workers_quiescent=True,
                       old_launches_revoked=True, old_workspace_reservations_released=True,
                       original_resource_assignments_preserved=True)
        node = dict(job='saved-subtree', level=1, index=0, bytes=8,
                    source=receipt['durable_runtime'], cpu_reverified=True,
                    recovered_from_journal=True)
        for folder, epoch, pid in [(old, 1, 100), (current, 2, 200)]:
            (folder / 'node.1.0').write_bytes(b'accepted')
            (folder / 'coordinator.json').write_text(json.dumps(
                dict(identity=dict(pid=pid), executable=[1] * 32)))
            (folder / 'recovery-state.json').write_text(json.dumps(
                dict(epoch=epoch, durable_runtime=receipt['durable_runtime'])))
            (folder / 'fleet-plan.json').write_text('{}')
        (current / 'coordinator-recovery.json').write_text(json.dumps(receipt))
        run = blank_run('recovery', 'typed-worker')
        run['verification']['native_applied'] = True
        data = dict(fresh_proofs=3, reused_proofs=1, coordinator_recovery=receipt,
                    execution_result=dict(coordinator_recovery=receipt,
                        coordinator_pid=200, recovery_epoch=2, reused_proofs=1,
                        reused_nodes=[node]))
        return run, data, current.parent / 'result.json'

    def test_coordinator_recovery_retains_journal_proof_and_source_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run, data, path = self.recovery_fixture(root)
            typed.preseal_evidence(run, data, {}, path, root)
            typed.coordinator_recovery(run, data, path, root)
            receipt = run['configuration']['coordinator_recovery']
            self.assertEqual(run['measurement_scope'],
                             'typed_native_candidate_application_after_coordinator_restart')
            self.assertEqual((receipt['reused_proofs'], receipt['fresh_proofs']), (1, 3))
            self.assertEqual(receipt['nodes'][0]['sha256'],
                             digest(path.parent / 'proofs/node.1.0'))
            self.assertNotIn('preseal_reuse', run['configuration'])
            self.assertEqual(len(run['sources']), 8)

    def test_coordinator_recovery_rejects_missing_native_application_or_reconciliation(self):
        for key in ['native_applied', 'old_coordinator_quiescent', 'old_workers_quiescent',
                    'old_launches_revoked', 'old_workspace_reservations_released',
                    'original_resource_assignments_preserved']:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run, data, path = self.recovery_fixture(root)
                if key == 'native_applied':
                    run['verification'][key] = False
                else:
                    data['coordinator_recovery'][key] = False
                with self.assertRaisesRegex(ValueError, 'complete reconciliation'):
                    typed.coordinator_recovery(run, data, path, root)

    def test_cached_continuation_is_cpu_recovery_without_proving_throughput(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run, data, path = self.recovery_fixture(root)
            run.update(status='succeeded', measurement_scope='typed_native_candidate_application')
            run['verification']['cpu_audited'] = True
            run['workload']['user_transactions'] = 3
            run['timing'].update(elapsed_seconds=9.0, recursive_seconds=2.0)
            self.assertEqual(transaction_rate(run), 20.0)
            data.update(cached_native_continuation=True, fresh_proofs=0, proving_seconds=2.0)
            data['execution_result'].update(cached_native_continuation=True, fresh_proofs=0,
                gpu_workers_started=0, workers=[], maximum_active_jobs=0, backend='cpu')
            typed.coordinator_recovery(run, data, path, root)
            self.assertEqual(run['track'], 'linux-cpu')
            self.assertEqual(run['measurement_scope'],
                'typed_native_cached_root_application_after_coordinator_restart')
            self.assertIsNone(run['timing']['recursive_seconds'])
            self.assertIsNone(transaction_rate(run))
            self.assertEqual(run['configuration']['coordinator_recovery']['recovery_seconds'], 2.0)
            self.assertEqual(run['configuration']['coordinator_recovery']['fresh_proofs'], 0)

    def test_cached_continuation_rejects_gpu_work_in_reported_receipt(self):
        for key, value in [('cached_native_continuation', False),
                           ('gpu_workers_started', 1), ('workers', [{'worker_pid': 99}]),
                           ('fresh_proofs', 1), ('maximum_active_jobs', 1), ('backend', 'gpu')]:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run, data, path = self.recovery_fixture(root)
                data.update(cached_native_continuation=True, fresh_proofs=0)
                data['execution_result'].update(cached_native_continuation=True, fresh_proofs=0,
                    gpu_workers_started=0, workers=[], maximum_active_jobs=0, backend='cpu')
                data['execution_result'][key] = value
                with self.assertRaisesRegex(ValueError, 'cached native continuation'):
                    typed.coordinator_recovery(run, data, path, root)

    def unexported_recovery_fixture(self, root):
        run, data, path = self.recovery_fixture(root)
        previous = Path(data['coordinator_recovery']['source'])
        (previous / 'node.1.0').unlink()
        (previous / 'node.1.0').mkdir()
        runtime = Path(data['coordinator_recovery']['durable_runtime'])
        (runtime / 'artifacts').mkdir(parents=True)
        (runtime / 'journal').mkdir()
        (runtime / 'journal/state').write_bytes(b'retained journal')
        artifact = runtime / 'artifacts' / ('n-' + 'a' * 64 + '.proof')
        artifact.write_bytes(b'accepted')
        data.update(cached_native_continuation=True, fresh_proofs=0, proving_seconds=2.0)
        data['execution_result'].update(cached_native_continuation=True, fresh_proofs=0,
            gpu_workers_started=0, workers=[], maximum_active_jobs=0, backend='cpu')
        return run, data, path, artifact

    def test_cached_export_recovery_pins_original_artifact_and_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run, data, path, artifact = self.unexported_recovery_fixture(root)
            typed.coordinator_recovery(run, data, path, root)
            receipt = run['configuration']['coordinator_recovery']
            self.assertEqual(receipt['recovered_unexported_proofs'], 1)
            self.assertEqual(receipt['nodes'][0]['source'], str(artifact.relative_to(root)))
            self.assertEqual(receipt['nodes'][0]['sha256'], digest(artifact))
            self.assertTrue(receipt['nodes'][0]['previous_export_missing'])
            self.assertEqual(run['measurement_scope'],
                'typed_native_cached_root_export_recovery_after_coordinator_restart')
            self.assertIsNone(transaction_rate(run))
            self.assertTrue(any(p['path'].endswith('journal/state') for p in run['sources']))

    def test_cached_export_recovery_rejects_missing_changed_or_ambiguous_artifact(self):
        for change in ('missing', 'changed', 'duplicate', 'journal', 'symlink', 'size'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run, data, path, artifact = self.unexported_recovery_fixture(root)
                if change == 'missing':
                    artifact.unlink()
                elif change == 'changed':
                    artifact.write_bytes(b'modified')
                elif change == 'duplicate':
                    artifact.with_name('n-' + 'b' * 64 + '.proof').write_bytes(b'accepted')
                elif change == 'journal':
                    (artifact.parent.parent / 'journal/state').unlink()
                elif change == 'symlink':
                    artifact.unlink()
                    artifact.symlink_to(path.parent / 'proofs/node.1.0')
                else:
                    data['execution_result']['reused_nodes'][0]['bytes'] = 7
                with self.assertRaisesRegex(ValueError, 'retained|unexported'):
                    typed.coordinator_recovery(run, data, path, root)

    def test_changed_prior_export_cannot_fall_back_to_matching_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run, data, path, artifact = self.unexported_recovery_fixture(root)
            previous = Path(data['coordinator_recovery']['source']) / 'node.1.0'
            previous.rmdir()
            previous.write_bytes(b'modified')
            with self.assertRaisesRegex(ValueError, 'retained accepted proof'):
                typed.coordinator_recovery(run, data, path, root)

    def test_coordinator_recovery_rejects_changed_proof_or_journal_origin(self):
        for change in ['bytes', 'origin', 'cpu_reverified', 'recovered_from_journal']:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run, data, path = self.recovery_fixture(root)
                if change == 'bytes':
                    (path.parent / 'proofs/node.1.0').write_bytes(b'changed')
                else:
                    node = data['execution_result']['reused_nodes'][0]
                    node['source' if change == 'origin' else change] = (
                        '/another/journal' if change == 'origin' else False)
                with self.assertRaisesRegex(ValueError, 'retained accepted proof'):
                    typed.coordinator_recovery(run, data, path, root)

    def test_coordinator_recovery_rejects_changed_identity_epoch_or_receipt(self):
        for name, field, value in [('coordinator.json', 'executable', [2] * 32),
                ('coordinator.json', 'identity', {'pid': 100}),
                ('recovery-state.json', 'epoch', 3),
                ('recovery-state.json', 'durable_runtime', '/another/journal'),
                ('coordinator-recovery.json', 'previous_epoch', 0)]:
            with self.subTest(name=name, field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run, data, path = self.recovery_fixture(root)
                source = path.parent / 'proofs' / name
                record = json.loads(source.read_text())
                record[field] = value
                source.write_text(json.dumps(record))
                with self.assertRaisesRegex(ValueError, 'identity or journal origin'):
                    typed.coordinator_recovery(run, data, path, root)

    def test_native_prefix_construction_retains_all_paired_node_modes(self):
        run = blank_run('prefix-modes', 'prefix')
        typed.metadata(run, {'construction': 'typed-paired-v1', 'preseal_only': True}, 'typed-worker')
        self.assertEqual(run['configuration']['construction'], 'paired')
        self.assertEqual(run['configuration']['registry_keys'], 12)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / 'prove.log'
            log.write_text(json.dumps({'event': 'fresh_typed_node', 'level': 1, 'index': 1,
                'mode': 8, 'count': 2, 'bytes': 1683948, 'seconds': 1.0,
                'cache_hits': 0, 'cache_setups': 1}) + '\n')
            _, _, warnings, proofs = collect([log], root, typed_construction=run['configuration']['construction'])
            self.assertEqual(warnings, [])
            self.assertEqual([p['artifact'] for p in proofs], ['node.1.1'])

    def test_failed_shared_owner_preserves_paired_events_without_root_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            owner = root / 'owner'
            owner.mkdir()
            data = dict(schema=typed.SHARED_SCHEMA, status='failed')
            controller = dict(schema=typed.SHARED_SCHEMA, status='failed',
                fleet_plan={'workers': [{'assignment': {'workload_kind':
                    'typed-paired-compact-depth-six-bootstrap-v1'}}]})
            (root / 'summary.json').write_text(json.dumps(controller))
            run = blank_run('failed-shared', 'typed-worker')
            typed.metadata(run, data, 'typed-worker')
            typed.enrich(run, data, owner / 'result.json', root)
            self.assertEqual(run['configuration']['construction'], 'paired')
            self.assertEqual(run['configuration']['registry_keys'], 12)
            log = owner / 'prove.log'
            log.write_text('\n'.join(json.dumps(dict(event='fresh_typed_node',
                level=level, index=index, mode=mode, count=count, bytes=1683948,
                seconds=1.0)) for level, index, mode, count in
                [(1, 1, 8, 2), (2, 0, 3, 4), (6, 0, 12, 4)]))
            _, _, warnings, proofs = collect([log], root,
                typed_construction=run['configuration']['construction'])
            self.assertEqual(warnings, [])
            self.assertEqual(len(proofs), 3)
            self.assertIsNone(run['verification']['cpu_audited'])
            self.assertIsNot(run['verification'].get('native_applied'), True)

    def test_preseal_audit_is_separate_from_root_and_native_application(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            owner = root / 'owner'
            proofs = owner / 'proofs'
            proofs.mkdir(parents=True)
            proof = proofs / 'node.1.0'
            proof.write_bytes(b'subtree')
            audit = {'status': 'passed', 'cpu_audited_roots': 0, 'nodes': [{'level': 1, 'index': 0}]}
            (owner / 'prefix-audit.json').write_text(json.dumps(audit))
            (proofs / 'result.json').write_text('{}')
            data = {'preseal_only': True, 'count': 2, 'fresh_proofs': 1, 'cpu_audited': False,
                    'cpu_prefix_audited': True, 'native_blocks_applied': 0, 'durable_host_applied': False,
                    'execution_result': {'preseal_only': True, 'root_file': None}, 'prefix_audit': audit,
                    'artifacts': {'node.1.0': hashlib.sha256(proof.read_bytes()).hexdigest()}}
            controller = {'status': 'succeeded', 'prefix_independently_confirmed': True, 'cpu_audited_roots': 0}
            run = blank_run('prefix-test', 'prefix')
            typed.preseal_evidence(run, data, controller, owner / 'result.json', root)
            self.assertEqual(run['measurement_scope'], 'typed_native_preseal_subtrees')
            self.assertIsNone(run['verification']['cpu_audited'])
            self.assertTrue(run['verification']['cpu_prefix_audited'])
            self.assertIsNone(run['workload']['user_transactions'])
            failed = blank_run('unconfirmed-prefix', 'prefix')
            typed.preseal_evidence(failed, data, controller | {'status': 'failed'}, owner / 'result.json', root)
            self.assertEqual(failed['status'], 'failed')
            self.assertIsNone(failed['verification']['cpu_audited'])
            self.assertFalse(failed['configuration']['preseal_prefix']['controller_confirmed'])
            for changes in [{'cpu_audited': True}, {'native_blocks_applied': 1},
                            {'durable_host_applied': True}, {'cpu_prefix_audited': False}]:
                with self.assertRaises(ValueError):
                    typed.preseal_evidence(blank_run('bad-prefix', 'bad'), data | changes, controller, owner / 'result.json', root)
            proof.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'subtree changed'):
                typed.preseal_evidence(blank_run('bad-prefix', 'bad'), data, controller, owner / 'result.json', root)

    def test_preseal_reuse_counters_require_reverification(self):
        for data in [{'reused_proofs': True}, {'reused_proofs': 1},
                     {'reused_proofs': 1, 'execution_result': {'reused_proofs': 1, 'reused_nodes': [{'cpu_reverified': False}]}}]:
            with self.assertRaisesRegex(ValueError, 'reuse accounting'):
                typed.preseal_evidence(blank_run('bad-reuse', 'bad'), data, {}, Path('/unused'), Path('/'))

    def test_pending_preparation_is_bound_to_applied_manifest_and_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "manifest.json"
            manifest = {"record_type": "native_delivery_preparation",
                        "preparation_backend": "durable-pending-arrivals", "status": "succeeded",
                        "native_state_preflight_passed": True, "independently_cpu_verified_wallets": 2,
                        "fresh_leaf_proofs": 0, "reused_leaf_proofs": 2,
                        "request_ids": ["second", "first"], "parent_head_token": "22" * 32,
                        "host_configuration_sha256": "11" * 32, "elapsed_seconds": 1.25}

            def inputs(document):
                path.write_text(json.dumps(document))
                sha = digest(path)
                run = blank_run("pending-test", "typed-worker")
                run["verification"]["durable_intake_applied"] = True
                run["configuration"]["native_host_binding"] = {
                    "preparation_sha256": list(bytes.fromhex(sha)), "head_token": [34] * 32}
                data = {"count": 2, "arrival_application": {
                    "fixture": str(root), "manifest_sha256": sha,
                    "request_ids": ["second", "first"], "host_configuration_sha256": "11" * 32}}
                return run, data

            run, data = inputs(manifest)
            typed.pending_preparation(run, data, root)
            self.assertEqual(run["configuration"]["pending_preparation"], manifest)
            self.assertEqual(run["stages"][0]["wall_seconds"], 1.25)
            self.assertEqual(run["sources"][0]["sha256"], digest(path))
            for change in [{"request_ids": ["first", "second"]},
                           {"independently_cpu_verified_wallets": 1},
                           {"native_state_preflight_passed": False},
                           {"parent_head_token": "33" * 32},
                           {"elapsed_seconds": -1}]:
                run, data = inputs(manifest | change)
                with self.subTest(change=change), self.assertRaises(ValueError):
                    typed.pending_preparation(run, data, root)
            run, data = inputs(manifest)
            path.write_text(json.dumps(manifest | {"elapsed_seconds": 3.0}))
            with self.assertRaises(ValueError):
                typed.pending_preparation(run, data, root)

    def test_prepared_fixture_does_not_claim_pending_preparation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "manifest.json").write_text(json.dumps({"record_type": "native_delivery_preparation"}))
            run = blank_run("prepared-test", "typed-worker")
            run["verification"]["durable_intake_applied"] = True
            typed.pending_preparation(run, {"arrival_application": {"fixture": str(root)}}, root)
            self.assertNotIn("pending_preparation", run["configuration"])
            self.assertEqual(run["stages"], [])

    def test_durable_intake_requires_exact_selection_and_independent_confirmation(self):
        binding = {"preparation_sha256": [3] * 32}
        receipt = {"host_configuration_sha256": "11" * 32}
        document = {"schema": "lattica-native-arrivals-v1", "request_ids": ["first", "second"],
                    "native_host_binding": binding, "host_configuration_sha256": "11" * 32,
                    "fixture": "/retained", "manifest_sha256": "03" * 32}
        token = hashlib.sha256((json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()
        intake = {**document, "selection_id": token, "status": "applied", "application": receipt}
        data = {"durable_arrival_intake": True, "arrival_application": intake, "native_host_binding": binding,
                "native_application": receipt, "arrival_publication_status": "applied", "arrival_selection": token,
                "count": 2, "intake_publication_seconds": 0.25}
        controller = {"arrival_selection": token, "arrival_application_independently_confirmed": True}
        run = blank_run("intake-test", "test")
        run["verification"]["native_applied"] = True
        typed.native_intake(run, data, controller)
        self.assertTrue(run["verification"]["durable_intake_applied"])
        self.assertEqual(run["stages"][-1]["wall_seconds"], 0.25)
        for mutation in ({"selection_id": "55" * 32}, {"request_ids": ["second", "first"]},
                         {"status": "sealed"}, {"application": {}}):
            with self.assertRaises(ValueError):
                typed.native_intake(copy.deepcopy(run), data | {"arrival_application": intake | mutation}, controller)
        with self.assertRaises(ValueError):
            typed.native_intake(copy.deepcopy(run), data, controller | {"arrival_application_independently_confirmed": False})

    def test_native_application_requires_the_outer_controller_and_exact_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, data, path, _ = self.evidence(root)
            binding = {"head_token": [17] * 32, "complete_body_sha256": [3] * 32,
                       "generation": 0, "expected": {"count": 4, "block_height": 10}}
            receipt = {"record_type": "native_shared_candidate_application", "count": 4,
                "root_sha256": data["artifacts"]["node.6.0"], "generation": 1, "state": {"height": 10},
                "parent_head_token": "11" * 32, "complete_body_sha256": "03" * 32,
                "durability_confirmed": True, "native_verifier": {"kind": "native-root-replay-v1"}}
            data.update(schema=typed.SHARED_SCHEMA, construction="paired", execution_backend="typed-shared-process-dag",
                durable_host_applied=True, native_blocks_applied=1, native_application_status="applied",
                native_host_binding=binding, native_application=receipt, native_application_seconds=3.5,
                execution_result={"native_host_bound": True, "native_host": binding})
            summary = {"schema": typed.SHARED_SCHEMA, "status": "succeeded", "result": data,
                       "native_host_binding": binding}
            (root / "summary.json").write_text(json.dumps(summary))
            run = blank_run("native-test", "test")
            apply_metadata(run, data, "typed-worker")
            typed.enrich(run, data, path, root)
            self.assertEqual(run["measurement_scope"], "typed_native_candidate_application")
            self.assertTrue(run["verification"]["native_applied"])
            self.assertIn("native height 10", run["label"])
            self.assertEqual(run["stages"][-1]["wall_seconds"], 3.5)
            recovered_data = copy.deepcopy(data)
            recovered_data.update(native_application_recovered=True, fresh_native_blocks_applied=0,
                                  cached_native_continuation=True)
            recovered_data['execution_result']['cached_native_continuation'] = True
            recovered = blank_run('native-recovered', 'typed-worker')
            typed.native_application(recovered, recovered_data, summary)
            self.assertTrue(recovered['configuration']['native_application_recovered'])
            self.assertEqual(recovered['configuration']['fresh_native_blocks_applied'], 0)
            self.assertEqual(recovered['stages'][-1]['name'], 'Recover published native application receipt')
            for change in ({'fresh_native_blocks_applied': 1}, {'cached_native_continuation': False},
                           {'native_application_recovered': 'true'}, {'fresh_native_blocks_applied': False}):
                with self.assertRaises(ValueError):
                    typed.native_application(blank_run('invalid-recovered', 'typed-worker'),
                                             recovered_data | change, summary)
            self.assertFalse(any("durable host application and delivered" in item for item in run["limitations"]))
            for changed in ({"generation": True}, {"count": 8}, {"root_sha256": "9" * 64},
                            {"parent_head_token": "99" * 32}, {"durability_confirmed": False}):
                bad = data | {"native_application": receipt | changed}
                with self.assertRaises(ValueError):
                    typed.native_application(run, bad, summary)
            pending = blank_run("native-pending", "test")
            apply_metadata(pending, data, "typed-worker")
            typed.native_application(pending, data, summary | {"status": "failed"})
            self.assertEqual(pending["measurement_scope"], "typed_recursive_aggregation")
            self.assertIsNot(pending["verification"].get("native_applied"), True)

    def failover_evidence(self):
        run = blank_run('failover', 'synthetic metadata')
        run['verification']['native_applied'] = True
        failed = {'worker_failed': True, 'worker_pid': 102, 'gpu_uuid': 'GPU-b',
            'exit_code': None, 'forced_stop_confirmed': True, 'launch_revoked': True,
            'workspace_released': True, 'process_and_cgroup_quiescent': True,
            'gpu_teardown_confirmed': True, 'teardown_method': 'process_and_cgroup_exit',
            'failed_job': 'a' * 64, 'lease_key': 'b' * 64, 'reconciled_ms': 49034}
        data = {'allow_worker_failover': True, 'failed_workers': 1,
            'execution_result': {'allow_worker_failover': True, 'failed_workers': 1,
                'workers': [failed, {'worker_pid': 101, 'gpu_uuid': 'GPU-a'}]}}
        controller = {'workers': [{'gpu_uuid': 'GPU-b',
            'worker_failed': True, 'termination': copy.deepcopy(failed)}]}
        return run, data, controller

    def memory_failover_evidence(self):
        run, data, controller = self.failover_evidence()
        events = dict(low=0, high=0, max=19, oom=1, oom_kill=2, oom_group_kill=1)
        controller['workers'][0].update(
            memory_failure=dict(memory_events=events, oom_killed=True),
            accounting={'memory.events': ''.join(f'{key} {value}\n' for key, value in events.items()), 'memory.peak': '90'},
            budget={'host': {'worker_bytes': 100}})
        controller['parent_memory_event_deltas'] = dict(events)
        return run, data, controller

    def test_worker_oom_recovery_requires_matching_fleet_and_worker_counters(self):
        run, data, controller = self.memory_failover_evidence()
        typed.worker_failover(run, data, controller)
        observed = run['configuration']['worker_failover']['memory_failures']
        self.assertEqual(len(observed), 1)
        self.assertTrue(observed[0]['oom_killed'])
        self.assertEqual(observed[0]['memory_events']['oom_kill'], 2)
        self.assertFalse(run['configuration']['worker_failover']['worker_replacement_qualified'])
        self.assertNotIn('OOM recovery and sustained', ' '.join(run['limitations']))
        self.assertTrue(any(stage['name'] == 'Worker memory failure and survivor retry' for stage in run['stages']))

    def test_worker_memory_failure_rejects_missing_or_changed_accounting(self):
        for change in ('unclassified', 'oom_marker', 'counter', 'fleet_counter', 'counter_reset', 'duplicate', 'peak'):
            run, data, controller = self.memory_failover_evidence()
            worker = controller['workers'][0]
            if change == 'unclassified':
                worker['memory_failure'] = None
            elif change == 'oom_marker':
                worker['memory_failure']['oom_killed'] = False
            elif change == 'counter':
                worker['memory_failure']['memory_events']['max'] += 1
            elif change == 'fleet_counter':
                controller['parent_memory_event_deltas']['max'] += 1
            elif change == 'counter_reset':
                worker['accounting']['memory.events'] = worker['accounting']['memory.events'].replace('max 19', 'max -1')
            elif change == 'duplicate':
                worker['accounting']['memory.events'] += 'max 19\n'
            else:
                worker['accounting']['memory.peak'] = '101'
            with self.subTest(change=change), self.assertRaises(ValueError):
                typed.worker_failover(run, data, controller)

    def test_failover_retains_failed_worker_without_claiming_coordinator_recovery(self):
        run, data, controller = self.failover_evidence()
        typed.worker_failover(run, data, controller)
        self.assertEqual(run['measurement_scope'], 'typed_native_candidate_application_with_worker_failover')
        recovery = run['configuration']['worker_failover']
        self.assertEqual(recovery['terminations'], [controller['workers'][0]['termination']])
        self.assertFalse(recovery['coordinator_recovery_qualified'])
        self.assertFalse(recovery['worker_replacement_qualified'])
        self.assertIn('Failure and retry time are included', ' '.join(run['limitations']))

    def test_failover_rejects_unconfirmed_or_inconsistent_termination(self):
        for key, value in [('launch_revoked', False), ('workspace_released', False),
                ('process_and_cgroup_quiescent', False), ('exit_code', 0),
                ('lease_key', 'invalid'), ('reconciled_ms', -1)]:
            with self.subTest(key=key):
                run, data, controller = self.failover_evidence()
                data['execution_result']['workers'][0][key] = value
                with self.assertRaises(ValueError):
                    typed.worker_failover(run, data, controller)
        for mutation in ('count', 'controller', 'native', 'survivor'):
            with self.subTest(mutation=mutation):
                run, data, controller = self.failover_evidence()
                if mutation == 'count':
                    data['failed_workers'] = 2
                elif mutation == 'controller':
                    controller['workers'][0]['termination']['lease_key'] = 'c' * 64
                elif mutation == 'native':
                    run['verification']['native_applied'] = False
                else:
                    data['execution_result']['workers'].pop()
                with self.assertRaises(ValueError):
                    typed.worker_failover(run, data, controller)

    def test_shared_workers_belong_to_one_audited_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, data, path, _ = self.evidence(root)
            data.update(schema=typed.SHARED_SCHEMA, construction="paired",
                        execution_backend="typed-shared-process-dag",
                        execution_result={"shared_dag_owner": True, "workers": [
                            {"gpu_uuid": "GPU-a", "worker_pid": 101},
                            {"gpu_uuid": "GPU-b", "worker_pid": 102}]})
            path.write_text(json.dumps(data))
            summary = root / "summary.json"
            summary.write_text(json.dumps({"schema": typed.SHARED_SCHEMA, "status": "succeeded",
                "result": data, "cpu_audited_roots": 1, "shared_dag_owner": True,
                "workers": [{"gpu_uuid": "GPU-a"}, {"gpu_uuid": "GPU-b"}]}))
            logs = []
            for index in (1, 2):
                worker = root / "workers" / f"gpu-{index:02d}"
                worker.mkdir(parents=True)
                log = worker / "prove.log"
                log.write_text("Synthetic worker telemetry; no proof payload.\n")
                logs.append(log)
                (worker / "accounting.json").write_text(json.dumps({"memory.peak": str(index)}))
            runs = list(discover(root, inputs=[root]))
            self.assertEqual(len(runs), 1)
            run = runs[0]
            self.assertTrue(run["verification"]["cpu_audited"])
            self.assertIn("shared GPU DAG", run["label"])
            self.assertEqual(run["configuration"]["shared_fleet"]["cpu_audited_roots"], 1)
            self.assertEqual(len(run["configuration"]["execution_result"]["workers"]), 2)
            self.assertTrue(any("coordinator recovery" in text for text in run["limitations"]))
            sources = {item["path"] for item in run["sources"]}
            self.assertTrue(all(str(log.relative_to(root)) in sources for log in logs))
            self.assertIn("summary.json", sources)
            changed = json.loads(summary.read_text())
            changed["result"]["root_bytes"] = 999
            summary.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, "differs"):
                list(discover(root, inputs=[root]))

    def test_interrupted_monitor_is_visible_without_changing_worker_outcome(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run, data, path, _ = self.evidence(root)
            interruption = {"role": "benchmark_monitor", "prover_restarted": False,
                            "dag_coordinator_restarted": False, "telemetry_continuous": False}
            summary = path.parent.parent / "summary.json"
            summary.write_text(json.dumps({"schema": typed.GPU_SCHEMA,
                                           "controller_interruption": interruption}))
            apply_metadata(run, data, "typed-worker")
            typed.enrich(run, data, path, root)
            self.assertEqual(run["configuration"]["benchmark_monitor_interruption"], interruption)
            self.assertTrue(any("telemetry gap" in message for message in run["limitations"]))
            self.assertTrue(run["verification"]["cpu_audited"])
            self.assertTrue(any(s["sha256"] == digest(summary) for s in run["sources"]))

    def test_persistent_child_preserves_process_identity_and_recovery_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run, data, path, _ = self.evidence(root)
            data.update(construction="paired", execution_backend="typed-process-dag", execution_result={
                "execution_backend": "typed_process_dag_v1", "worker_pid": 101, "coordinator_pid": 100,
                "worker_process_exited": True, "arrival_backend_integrated": False})
            apply_metadata(run, data, "typed-worker")
            typed.enrich(run, data, path, root)
            self.assertEqual(run["configuration"]["execution_result"], data["execution_result"])
            self.assertIn("persistent GPU child", run["label"])
            self.assertTrue(any("active-worker recovery" in message for message in run["limitations"]))
            self.assertFalse(any("same process" in message for message in run["limitations"]))

    def test_typed_dag_preserves_execution_identity_cache_counters_and_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run, data, path, _ = self.evidence(root)
            data.update(construction="paired", registry_keys=12, fresh_proofs=4, proving_seconds=399.0,
                        execution_backend="typed-dag", execution_result={
                            "execution_backend": "typed_inline_dag_v1", "cache_hits": 1,
                            "cache_setups": 3, "workspace_released_after_gpu_teardown": True,
                            "arrival_backend_integrated": False, "durable_host_applied": False})
            apply_metadata(run, data, "typed-worker")
            typed.enrich(run, data, path, root)
            self.assertEqual(run["configuration"]["execution_backend"], "typed-dag")
            self.assertEqual(run["configuration"]["execution_result"], data["execution_result"])
            self.assertIn("typed DAG", run["label"])
            self.assertEqual(run["measurement_scope"], "typed_recursive_aggregation")
            self.assertEqual(run["timing"]["recursive_seconds"], 399.0)
            self.assertTrue(any("same process" in message for message in run["limitations"]))
            run["proofs"] = [{"artifact": f"synthetic-{index}", "elapsed_seconds": 0, "resumed": False}
                             for index in range(4)]
            validate_run(run)

    def test_query_layout_is_visible_in_configuration_and_gather_label(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run, data, path, _ = self.evidence(root)
            self.assertEqual(run["configuration"]["query_readback_layout"], "rows")
            data.update(construction="paired", registry_keys=12, fresh_proofs=4)
            data["budget"]["query_readback_layout"] = "gather"
            apply_metadata(run, data, "typed-worker")
            typed.enrich(run, data, path, root)
            self.assertEqual(run["configuration"]["query_readback_layout"], "gather")
            self.assertIn("paired", run["label"])
            self.assertIn("gathered queries", run["label"])

    def test_compact_failure_retains_model_and_does_not_claim_transactions(self):
        for construction, marker in (
                ("reference", "typed-compact-depth-six-bootstrap-v1"),
                ("finalizer", "typed-finalizer-compact-depth-six-bootstrap-v1"),
                ("paired", "typed-paired-compact-depth-six-bootstrap-v1")):
            with self.subTest(construction=construction), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                attempt = root / "001-typed"
                attempt.mkdir()
                path = attempt / "attempt.json"
                data = {"config": {"construction": construction, "ram_admission": "compact",
                                   "workload": {"name": marker}}, "budget": {}}
                path.write_text(json.dumps(data))
                (root / "summary.json").write_text(json.dumps({"schema": typed.GPU_SCHEMA,
                    "status": "failed", "failure": "memory event after compact admission"}))
                self.assertEqual(classify(data, path), "typed-attempt")
                run = blank_run("compact-failure", "test")
                apply_metadata(run, data, classify(data, path))
                typed.enrich(run, data, path, root)
                self.assertEqual(run["configuration"]["ram_admission"], "compact")
                self.assertEqual(run["configuration"]["construction"], construction)
                self.assertEqual(run["status"], "failed")
                self.assertIsNone(run["workload"]["user_transactions"])
                self.assertFalse(run["verification"]["cpu_audited"])
                self.assertIn("memory event after compact admission", run["limitations"])

    def test_finalizer_identity_survives_root_enrichment_and_failed_attempts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); _, data, path, _ = self.evidence(root)
            data.update(construction="finalizer", registry_keys=6, fresh_proofs=8)
            run = blank_run("finalizer-test", "test")
            run["proofs"] = [{"artifact": f"synthetic-{index}", "elapsed_seconds": 0, "resumed": False}
                             for index in range(8)]
            apply_metadata(run, data, classify(data, path))
            typed.enrich(run, data, path, root)
            self.assertIn("finalizer", run["label"])
            self.assertEqual(run["configuration"]["registry_keys"], 6)
            self.assertEqual(run["workload"]["user_transactions"], 3)
            validate_run(run)
            attempt = {"config": {"construction": "finalizer", "workload": {"name": "typed-finalizer-depth-six-bootstrap-v1"}}}
            self.assertEqual(classify(attempt, Path("attempt.json")), "typed-attempt")
            apply_metadata(run, attempt, "typed-attempt")
            self.assertEqual(run["configuration"]["construction"], "finalizer")

    def evidence(self, root):
        attempt = root / "attempt"; attempt.mkdir()
        audit = attempt / "root-only"; audit.mkdir()
        body = audit / "body.json"
        body.write_text(json.dumps({"transactions": [{"kind": kind} for kind in
            ["joinsplit", "htlc_redeem", "htlc_refund", "issuance", "issuance"]]}))
        data = {"schema": typed.GPU_SCHEMA, "status": "succeeded", "count": 4,
                "cpu_audited": True, "elapsed_seconds": 400, "root_bytes": 1234,
                "artifacts": {"node.6.0": "1" * 64, "body.json": digest(body)},
                "budget": {"cpu": {"rayon_threads": 4}, "gpu": {"uuid": "GPU-test"}, "host": {}}}
        path = attempt / "result.json"; path.write_text(json.dumps(data))
        run = blank_run("typed-test", "test")
        apply_metadata(run, data, classify(data, path))
        typed.enrich(run, data, path, root)
        return run, data, path, body

    def test_typed_root_counts_only_audited_prefix_and_excludes_issuance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); run, data, path, body = self.evidence(root)
            self.assertEqual(run["adapter"], "typed-worker")
            self.assertEqual(run["workload"]["user_transactions"], 3)
            self.assertEqual(run["workload"]["issuance_transactions"], 1)
            self.assertEqual(run["verification"]["root_sha256"], "1" * 64)
            self.assertEqual(run["measurement_scope"], "typed_recursive_aggregation")
            self.assertIn("durable host", " ".join(run["limitations"]))
            validate_run(run)

    def test_missing_changed_and_unaudited_body_cannot_create_transaction_count(self):
        for change in ("missing", "changed", "audit", "kind", "count"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); _, data, path, body = self.evidence(root)
                if change == "missing": body.unlink()
                elif change == "changed": body.write_text("changed")
                elif change == "audit": data["cpu_audited"] = False
                elif change == "kind":
                    body.write_text(json.dumps({"transactions": [{"kind": "unknown"}] * 4}))
                    data["artifacts"]["body.json"] = digest(body)
                else: data["count"] = True
                run = blank_run("typed-test", "test")
                apply_metadata(run, data, classify(data, path))
                typed.enrich(run, data, path, root)
                self.assertIsNone(run["workload"]["user_transactions"])

    def test_cpu_registration_never_counts_as_a_root_audit(self):
        data = {"schema": typed.CPU_SCHEMA, "status": "succeeded", "elapsed_seconds": 280,
                "stages": [{"name": "register-1", "elapsed_seconds": 42}]}
        run = blank_run("typed-prep", "test")
        apply_metadata(run, data, classify(data, Path("worker-result.json")))
        self.assertEqual(run["kind"], "diagnostic")
        self.assertIsNone(run["verification"]["cpu_audited"])
        self.assertIsNone(run["workload"]["user_transactions"])
        self.assertEqual(run["stages"][0]["wall_seconds"], 42)
        validate_run(run)

    def test_failed_typed_attempt_keeps_controller_failure_and_unknown_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); attempt = root / "attempt"; attempt.mkdir()
            path = attempt / "attempt.json"
            data = {"config": {"workload": {"name": "typed-depth-six-bootstrap-v1"}}, "budget": {}}
            path.write_text(json.dumps(data))
            (root / "summary.json").write_text(json.dumps({"schema": typed.GPU_SCHEMA,
                "status": "failed", "failure": "resource admission failed"}))
            run = blank_run("typed-failure", "test")
            apply_metadata(run, data, classify(data, path))
            typed.enrich(run, data, path, root)
            self.assertEqual(run["status"], "failed")
            self.assertIsNone(run["workload"]["user_transactions"])
            self.assertIn("resource admission failed", run["limitations"])

    def test_paired_node_timings_cover_all_four_proofs_and_are_registry_scoped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); log = root / "prove.log"
            nodes = [{"event": "fresh_typed_node", "level": level, "index": index,
                      "mode": mode, "count": count, "bytes": 1234, "seconds": 2.5}
                     for level, index, mode, count in ((1, 0, 4, 2), (1, 1, 8, 2), (2, 0, 3, 4), (6, 0, 12, 4))]
            log.write_text("\n".join(json.dumps(n) for n in nodes) + "\n")
            measurements, _, warnings, proofs = collect([log], root, typed_construction="paired")
            self.assertEqual(warnings, [])
            self.assertEqual(len(proofs), 4)
            self.assertEqual({p["artifact"] for p in proofs}, {"node.1.0", "node.1.1", "node.2.0", "node.6.0"})
            run = blank_run("paired-test", "test")
            run.update(adapter="typed-worker", status="succeeded", proofs=proofs, measurements=measurements)
            run["configuration"] = {"construction": "paired", "registry_keys": 12, "recorded_fresh_proofs": 4}
            validate_run(run)
            run["proofs"] = proofs[:2]
            with self.assertRaisesRegex(ValueError, "fresh proof timings"):
                validate_run(run)
            pair = dict(nodes[0], mode=6)
            log.write_text(json.dumps(pair) + "\n")
            self.assertEqual(len(collect([log], root, typed_construction="paired")[3]), 1)
            self.assertEqual(collect([log], root, typed_construction="finalizer")[3], [])
            for malformed in (dict(pair, level=0), dict(pair, index=32), dict(pair, count=3),
                              dict(nodes[-1], level=5), dict(nodes[-1], count=33)):
                log.write_text(json.dumps(malformed) + "\n")
                _, _, warnings, proofs = collect([log], root, typed_construction="paired")
                self.assertEqual(proofs, [])
                self.assertTrue(warnings)

    def test_shared_node_identity_survives_export_and_rejects_arbitrary_strings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "prove.log"
            node = {"event": "fresh_typed_node", "level": 6, "index": 0, "mode": 12,
                    "count": 8, "bytes": 1234, "seconds": 30.125,
                    "gpu_uuid": "GPU-9ccf62bc-bc19-a667-4803-d3bce901ee6b",
                    "worker_pid": 101, "accepted_ms": 32125}
            log.write_text(json.dumps(node) + "\n")
            _, _, warnings, proofs = collect([log], root, typed_construction="paired")
            self.assertEqual(warnings, [])
            self.assertEqual(proofs[0]["gpu_uuid"], node["gpu_uuid"])
            self.assertEqual(proofs[0]["worker_pid"], 101)
            self.assertEqual(proofs[0]["accepted_ms"], 32125)
            for changes in ({"gpu_uuid": "arbitrary-private-data"}, {"worker_pid": True},
                            {"accepted_ms": -1}):
                log.write_text(json.dumps(node | changes) + "\n")
                _, _, warnings, proofs = collect([log], root, typed_construction="paired")
                self.assertEqual(proofs, [])
                self.assertTrue(warnings)

    def test_public_node_json_preserves_timings_without_arbitrary_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); log = root / "prove.log"
            node = {"event": "fresh_typed_node", "level": 6, "index": 0, "mode": 3,
                    "count": 4, "bytes": 1234, "seconds": 30.125, "private_inputs": "must-not-import"}
            log.write_text(json.dumps(node) + "\n")
            measurements, _, warnings, proofs = collect([log], root)
            self.assertEqual(warnings, [])
            self.assertEqual(proofs[0]["artifact"], "node.6.0")
            self.assertEqual(proofs[0]["elapsed_seconds"], 30.125)
            self.assertNotIn("must-not-import", json.dumps(measurements))
            node["mode"] = 6
            log.write_text(json.dumps(node) + "\n")
            _, _, warnings, proofs = collect([log], root)
            self.assertEqual(warnings, [])
            self.assertEqual(proofs[0]["artifact"], "node.6.0")
            node["level"] = 5
            log.write_text(json.dumps(node) + "\n")
            _, _, warnings, proofs = collect([log], root)
            self.assertEqual(proofs, [])
            self.assertTrue(warnings)
            node["level"] = 6
            node["seconds"] = -1
            log.write_text(json.dumps(node) + "\n")
            _, _, warnings, proofs = collect([log], root)
            self.assertEqual(proofs, [])
            self.assertTrue(warnings)


    def test_typed_cache_and_cpu_overhead_counters_survive_public_log_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "prove.log"
            node = {"event": "fresh_typed_node", "level": 2, "index": 0, "mode": 3,
                    "count": 4, "bytes": 1234, "seconds": 30.125, "cache_setups": 0,
                    "cache_hits": 1, "input_verification_ms": 600, "proving_ms": 29000,
                    "serialization_ms": 100, "private_inputs": "must-not-import"}
            log.write_text(json.dumps(node) + "\n")
            measurements, _, warnings, proofs = collect([log], root, typed_construction="paired")
            self.assertEqual(warnings, [])
            self.assertEqual(proofs[0]["setups"], 0)
            self.assertEqual(proofs[0]["cache_hits"], 1)
            table = measurements["tables"][0]
            for field in ("input_verification_ms", "proving_ms", "serialization_ms"):
                self.assertIn(field, table["columns"])
            self.assertNotIn("must-not-import", json.dumps(measurements))
            for invalid in (-1, True, "1", 1.5, 2**63):
                log.write_text(json.dumps({**node, "cache_hits": invalid}) + "\n")
                _, _, warnings, proofs = collect([log], root, typed_construction="paired")
                self.assertEqual(proofs, [])
                self.assertTrue(warnings)


if __name__ == "__main__":
    unittest.main()
