#!/usr/bin/env python3
"""Controller receipt validation; synthetic data does not qualify proving."""
import copy
import importlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from unittest import mock

S = importlib.import_module("block-v2-typed-shared-gpu-run")


class SharedOwnerReceipts(unittest.TestCase):
    def test_recovery_rejects_changed_workload_options_before_admission(self):
        profile = {'geometry': {'opening_denominator_cache': True}}
        recovery = {'resource_assignment': {}, 'workload_profile': profile}
        with mock.patch.object(S.M, 'plan_budgets', return_value={}) as plan:
            S.admit_recovery({}, [], profile, recovery, Path('/unused'), 10)
            self.assertEqual(plan.call_count, 1)
            with self.assertRaisesRegex(ValueError, 'workload profile differs'):
                S.admit_recovery({}, [], {'geometry': {}}, recovery, Path('/unused'), 10)
            self.assertEqual(plan.call_count, 1)

    def test_fresh_shared_owner_passes_fixed_allocation_to_admission(self):
        fixed = {'schema': 'lattica-typed-fleet-assignment-v1', 'limits_by_gpu': {'GPU-a': {}}}
        with mock.patch.object(S.M, 'plan_budgets', return_value={'GPU-a': {}}) as plan:
            result = S.admit_recovery({}, [{'uuid': 'GPU-a'}], {}, None, Path('/unused'), 10, assignment=fixed)
        self.assertEqual(result[2], {'GPU-a': {}})
        self.assertEqual(plan.call_args.kwargs, {'assignment': fixed, 'calibrations': None})

    def test_fresh_admission_passes_context_calibrations(self):
        calibration = {'GPU-a': {'peak_context_bytes': 123}}
        with mock.patch.object(S.M, 'plan_budgets', return_value={}) as plan:
            S.admit_recovery({}, [], {}, None, Path('/unused'), 10, calibrations=calibration)
        self.assertEqual(plan.call_args.kwargs['calibrations'], calibration)

    def test_recovery_inherits_context_calibrations(self):
        calibration = {'GPU-a': {'peak_context_bytes': 123}}
        recovery = {'resource_assignment': {}, 'context_calibrations': calibration}
        with mock.patch.object(S.M, 'plan_budgets', return_value={}) as plan:
            S.admit_recovery({}, [], {}, recovery, Path('/unused'), 10)
        self.assertEqual(plan.call_args.kwargs['calibrations'], calibration)

    def test_recovery_rejects_changed_context_calibrations_before_admission(self):
        recovery = {'resource_assignment': {}, 'context_calibrations': {'GPU-a': {'samples': 3}}}
        with mock.patch.object(S.M, 'plan_budgets') as plan, self.assertRaisesRegex(
                ValueError, 'context calibration differs'):
            S.admit_recovery({}, [], {}, recovery, Path('/unused'), 10, calibrations={})
        plan.assert_not_called()

    def test_recovery_rejects_a_fixed_allocation_override_before_admission(self):
        with mock.patch.object(S.M, 'plan_budgets') as plan:
            with self.assertRaisesRegex(ValueError, 'original recovery limits'):
                S.admit_recovery({}, [], {}, {'resource_assignment': {'original': True}},
                                 Path('/unused'), 10, assignment={'changed': True})
        plan.assert_not_called()

    def test_stale_cleanup_checks_worker_services_without_owner_name_validation(self):
        owner = 'lattica-v2-multi-owner-' + 'a' * 64 + '.service'
        worker = 'lattica-v2-multi-persistent-' + 'b' * 64 + '.service'
        state = dict(LoadState='loaded', ActiveState='failed', SubState='failed',
                     MainPID=0, ControlPID=0, Job='', InvocationID='', ControlGroup='')
        with patch.object(S.Bootstrap, 'observation', return_value=state) as observe, \
             patch.object(S.G, 'systemctl', return_value='\n'.join(f'{k}={v}' for k, v in state.items())) as systemctl:
            S.quiescent_fleet(owner, [{'unit': worker}])
        observe.assert_called_once_with(owner)
        self.assertEqual(systemctl.call_args.args[:2], ('show', worker))

    def test_stale_cleanup_rejects_live_worker_or_wrong_service(self):
        owner = 'lattica-v2-multi-owner-' + 'a' * 64 + '.service'
        worker = 'lattica-v2-multi-persistent-' + 'b' * 64 + '.service'
        state = dict(ActiveState='failed', SubState='failed', MainPID=0, ControlPID=0,
                     Job='', InvocationID='', ControlGroup='')
        for changed in ({'MainPID': 42}, {'ControlPID': 42}, {'Job': '42'}, {'ActiveState': 'active'}):
            with self.subTest(changed=changed), \
                 patch.object(S.Bootstrap, 'observation', return_value=state), \
                 patch.object(S.G, 'systemctl', return_value='\n'.join(f'{k}={v}' for k, v in (state | changed).items())), \
                 self.assertRaises(ValueError):
                S.quiescent_fleet(owner, [{'unit': worker}])
        with patch.object(S.Bootstrap, 'observation', return_value=state), \
             patch.object(S.G, 'systemctl') as systemctl, self.assertRaises(ValueError):
            S.quiescent_fleet(owner, [{'unit': owner}])
        systemctl.assert_not_called()

    def test_fleet_memory_events_must_match_drained_failed_worker_accounting(self):
        before = dict(low=0, high=0, max=7, oom=1, oom_kill=2, oom_group_kill=1)
        events = dict(low=0, high=0, max=35, oom=1, oom_kill=2, oom_group_kill=1)
        termination = dict(worker_failed=True, exit_code=None, teardown_method='process_and_cgroup_exit',
                           forced_stop_confirmed=True, launch_revoked=True, workspace_released=True,
                           process_and_cgroup_quiescent=True, gpu_teardown_confirmed=True)
        worker = dict(accounting={'memory.events': ''.join(f'{key} {value}\n' for key, value in events.items()),
                                  'memory.peak': '90'}, budget={'host': {'worker_bytes': 100}}, termination=termination)
        worker['memory_failure'] = S.validate_worker_accounting(worker['accounting'], worker['budget'], termination, True)
        after = {key: before[key] + events[key] for key in before}
        self.assertEqual(S.fleet_event_deltas(before, after, [worker], True), events)
        for changed in [after | {'max': after['max']+1}, after | {'oom_kill': after['oom_kill']-1},
                        after | {'low': 1}, after | {'max': before['max']-1}, after | {'extra': 0}]:
            with self.subTest(after=changed), self.assertRaises(ValueError):
                S.fleet_event_deltas(before, changed, [worker], True)
        with self.assertRaises(ValueError):
            S.fleet_event_deltas(before, after, [worker], False)
        with self.assertRaises(ValueError):
            S.fleet_event_deltas(before, after, [worker | {'memory_failure': None}], True)

    def test_fleet_without_worker_memory_failure_still_requires_clean_deltas(self):
        counters = dict(low=0, high=0, max=35, oom=1, oom_kill=2, oom_group_kill=1)
        self.assertEqual(S.fleet_event_deltas(counters, counters, [], False), dict.fromkeys(counters, 0))
        with self.assertRaises(ValueError):
            S.fleet_event_deltas(counters, counters | {'max': 36}, [], True)

    def test_memory_events_require_an_admitted_drained_failed_worker(self):
        accounting = {'memory.events': 'low 0\nhigh 0\nmax 4\noom 1\noom_kill 1\noom_group_kill 1\n',
                      'memory.peak': '90'}
        budget = {'host': {'worker_bytes': 100}}
        worker = dict(worker_failed=True, exit_code=None, teardown_method='process_and_cgroup_exit',
                      forced_stop_confirmed=True, launch_revoked=True, workspace_released=True,
                      process_and_cgroup_quiescent=True, gpu_teardown_confirmed=True)
        observed = S.validate_worker_accounting(accounting, budget, worker, True)
        self.assertTrue(observed['oom_killed'])
        self.assertEqual(observed['memory_events']['max'], 4)
        for allowed in [False, 1, None]:
            with self.subTest(allowed=allowed), self.assertRaises(ValueError):
                S.validate_worker_accounting(accounting, budget, worker, allowed)
        for key in ['worker_failed', 'forced_stop_confirmed', 'launch_revoked',
                    'workspace_released', 'process_and_cgroup_quiescent', 'gpu_teardown_confirmed']:
            for value in [False, 1, None]:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    S.validate_worker_accounting(accounting, budget, worker | {key: value}, True)
        for change in [{'exit_code': 0}, {'teardown_method': 'socket_eof'}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                S.validate_worker_accounting(accounting, budget, worker | change, True)

    def test_healthy_worker_memory_events_still_fail_qualification(self):
        clean = 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n'
        budget = {'host': {'worker_bytes': 100}}
        worker = dict(worker_failed=False, exit_code=0)
        self.assertIsNone(S.validate_worker_accounting({'memory.events': clean, 'memory.peak': '90'},
                                                       budget, worker, True))
        for key in ['low', 'high', 'max', 'oom', 'oom_kill', 'oom_group_kill']:
            with self.subTest(key=key), self.assertRaises(ValueError):
                S.validate_worker_accounting({'memory.events': clean.replace(key + ' 0\n', key + ' 1\n'),
                                              'memory.peak': '90'}, budget, worker, True)

    def test_worker_memory_accounting_requires_complete_nonnegative_unique_counters(self):
        clean = 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n'
        for malformed in [clean + 'max 0\n', clean.replace('max 0\n', ''),
                          clean.replace('max 0', 'max -1'), clean + 'unexpected\n']:
            with self.subTest(events=malformed), self.assertRaises(ValueError):
                S.validate_worker_accounting({'memory.events': malformed, 'memory.peak': '90'},
                                             {'host': {'worker_bytes': 100}}, {}, False)

    def test_failover_does_not_allow_exceeding_original_memory_assignment(self):
        clean = 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n'
        for peak in ['0', '-1', '101']:
            with self.subTest(peak=peak), self.assertRaises(ValueError):
                S.validate_worker_accounting({'memory.events': clean, 'memory.peak': peak},
                                             {'host': {'worker_bytes': 100}}, {'worker_failed': True}, True)

    def test_worker_launch_origin_matches_fresh_or_recovered_coordinator_journal(self):
        owner = Path('/new/owner')
        existing = {'source': '/old/proofs', 'launch_directory': '/original/journal/launches',
                    'bootstrap_recovery': None}
        self.assertEqual(S.recovery_paths(owner, existing), ('/old/proofs', '/original/journal/launches'))
        fresh = (None, '/new/owner/proofs/execution/launches')
        self.assertEqual(S.recovery_paths(owner, None), fresh)
        unfinished = dict(existing, bootstrap_recovery={'abandoned_incomplete_new_candidate': True})
        self.assertEqual(S.recovery_paths(owner, unfinished), fresh)
        interrupted = dict(existing, bootstrap_recovery={'abandoned_incomplete_new_candidate': False,
                                                         'interrupted_existing_journal': True})
        self.assertEqual(S.recovery_paths(owner, interrupted), ('/old/proofs', '/original/journal/launches'))
        for recovery in [None, unfinished, existing, interrupted]:
            with self.subTest(recovery=recovery):
                config, fleet, report = {}, {'recover_from': None}, {}
                source, expected_launches = S.recovery_paths(owner, recovery)
                self.assertEqual(S.configure_recovery(owner, recovery, config, fleet, report), expected_launches)
                self.assertEqual(config.get('recover_from'), source)
                self.assertEqual(fleet['recover_from'], source)
                self.assertEqual(report.get('recovery_source'), source)
                if recovery and recovery['bootstrap_recovery']:
                    self.assertEqual(config['bootstrap_recovery'], recovery['bootstrap_recovery'])

    def test_incomplete_bootstrap_retains_assignment_without_requiring_rust_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owner = root / 'owner'
            owner.mkdir()
            gpu, cpu = root / 'gpu', root / 'cpu'
            gpu.write_bytes(b'synthetic image identity')
            cpu.write_bytes(b'synthetic CPU identity')
            binding = {'head_token': [7] * 32}
            assignment = {'gpu': {'uuid': 'GPU-a', 'available_bytes': 5, 'context_bytes': 3},
                          'cpu': {'rayon_threads': 2}, 'host': {'worker_bytes': 9, 'coordinator_job_bytes': 1},
                          'detected_gpu': {'nvidia': {'driver': 'same'}, 'opencl': {'driver': 'same'}}}
            gate = owner / 'coordinator-startup'
            plan = {'workers': [{'assignment': assignment}], 'recover_from': None,
                    'startup_fenced': True, 'coordinator_bootstrap_guard': str(gate)}
            plan_path = root / 'fleet-plan.json'
            plan_path.write_text(json.dumps(plan))
            config = {'owner_directory': str(owner), 'count': 4, 'native_host': binding,
                      'gpu_binary': str(gpu), 'cpu_binary': str(cpu), 'fleet_plan': str(plan_path),
                      'owner_unit': 'lattica-v2-multi-owner-' + 'a' * 64 + '.service',
                      'coordinator_bootstrap_guard': str(gate),
                      'pins': dict(S.T.pin(p) for p in [gpu, cpu, plan_path])}
            config_path = root / 'config.json'
            config_path.write_text(json.dumps(config))
            S.Bootstrap.create(config_path, root / 'controller.py')
            state = dict(LoadState='not-found', ActiveState='inactive', SubState='dead', MainPID=0,
                         ControlPID=0, Job='', InvocationID='', ControlGroup='')
            with mock.patch.object(S.Bootstrap, 'observation', return_value=state):
                recovery = S.pin_recovery(owner, 4, gpu, cpu, binding)
            self.assertTrue(recovery['bootstrap_recovery']['abandoned_incomplete_new_candidate'])
            self.assertEqual(recovery['bootstrap_recovery']['accepted_proofs_discarded'], 0)
            self.assertEqual(recovery['resource_assignment']['limits_by_gpu']['GPU-a']['gpu']['context_bytes'], 3)
            self.assertNotIn(str(owner / 'proofs/coordinator.json'), recovery['pins'])
            self.assertIn(str(gate / 'revoked.json'), recovery['pins'])

    def test_application_recovery_uses_only_the_exact_sealed_owner_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            owner = root / 'owner'
            owner.mkdir()
            config = {'owner_directory': str(owner), 'native_host': {'generation': 2}}
            (root / 'config.json').write_text(json.dumps(config))
            self.assertEqual(S.application_recovery_inputs(owner), {})
            (owner / 'root-only').mkdir()
            proof = owner / 'root-only/node.6.0'
            proof.write_bytes(b'root')
            self.assertEqual(S.application_recovery_inputs(owner),
                             {'recover_proof': proof, 'recover_binding': config['native_host']})
            for changed in ({'owner_directory': str(root)}, {'preseal_only': True}, {'native_host': None}):
                (root / 'config.json').write_text(json.dumps(config | changed))
                with self.assertRaises(ValueError):
                    S.application_recovery_inputs(owner)

    def test_partial_recovery_metadata_routes_to_original_journal_and_retains_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gpu, cpu = root / 'gpu', root / 'cpu'
            gpu.write_bytes(b'GPU identity')
            cpu.write_bytes(b'CPU identity')
            binding = {'head_token': [7] * 32}
            assignment = {'gpu': {'uuid': 'GPU-a', 'available_bytes': 5, 'context_bytes': 3},
                          'cpu': {'rayon_threads': 2}, 'host': {'worker_bytes': 9, 'coordinator_job_bytes': 1},
                          'detected_gpu': {'nvidia': {'driver': 'same'}, 'opencl': {'driver': 'same'}}}
            owners = [root / name / 'owner' for name in ('original', 'interrupted')]
            for index, owner in enumerate(owners):
                proofs = owner / 'proofs'
                proofs.mkdir(parents=True)
                gate = owner / 'coordinator-startup'
                source = None if index == 0 else str(owners[0] / 'proofs')
                plan = {'workers': [{'assignment': assignment}], 'recover_from': source,
                        'startup_fenced': True}
                config = {'owner_directory': str(owner), 'count': 4, 'native_host': binding,
                          'gpu_binary': str(gpu), 'cpu_binary': str(cpu), 'recover_from': source,
                          'owner_unit': 'lattica-v2-multi-owner-' + str(index) * 64 + '.service',
                          'fleet_plan': str(owner.parent / 'fleet-plan.json')}
                if index:
                    plan['coordinator_bootstrap_guard'] = str(gate)
                    config['coordinator_bootstrap_guard'] = str(gate)
                Path(config['fleet_plan']).write_text(json.dumps(plan))
                config['pins'] = dict(S.T.pin(p) for p in [gpu, cpu, config['fleet_plan']])
                config_path = owner.parent / 'config.json'
                config_path.write_text(json.dumps(config))
                if index:
                    (proofs / 'coordinator.json').write_text('{unfinished')
                    S.Bootstrap.create(config_path, root / 'controller.py')
                else:
                    for name, value in {'fleet-plan.json': plan, 'coordinator.json': {}, 'expected.json': {},
                                        'recovery-state.json': {'schema_version': 1, 'epoch': 1,
                                                               'durable_runtime': str(proofs / 'execution')}}.items():
                        (proofs / name).write_text(json.dumps(value))
            state = dict(LoadState='not-found', ActiveState='inactive', SubState='dead', MainPID=0,
                         ControlPID=0, Job='', InvocationID='', ControlGroup='')
            with mock.patch.object(S.Bootstrap, 'observation', return_value=state):
                recovery = S.pin_recovery(owners[1], 4, gpu, cpu, binding)
            self.assertEqual(S.recovery_paths(root / 'next/owner', recovery),
                             (str(owners[0] / 'proofs'), str(owners[0] / 'proofs/execution/launches')))
            self.assertTrue(recovery['bootstrap_recovery']['interrupted_existing_journal'])
            self.assertIn(str(owners[1] / 'proofs/coordinator.json'), recovery['pins'])
            self.assertIn(str(owners[1] / 'coordinator-startup/revoked.json'), recovery['pins'])

    def setUp(self):
        self.workers = [{"budget": {"gpu": {"uuid": "GPU-a"}, "unit": "unit-a"}},
                        {"budget": {"gpu": {"uuid": "GPU-b"}, "unit": "unit-b"}}]
        self.result = {"status": "proved_cpu_audit_pending", "root_file": "node.6.0",
                       "execution_backend": "typed_shared_process_dag_v1", "shared_dag_owner": True,
                       "count": 8, "construction": "typed-paired-v1", "cpu_verified_nodes": 8,
                       "fresh_proofs": 8, "worker_processes_exited": True,
                       "workspace_released_after_gpu_teardown": True, "arrival_backend_integrated": False,
                       "durable_host_applied": False, "production_ready": False,
                       "coordinator_pid": 10, "maximum_active_jobs": 2, "workers": []}
        for index, expected in enumerate(self.workers):
            self.result["workers"].append({"gpu_uuid": expected["budget"]["gpu"]["uuid"],
                "unit": expected["budget"]["unit"], "worker_pid": 20 + index, "coordinator_pid": 10,
                "exit_code": 0, "gpu_teardown_confirmed": True, "workspace_released": True,
                "process_and_cgroup_quiescent": True, "cache_setups": 2, "cache_hits": 2})

    def test_complete_receipt(self):
        S.validate_execution(self.result, 8, self.workers)

    def test_cached_native_continuation_requires_zero_new_gpu_work(self):
        binding = {'head_token': [7] * 32}
        recovery = dict(source='/prior/proofs', previous_epoch=1, recovery_epoch=2,
            previous_coordinator_pid=9, coordinator_pid=10, old_coordinator_quiescent=True,
            old_workers_quiescent=True, old_launches_revoked=True,
            old_workspace_reservations_released=True, original_resource_assignments_preserved=True)
        result = self.result | dict(native_host_bound=True, native_host=binding,
            coordinator_recovery=recovery, recovery_epoch=2, cached_native_continuation=True,
            fresh_proofs=0, cpu_verified_nodes=0, reused_proofs=8,
            reused_nodes=[dict(cpu_reverified=True, recovered_from_journal=True) for _ in range(8)],
            workers=[], gpu_workers_started=0, maximum_active_jobs=0, backend='cpu')
        def validate(value, **kwargs):
            S.validate_execution(value, 8, self.workers, binding,
                recovery_source='/prior/proofs', **kwargs)
        validate(result, recover_cached_only=True)
        with self.assertRaises(ValueError):
            validate(result)
        for key, value in [('workers', self.result['workers']), ('gpu_workers_started', 1),
                ('gpu_workers_started', False), ('maximum_active_jobs', 1), ('backend', 'gpu'),
                ('coordinator_pid', 0), ('failed_workers', 1), ('fresh_proofs', 1)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate(result | {key: value}, recover_cached_only=True)

    def test_cached_admission_reserves_only_the_current_cpu_coordinator(self):
        gib = 2**30
        host = dict(physical_bytes=64*gib, available_bytes=10*gib,
                    cgroup_memory_headroom=2*gib, cpu_capacity='1')
        assignment = dict(gpu={'uuid': 'GPU-a'}, detected_gpu={'uuid': 'GPU-a'},
            host={'worker_bytes': 21*gib, 'coordinator_bytes': gib,
                  'coordinator_job_bytes': gib//2}, cpu={'rayon_threads': 12})
        recovery = dict(gpu_uuids=['GPU-a'], previous_plan=dict(coordinator_ram_bytes=gib,
            coordinator_threads=1, workers=[{'assignment': assignment}]))
        before = copy.deepcopy(recovery)
        with mock.patch.object(S.R, 'detect_gpus', side_effect=AssertionError('GPU inventory called')):
            actual_host, devices, budgets = S.admit_cached_recovery(host, recovery)
        self.assertEqual(actual_host, host)
        self.assertEqual(devices, [{'uuid': 'GPU-a'}])
        self.assertEqual(budgets['GPU-a']['host']['worker_bytes'], 21*gib)
        self.assertNotIn('coordinator_job_bytes', budgets['GPU-a']['host'])
        self.assertEqual(recovery, before)
        for changed in [host | {'available_bytes': 7*gib},
                        host | {'cgroup_memory_headroom': gib//2},
                        host | {'cpu_capacity': '1/2'}]:
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, 'host capacity'):
                S.admit_cached_recovery(changed, recovery)

    def test_recovery_waits_for_capacity_without_changing_the_assignment(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = {'available_bytes': 1, 'scratch': {'path': '/tmp'}}
            later = {'available_bytes': 2, 'scratch': {'path': '/tmp'}}
            devices = [{'uuid': 'GPU-a'}]
            recovery = {'resource_assignment': {'original': True}, 'gpu_binary': '/gpu'}
            with mock.patch.object(S.M, 'plan_budgets', side_effect=[ValueError(
                    'current host capacity cannot admit the fixed comparison limits'), {'admitted': True}]) as plan, \
                    mock.patch.object(S.G, 'detect_worker_host', return_value=later), \
                    mock.patch.object(S.R, 'detect_gpus', return_value=devices), \
                    mock.patch.object(S.time, 'sleep') as sleep:
                result = S.admit_recovery(host, devices, {}, recovery, tmp, 10)
            self.assertEqual(result, (later, devices, {'admitted': True}))
            self.assertEqual(plan.call_count, 2)
            self.assertEqual([call.kwargs['assignment'] for call in plan.call_args_list],
                [recovery['resource_assignment']] * 2)
            sleep.assert_called_once_with(2)
            self.assertEqual(S.read(Path(tmp) / 'recovery-admission-waits.json')[0]['host'], host)

    def test_recovery_admission_rejects_invalid_assignments_without_waiting(self):
        with mock.patch.object(S.M, 'plan_budgets', side_effect=ValueError('host margins changed')), \
                mock.patch.object(S.time, 'sleep') as sleep:
            with self.assertRaisesRegex(ValueError, 'host margins changed'):
                S.admit_recovery({}, [], {}, {'resource_assignment': {}}, '/unused', 10)
        sleep.assert_not_called()

    def test_recovery_pins_original_candidate_binary_and_resource_assignment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            owner = root / 'owner'
            proofs = owner / 'proofs'
            (proofs / 'execution').mkdir(parents=True)
            gpu, cpu = root / 'gpu', root / 'cpu'
            gpu.write_bytes(b'synthetic GPU image identity')
            cpu.write_bytes(b'synthetic CPU image identity')
            binding = {'head_token': [7] * 32}
            assignment = {'gpu': {'uuid': 'GPU-a', 'available_bytes': 5, 'context_bytes': 3},
                'cpu': {'rayon_threads': 2}, 'host': {'worker_bytes': 9, 'coordinator_job_bytes': 1},
                'detected_gpu': {'nvidia': {'driver': 'same'}, 'opencl': {'driver': 'same'}}}
            plan = {'workers': [{'assignment': assignment}], 'recover_from': None}
            plan_path = root / 'fleet-plan.json'
            plan_path.write_text(json.dumps(plan))
            (proofs / 'fleet-plan.json').write_text(json.dumps(plan))
            for filename in ['coordinator.json', 'expected.json', 'execution/worker-0-start.json']:
                (proofs / filename).write_text('{}')
            (proofs / 'recovery-state.json').write_text(json.dumps({'durable_runtime': str(proofs / 'execution')}))
            pins = dict(S.T.pin(path) for path in [gpu, cpu, plan_path])
            config = {'owner_directory': str(owner), 'count': 4, 'native_host': binding,
                'gpu_binary': str(gpu), 'cpu_binary': str(cpu), 'pins': pins,
                'fleet_plan': str(plan_path)}
            config['context_calibrations'] = {'GPU-a': {'peak_context_bytes': 2, 'samples': 3}}
            workload = Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json').resolve()
            config['pins'].update(dict([S.T.pin(workload)]))
            config['workload_path'] = str(workload)
            config['workload_profile'] = S.T.resource_profile(workload, 'paired', 'compact')
            (root / 'config.json').write_text(json.dumps(config))
            result = S.pin_recovery(owner, 4, gpu, cpu, binding)
            self.assertEqual(result['context_calibrations'], config['context_calibrations'])
            self.assertEqual(result['workload_profile'], config['workload_profile'])
            self.assertEqual(result['launch_directory'], str(proofs / 'execution/launches'))
            limits = result['resource_assignment']['limits_by_gpu']['GPU-a']
            self.assertNotIn('coordinator_job_bytes', limits['host'])
            self.assertNotIn('available_bytes', limits['gpu'])
            self.assertEqual(limits['gpu']['context_bytes'], 3)
            for count, current in [(8, binding), (4, {'head_token': [8] * 32})]:
                with self.assertRaises(ValueError):
                    S.pin_recovery(owner, count, gpu, cpu, current)
            plan['startup_fenced'] = True
            plan_path.write_text(json.dumps(plan))
            (proofs / 'fleet-plan.json').write_text(json.dumps(plan))
            config['pins'].update(dict([S.T.pin(plan_path)]))
            (root / 'config.json').write_text(json.dumps(config))
            (proofs / 'execution/worker-0-start.json').unlink()
            gate = proofs / 'execution/worker-0-startup'
            gate.mkdir()
            intent = gate / 'intent.json'
            intent.write_text('{}')
            interrupted = S.pin_recovery(owner, 4, gpu, cpu, binding)
            self.assertIn(str(intent), interrupted['pins'])
            self.assertNotIn(str(proofs / 'execution/worker-0-start.json'), interrupted['pins'])
            gpu.write_bytes(b'changed image')
            with self.assertRaises(ValueError):
                S.pin_recovery(owner, 4, gpu, cpu, binding)

    def test_coordinator_recovery_requires_exact_old_owner_reconciliation(self):
        binding = {'head_token': [7] * 32}
        recovery = {'source': '/prior/proofs', 'previous_epoch': 1, 'recovery_epoch': 2,
            'previous_coordinator_pid': 9, 'coordinator_pid': 10,
            'old_coordinator_quiescent': True, 'old_workers_quiescent': True,
            'old_launches_revoked': True, 'old_workspace_reservations_released': True,
            'original_resource_assignments_preserved': True}
        result = self.result | {'native_host_bound': True, 'native_host': binding,
            'coordinator_recovery': recovery, 'recovery_epoch': 2}
        S.validate_execution(result, 8, self.workers, binding, recovery_source='/prior/proofs')
        with self.assertRaises(ValueError):
            S.validate_execution(result, 8, self.workers, binding)
        for key, value in [('source', '/wrong/proofs'), ('old_coordinator_quiescent', False),
                ('old_workers_quiescent', False), ('old_launches_revoked', False),
                ('old_workspace_reservations_released', False), ('recovery_epoch', 3),
                ('previous_coordinator_pid', 10), ('original_resource_assignments_preserved', False)]:
            with self.subTest(key=key):
                altered = result | {'coordinator_recovery': recovery | {key: value}}
                with self.assertRaises(ValueError):
                    S.validate_execution(altered, 8, self.workers, binding, recovery_source='/prior/proofs')

    def test_failover_requires_explicit_admission_and_exact_stop_receipts(self):
        binding = {"head_token": [7] * 32}
        result = copy.deepcopy(self.result)
        result.update(native_host_bound=True, native_host=binding)
        result.update(allow_worker_failover=True, failed_workers=1)
        result['workers'][0].update(worker_failed=True, exit_code=None,
            forced_stop_confirmed=True, launch_revoked=True, teardown_method='process_and_cgroup_exit',
            failed_job='11' * 32, lease_key='22' * 32, cache_setups=0, cache_hits=0)
        result['workers'][1].update(cache_setups=2, cache_hits=6)
        S.validate_execution(result, 8, self.workers, binding, allow_worker_failover=True)
        with self.assertRaises(ValueError):
            S.validate_execution(result, 8, self.workers, binding)
        for key, value in [('forced_stop_confirmed', False), ('launch_revoked', False),
                           ('process_and_cgroup_quiescent', False), ('workspace_released', False),
                           ('exit_code', 0), ('lease_key', 'bad'), ('worker_failed', 1)]:
            changed = copy.deepcopy(result)
            changed['workers'][0][key] = value
            with self.assertRaises(ValueError):
                S.validate_execution(changed, 8, self.workers, binding, allow_worker_failover=True)
        for count in [0, 2, True]:
            with self.assertRaises(ValueError):
                S.validate_execution(result | {'failed_workers': count}, 8, self.workers, binding, allow_worker_failover=True)

    def test_successful_prefix_exit_does_not_require_a_root_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'result.json'
            result = {'status': 'succeeded', 'preseal_only': True, 'cpu_prefix_audited': True, 'cpu_audited': False}
            path.write_text(json.dumps(result))
            state = {'Result': 'success', 'ExecMainStatus': '0'}
            self.assertTrue(S.owner_succeeded(tmp, state, prefix=True))
            self.assertFalse(S.owner_succeeded(tmp, state))
            self.assertFalse(S.owner_succeeded(tmp, state | {'ExecMainStatus': '1'}, prefix=True))
            path.write_text(json.dumps(result | {'cpu_prefix_audited': False}))
            self.assertFalse(S.owner_succeeded(tmp, state, prefix=True))

    def test_prefix_cannot_be_counted_as_root_or_full_candidate(self):
        result = self.result | {'preseal_only': True, 'status': 'preseal_verified', 'root_file': None}
        S.validate_execution(result, 8, self.workers, preseal_only=True)
        with self.assertRaises(ValueError):
            S.validate_execution(result, 8, self.workers)
        for key, value in [('root_file', 'node.6.0'), ('status', 'proved_cpu_audit_pending')]:
            with self.assertRaises(ValueError):
                S.validate_execution(result | {key: value}, 8, self.workers, preseal_only=True)

    def test_cached_nodes_require_cpu_reverification_and_exact_accounting(self):
        result = self.result | {'reused_proofs': 1, 'reused_nodes': [{'cpu_reverified': True}]}
        S.validate_execution(result, 8, self.workers)
        for key, value in [('reused_proofs', True), ('reused_proofs', 2), ('reused_proofs', -1),
                           ('reused_nodes', [None]), ('reused_nodes', [{'cpu_reverified': False}])]:
            with self.assertRaises(ValueError):
                S.validate_execution(result | {key: value}, 8, self.workers)

    def test_prefix_requires_unsealed_native_intake(self):
        for native, directory, selection in [(None, '/unused', None), (object(), None, None),
                                               (object(), '/unused', 'sealed')]:
            with self.assertRaises(ValueError):
                S.open_intake(native, directory, selection, prefix=True)

    def test_cache_pins_cover_manifest_and_bounded_distinct_nodes(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            proof = directory / 'node.1.0'
            proof.write_bytes(b'proof')
            node = {'level': 1, 'index': 0, 'bytes': 5}
            cache = {'schema_version': 1, 'status': 'preseal_verified', 'preseal_only': True,
                     'stable_nodes': [node]}
            manifest = directory / 'result.json'
            manifest.write_text(json.dumps(cache))
            paths, pins = S.pin_preseal([directory])
            self.assertEqual(paths, [str(directory)])
            self.assertEqual(set(pins), {str(manifest), str(proof)})
            with self.assertRaises(ValueError):
                S.pin_preseal([directory, directory])
            for changes in [{'level': 6}, {'index': -1}, {'level': True}, {'bytes': 4},
                            {'bytes': 2 * 1024 * 1024 + 1}]:
                manifest.write_text(json.dumps(cache | {'stable_nodes': [node | changes]}))
                with self.assertRaises(ValueError):
                    S.pin_preseal([directory])
            manifest.write_text(json.dumps(cache | {'stable_nodes': [node, node]}))
            with self.assertRaises(ValueError):
                S.pin_preseal([directory])

    def test_arrival_options_require_a_native_candidate_and_complete_pair(self):
        self.assertIsNone(S.open_intake(None, None, None))
        for directory, selection in [("/unused", None), (None, "11" * 32), ("/unused", "11" * 32)]:
            with self.assertRaises(ValueError):
                S.open_intake(None, directory, selection)

    def test_native_binding_must_match_and_cannot_appear_in_a_fixture_receipt(self):
        binding = {"head_token": [7] * 32, "expected": {"count": 8, "block_height": 10}}
        result = self.result | {"native_host_bound": True, "native_host": binding}
        S.validate_execution(result, 8, self.workers, binding)
        with self.assertRaises(ValueError):
            S.validate_execution(result, 8, self.workers)
        with self.assertRaises(ValueError):
            S.validate_execution(self.result, 8, self.workers, binding)
        changed = copy.deepcopy(binding)
        changed["expected"]["block_height"] = 11
        with self.assertRaises(ValueError):
            S.validate_execution(result, 8, self.workers, changed)
        with self.assertRaises(ValueError):
            S.validate_execution(result | {"native_host_bound": 1}, 8, self.workers, binding)

    def test_scope_does_not_turn_into_native_delivery_or_another_backend(self):
        for key, bad in [("execution_backend", "typed_process_dag_v1"), ("shared_dag_owner", False),
                         ("arrival_backend_integrated", True), ("durable_host_applied", True),
                         ("production_ready", True), ("count", 4), ("count", True),
                         ("fresh_proofs", None), ("cpu_verified_nodes", 7)]:
            with self.subTest(key=key, value=bad):
                changed = copy.deepcopy(self.result)
                changed[key] = bad
                with self.assertRaises(ValueError):
                    S.validate_execution(changed, 8, self.workers)

    def test_every_assigned_worker_has_a_distinct_observed_identity(self):
        for key, bad in [("gpu_uuid", "GPU-other"), ("unit", "another.service"),
                         ("worker_pid", 10), ("worker_pid", 21), ("worker_pid", -1),
                         ("worker_pid", True), ("coordinator_pid", 99)]:
            with self.subTest(key=key, value=bad):
                changed = copy.deepcopy(self.result)
                changed["workers"][0][key] = bad
                with self.assertRaises(ValueError):
                    S.validate_execution(changed, 8, self.workers)
        for workers in [[], self.result["workers"][:1], self.result["workers"] * 2]:
            with self.assertRaises(ValueError):
                S.validate_execution(self.result | {"workers": workers}, 8, self.workers)

    def test_teardown_and_cgroup_exit_are_both_required(self):
        for key, bad in [("exit_code", 1), ("exit_code", False), ("gpu_teardown_confirmed", False),
                         ("workspace_released", False), ("process_and_cgroup_quiescent", False)]:
            with self.subTest(key=key, value=bad):
                changed = copy.deepcopy(self.result)
                changed["workers"][0][key] = bad
                with self.assertRaises(ValueError):
                    S.validate_execution(changed, 8, self.workers)

    def test_cache_totals_must_cover_exactly_the_completed_jobs(self):
        for key, bad in [("cache_setups", -1), ("cache_hits", True), ("cache_hits", 3), ("cache_setups", None)]:
            with self.subTest(key=key, value=bad):
                changed = copy.deepcopy(self.result)
                changed["workers"][0][key] = bad
                with self.assertRaises(ValueError):
                    S.validate_execution(changed, 8, self.workers)

    def test_active_job_count_is_within_the_assigned_fleet(self):
        for value in [0, 3, True, -1]:
            with self.assertRaises(ValueError):
                S.validate_execution(self.result | {"maximum_active_jobs": value}, 8, self.workers)

    def test_accounting_path_is_quoted_for_systemd_without_shell_evaluation(self):
        value = S.accounting_property('/tmp/a "quoted" $x %n path')
        self.assertIn('"/tmp/a \\"quoted\\" $x %%n path"', value)
        self.assertTrue(value.startswith("--property=ExecStopPost=:"))


if __name__ == "__main__":
    unittest.main()
