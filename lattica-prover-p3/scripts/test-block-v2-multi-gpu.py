#!/usr/bin/env python3
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import block_v2_resources as R

spec = importlib.util.spec_from_file_location('multi', Path(__file__).with_name('block-v2-multi-gpu-run.py'))
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)


def host():
    return {'physical_bytes': 64 * R.GIB, 'available_bytes': 58 * R.GIB,
            'cgroup_memory_headroom': None, 'cpu_capacity': '24', 'effective_cpus': list(range(24)),
            'scratch': {'capacity_bytes': 32 * R.GIB, 'available_bytes': 30 * R.GIB,
                        'quota_bytes': None, 'device': 9, 'path': '/tmp', 'tmpfs': True}}


def device(uuid='GPU-a', total=16 * R.GIB, free=15 * R.GIB):
    return {'uuid': uuid, 'opencl': {'global_bytes': total, 'max_allocation_bytes': total // 4, 'driver': 'CL'},
            'nvidia': {'total_bytes': total, 'free_bytes': free, 'driver': 'NV'}}


def calibration(uuid='GPU-a', overhead=600 * R.MIB):
    return {'uuid': uuid, 'driver': 'NV', 'runtime': 'CL', 'peak_context_bytes': overhead}


class ResourceTests(unittest.TestCase):
    def test_fri_and_preprocessing_reservations_survive_every_admission_check(self):
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json').read_text())
        budget = R.plan(host(), [device()], 1, profile)['GPU-a']
        profile['phases'] = [dict(name='boundary', heap_bytes=budget['host']['worker_bytes'],
            pinned_bytes=0, driver_host_bytes=0, resident_spill_bytes=0, managed_gpu_bytes=0,
            max_gpu_allocation_bytes=0, spill_payloads=[])]
        self.assertTrue(R.workload_fits(budget, profile))
        profile['geometry']['gpu_fri_fold'] = True
        self.assertTrue(any('host RAM' in failure for failure in R.workload_failures(budget, profile)))
        profile['phases'][0]['heap_bytes'] -= R.MIB
        self.assertTrue(R.workload_fits(budget, profile))
        profile['preprocessing_cache'] = {'entries': 2, 'reserve_bytes': R.GIB}
        self.assertFalse(R.workload_fits(budget, profile))
        profile['phases'][0]['heap_bytes'] -= R.GIB
        self.assertTrue(R.workload_fits(budget, profile))
        env = S.environment(dict(budget, gpu_fri_fold=True, unit='test.service'), Path('/tmp/test'))
        self.assertEqual(env['LATTICA_V2_GPU_FRI_FOLD'], '1')
        for invalid in (1, 'true', None):
            with self.assertRaises(ValueError):
                S.environment(dict(budget, gpu_fri_fold=invalid), Path('/tmp/test'))

    def test_pool_reserves_wallet_and_coordinator_before_weighted_workers(self):
        policy = {'wallet_threads': 4, 'wallet_bytes': 4 * R.GIB,
                  'coordinator_threads': 2, 'coordinator_bytes': 2 * R.GIB,
                  'weights': {'GPU-a': 2, 'GPU-b': 1}}
        budgets = R.shared_budgets(host(), ['GPU-b', 'GPU-a'], policy)
        a, b = budgets['GPU-a'], budgets['GPU-b']
        self.assertEqual(a['cpu']['rayon_threads'] + b['cpu']['rayon_threads'], 17)
        self.assertGreater(a['cpu']['rayon_threads'], b['cpu']['rayon_threads'])
        used = a['host']['worker_bytes'] + b['host']['worker_bytes'] + 6 * R.GIB
        self.assertLessEqual(used, a['host']['fleet_bytes'])
        self.assertEqual(a['wallet'], {'threads': 4, 'ram_bytes': 4 * R.GIB})
        for budget in budgets.values():
            self.assertLessEqual(budget['host']['spill_bytes'], budget['host']['worker_bytes'])
        policy['wallet_bytes'] = 128 * R.GIB
        with self.assertRaises(ValueError):
            R.shared_budgets(host(), ['GPU-a', 'GPU-b'], policy)

    def test_opening_denominator_cache_is_pinned_and_memory_bounded(self):
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json').read_text())
        cached = copy.deepcopy(profile)
        cached['geometry']['opening_denominator_cache'] = True
        self.assertNotEqual(S.profile_digest({'workload': profile}), S.profile_digest({'workload': cached}))
        control = R.plan(host(), [device()], 1, profile)['GPU-a']
        candidate = R.plan(host(), [device()], 1, cached)['GPU-a']
        for section in ('cpu', 'host', 'gpu'):
            self.assertEqual(control[section], candidate[section])
        for budget, expected in [(control, '0'), (candidate, '1')]:
            budget = dict(budget, unit='lattica-v2-multi-test.service')
            self.assertEqual(S.environment(budget, Path('/tmp/test'))[
                'LATTICA_V2_GPU_OPENING_DENOMINATOR_CACHE'], expected)
        cached['geometry']['opening_denominator_cache'] = 'true'
        with self.assertRaisesRegex(ValueError, 'must be boolean'):
            R.plan(host(), [device()], 1, cached)
        with self.assertRaisesRegex(ValueError, 'must be boolean'):
            S.environment(dict(candidate, opening_denominator_cache=1), Path('/tmp/test'))

    def test_query_gather_is_profile_bound_and_preserves_resource_reservations(self):
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json').read_text())
        gathered = copy.deepcopy(profile)
        gathered['geometry']['query_readback_layout'] = 'gather'
        self.assertNotEqual(S.profile_digest({'workload': profile}), S.profile_digest({'workload': gathered}))
        controls = R.plan(host(), [device()], 1, profile)
        candidates = R.plan(host(), [device()], 1, gathered)
        for section in ('host', 'cpu', 'gpu'):
            self.assertEqual(controls['GPU-a'][section], candidates['GPU-a'][section])
        for budgets, expected in ((controls, '0'), (candidates, '1')):
            budget = dict(budgets['GPU-a'], unit='lattica-v2-multi-test.service')
            self.assertEqual(S.environment(budget, Path('/tmp/test'))['LATTICA_V2_GPU_QUERY_GATHER'], expected)
        gathered['geometry']['query_readback_layout'] = 'typo'
        with self.assertRaisesRegex(ValueError, 'query readback layout'):
            R.plan(host(), [device()], 1, gathered)
        budget = dict(candidates['GPU-a'], unit='lattica-v2-multi-test.service', query_readback_layout='typo')
        with self.assertRaisesRegex(ValueError, 'query readback layout'):
            S.environment(budget, Path('/tmp/test'))

    def test_direct_readback_admits_two_workers_without_relaxing_budgets(self):
        directory = Path(__file__).parent
        banded = json.loads((directory / 'block-v2-multi-gpu-workload.json').read_text())
        direct = json.loads((directory / 'block-v2-multi-gpu-direct-readback-workload.json').read_text())
        h = host()
        h['available_bytes'] = 43 * R.GIB
        devices = [device('GPU-a'), device('GPU-b')]
        calibrations = {d['uuid']: calibration(d['uuid']) for d in devices}
        with self.assertRaisesRegex(ValueError, 'host RAM|spill'):
            R.plan(h, devices, 2, banded, calibrations)
        budgets = R.plan(h, devices, 2, direct, calibrations)
        self.assertEqual(len(budgets), 2)
        unchanged = R.shared_budgets(h, ['GPU-a', 'GPU-b'])
        for uuid, b in budgets.items():
            self.assertEqual(b['host'], unchanged[uuid]['host'])
            self.assertEqual(b['cpu'], unchanged[uuid]['cpu'])
            self.assertEqual(b['readback_layout'], 'direct')
            self.assertEqual(R.workload_failures(b, direct), [])
            env = S.environment(dict(b, unit='lattica-v2-multi-test.service'), Path('/tmp/test'))
            self.assertEqual(env['LATTICA_V2_GPU_DIRECT_READBACK'], '1')
            self.assertEqual(env['LATTICA_SPILL_MAX_BYTES'], str(b['host']['spill_bytes']))
        for a, b in zip(banded['phases'], direct['phases']):
            self.assertEqual(a['heap_bytes'], b['heap_bytes'])
            self.assertEqual(a['driver_host_bytes'], b['driver_host_bytes'])
            self.assertEqual(a['managed_gpu_bytes'], b['managed_gpu_bytes'])

    def test_readback_layout_is_pinned_and_invalid_modes_fail_closed(self):
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-workload.json').read_text())
        reference = S.profile_digest({'workload': profile})
        profile['geometry']['host_readback_layout'] = 'direct'
        self.assertNotEqual(reference, S.profile_digest({'workload': profile}))
        profile['geometry']['host_readback_layout'] = 'typo'
        with self.assertRaisesRegex(ValueError, 'readback layout'):
            R.plan(host(), [device()], 1, profile)
        budget = {**R.shared_budgets(host(), ['GPU-a'])['GPU-a'],
                  'gpu': vars(R.gpu_budget(device())), 'unit': 'lattica-v2-multi-test.service'}
        self.assertEqual(S.environment(budget, Path('/tmp/test'))['LATTICA_V2_GPU_DIRECT_READBACK'], '0')
        budget['readback_layout'] = 'typo'
        with self.assertRaisesRegex(ValueError, 'readback layout'):
            S.environment(budget, Path('/tmp/test'))

    def test_heterogeneous_devices_never_share_vram(self):
        large = R.gpu_budget(device(), calibration())
        small = R.gpu_budget(device('GPU-b', 8 * R.GIB, 5 * R.GIB), calibration('GPU-b'))
        self.assertGreater(large.managed_bytes, small.managed_bytes)
        for b in (large, small):
            self.assertEqual(b.total_bytes, b.managed_bytes + b.context_bytes)
            self.assertLessEqual(b.total_bytes + b.headroom_bytes, b.available_bytes)
            self.assertEqual(b.managed_bytes % R.QUANTUM, 0)
            self.assertGreaterEqual(b.context_bytes * 4, 600 * R.MIB * 5)

    def test_bootstrap_uses_at_most_half_available_after_headroom(self):
        b = R.gpu_budget(device())
        self.assertTrue(b.bootstrap)
        self.assertLessEqual(b.managed_bytes * 2, b.available_bytes - b.headroom_bytes)

    def test_calibration_binding_and_low_gpu(self):
        c = calibration()
        c['driver'] = 'new'
        with self.assertRaises(ValueError):
            R.gpu_budget(device(), c)
        with self.assertRaises(ValueError):
            R.gpu_budget(device(free=512 * R.MIB))

    def test_cpu_budget_reserves_coordinator_and_orders_remainder_by_uuid(self):
        p = R.shared_budgets(host(), ['GPU-b', 'GPU-a'])
        self.assertEqual(p['GPU-a']['cpu']['rayon_threads'], 12)
        self.assertEqual(p['GPU-b']['cpu']['rayon_threads'], 11)
        self.assertEqual(p['GPU-a']['cpu']['allowed_cpus'], tuple(range(24)))

    def test_fractional_ancestor_quota_enforced(self):
        h = host()
        h['cpu_capacity'] = '7/2'
        p = R.shared_budgets(h, ['GPU-b', 'GPU-a'])
        self.assertEqual(p['GPU-a']['cpu']['rayon_threads'], 1)
        self.assertEqual(p['GPU-a']['cpu']['quota_percent'], '125%')
        h['cpu_capacity'] = '3/2'
        with self.assertRaises(ValueError):
            R.shared_budgets(h, ['GPU-a', 'GPU-b'])
        self.assertEqual(R.shared_budgets(h, ['GPU-a'])['GPU-a']['cpu']['quota_percent'], '150%')

    def test_worker_and_caller_ancestors_both_constrain_admission(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            caller = root / 'session'
            parent = root / 'user' / 'lattica.slice'
            fleet = parent / 'lattica-v2-multi.slice'
            caller.mkdir()
            fleet.mkdir(parents=True)
            for path, values in [
                (root, {'cpu.max': '700000 100000', 'memory.max': str(64 * R.GIB),
                        'memory.current': str(R.GIB)}),
                (caller, {'cpuset.cpus.effective': '0-7', 'cpu.max': '600000 100000'}),
                (parent, {'cpuset.cpus.effective': '2-5', 'cpu.max': '350000 100000',
                          'memory.max': str(12 * R.GIB), 'memory.current': str(3 * R.GIB)}),
                (fleet, {'cpu.max': '250000 100000', 'memory.max': str(2 * R.GIB),
                         'memory.current': str(R.GIB)}),
            ]:
                for name, value in values.items():
                    (path / name).write_text(value)
            limits = R.cgroup_limits([caller, fleet], range(24), [fleet], root)
            self.assertEqual(limits['effective_cpus'], [2, 3, 4, 5])
            self.assertEqual(limits['cpu_capacity'], '5/2')
            self.assertEqual(limits['cgroup_memory_headroom'], 9 * R.GIB)
            rows = limits['ancestors']
            self.assertEqual(sum(row['path'] == str(root) for row in rows), 1)
            self.assertTrue(next(row for row in rows if row['path'] == str(fleet))
                            ['memory_limit_owned_by_controller'])
            # Without the explicit controller-owned exception, the fleet limit applies.
            self.assertEqual(R.cgroup_limits([fleet], range(24), root=root)
                             ['cgroup_memory_headroom'], R.GIB)

    def test_worker_inventory_uses_assigned_slice_instead_of_bounded_observer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            observer = root / 'observer.service'
            parent = root / 'user.slice'
            fleet = parent / 'fleet.slice'
            observer.mkdir()
            fleet.mkdir(parents=True)
            for path, values in [
                (root, {'cpu.max': '2400000 100000'}),
                (observer, {'cpu.max': '100000 100000', 'memory.max': str(2 * R.GIB),
                            'memory.current': str(R.GIB)}),
                (parent, {'cpu.max': '1200000 100000', 'memory.max': str(60 * R.GIB),
                          'memory.current': str(8 * R.GIB)}),
                (fleet, {'memory.max': str(40 * R.GIB), 'memory.current': str(R.GIB)}),
            ]:
                for name, value in values.items():
                    (path / name).write_text(value)
            original = R.cgroup_limits
            def limits(paths, cpus, ignored):
                return original(paths, cpus, ignored, root=root)
            filesystem = {'filesystems': [{'fstype': 'tmpfs', 'options': 'rw'}]}
            with patch.object(R, 'cgroup_path', return_value=observer), \
                 patch.object(R, 'cgroup_limits', side_effect=limits), \
                 patch.object(R.os, 'sched_getaffinity', return_value=set(range(24))), \
                 patch.object(R, 'command_json', return_value=filesystem):
                workers = R.detect_host(tmp, worker_cgroup=fleet)
                current = R.detect_host(tmp)
            self.assertEqual(workers['cpu_capacity'], '12')
            self.assertEqual(workers['cgroup_memory_headroom'], 52 * R.GIB)
            self.assertEqual(workers['resource_cgroup_scope'], 'assigned_workers')
            self.assertNotIn(str(observer), [group['path'] for group in workers['ancestors']])
            self.assertEqual(current['cpu_capacity'], '1')
            self.assertEqual(current['cgroup_memory_headroom'], R.GIB)
            self.assertEqual(current['resource_cgroup_scope'], 'current_process')

    def test_inactive_worker_slice_plan_still_observes_existing_parents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'cpu.max').write_text('150000 100000')
            missing = root / 'inactive.slice' / 'fleet.slice'
            limits = R.cgroup_limits([missing], range(24), root=root)
            self.assertEqual(limits['cpu_capacity'], '3/2')
            self.assertEqual(sum(row.get('present') is False for row in limits['ancestors']), 2)
        with patch.object(S, 'systemctl', return_value='/'), \
                patch.object(Path, 'is_dir', return_value=True):
            self.assertEqual(S.worker_cgroup(), Path('/sys/fs/cgroup/lattica.slice/lattica-v2.slice/lattica-v2-multi.slice'))
        with patch.object(S, 'systemctl', return_value=''):
            with self.assertRaises(ValueError):
                S.worker_cgroup()

    def test_host_adapts_to_cgroup_and_counts_tmpfs_in_ram(self):
        h = host()
        h['cgroup_memory_headroom'] = 12 * R.GIB
        b = R.shared_budgets(h, ['GPU-a', 'GPU-b'])['GPU-a']['host']
        self.assertLessEqual(2 * b['worker_bytes'] + b['coordinator_bytes'], 12 * R.GIB)
        self.assertLessEqual(b['spill_bytes'], b['worker_bytes'])
        self.assertEqual(b['swap_bytes'], 0)
        h['available_bytes'] = R.GIB
        with self.assertRaises(ValueError):
            R.shared_budgets(h, ['GPU-a'])

    def test_spill_quota_and_mapping_headers_are_not_free(self):
        h = host()
        h['scratch']['quota_bytes'] = 2 * R.GIB
        b = R.shared_budgets(h, ['GPU-a', 'GPU-b'])['GPU-a']
        b['gpu'] = R.asdict(R.gpu_budget(device()))
        self.assertEqual(b['host']['spill_bytes'], R.GIB)
        phase = dict(heap_bytes=0, pinned_bytes=0, driver_host_bytes=0, resident_spill_bytes=0,
                     spill_payloads=[R.GIB], managed_gpu_bytes=1, max_gpu_allocation_bytes=1)
        profile = {'version': 1, 'page_bytes': 4096, 'phases': [phase]}
        self.assertFalse(R.workload_fits(b, profile))
        phase['spill_payloads'] = [R.GIB - 4096]
        self.assertTrue(R.workload_fits(b, profile))
        phase['heap_bytes'] = b['host']['worker_bytes']
        self.assertFalse(R.workload_fits(b, profile))

    def test_qualification_uses_stricter_calculated_limits(self):
        h = host()
        h['scratch']['available_bytes'] = 32 * R.GIB
        b = R.shared_budgets(h, ['GPU-a', 'GPU-b'])['GPU-a']
        b['gpu'] = R.asdict(R.gpu_budget(device(), calibration()))
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-workload.json').read_text())
        q = R.qualification_budget(b, profile)
        self.assertLess(q['host']['worker_bytes'], b['host']['worker_bytes'])
        self.assertLess(q['gpu']['managed_bytes'], b['gpu']['managed_bytes'])
        self.assertEqual(q['cpu'], b['cpu'])
        self.assertTrue(R.workload_fits(q, profile))
        self.assertEqual(q['host']['worker_bytes'], 19 * R.GIB)

    def test_fallback_retains_specific_resource_failure(self):
        h = host()
        h['scratch']['quota_bytes'] = 2 * R.GIB
        phase = dict(name='commit', heap_bytes=0, pinned_bytes=0, driver_host_bytes=0,
                     resident_spill_bytes=0, spill_payloads=[R.GIB + 4096],
                     managed_gpu_bytes=1, max_gpu_allocation_bytes=1)
        config = {'max_concurrency': 2, 'jobs': [{}, {}],
                  'workload': {'version': 1, 'page_bytes': 4096, 'phases': [phase]}}
        devices = [device(), device('GPU-b')]
        failures = []
        budgets = S.choose_plan(config, h, devices, failures)
        self.assertEqual(len(budgets), 1)
        self.assertEqual(failures[0]['worker_slots'], 2)
        self.assertIn('commit: spill requires', failures[0]['reason'])
        config['worker_slots'] = 2
        with self.assertRaisesRegex(ValueError, 'commit: spill requires'):
            S.choose_plan(config, h, devices)

    def test_cpu_list_and_rounding(self):
        self.assertEqual(R.cpulist('0-3,8,10-11'), {0, 1, 2, 3, 8, 10, 11})
        with self.assertRaises(ValueError):
            R.cpulist('4-1')
        self.assertEqual(R.up(R.QUANTUM + 1), R.QUANTUM * 2)
        self.assertEqual(R.down(R.QUANTUM - 1), 0)

    def test_recovery_keeps_live_reservations_and_never_queues_retry(self):
        with tempfile.TemporaryDirectory() as d:
            a = {'unit': 'a', 'directory': d, 'status': 'running', 'reservation_released': False}
            ledger = {'attempts': [a], 'queued': []}
            S.reconcile(ledger, lambda _: {'ActiveState': 'active', 'ControlGroup': ''})
            self.assertEqual(a['status'], 'running')
            self.assertFalse(a['reservation_released'])
            S.reconcile(ledger, lambda _: {'ActiveState': 'failed', 'ControlGroup': ''})
            self.assertEqual(a['status'], 'interrupted')
            self.assertTrue(a['reservation_released'])
            self.assertEqual(ledger['queued'], [])

    def test_recovery_does_not_release_on_unknown_termination(self):
        a = {'unit': 'a', 'directory': '/missing', 'status': 'running', 'reservation_released': False}
        for state in ['activating', 'deactivating', 'active', 'reloading']:
            S.reconcile({'attempts': [a]}, lambda _: {'ActiveState': state})
            self.assertFalse(a['reservation_released'])

    def test_failed_service_or_missing_cpu_audit_cannot_count_as_success(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'result.json'
            path.write_text(json.dumps({'status': 'succeeded', 'cpu_audited': True}))
            state = {'Result': 'success', 'ExecMainStatus': '0'}
            self.assertTrue(S.attempt_succeeded(d, state))
            self.assertFalse(S.attempt_succeeded(d, {**state, 'Result': 'exit-code'}))
            self.assertFalse(S.attempt_succeeded(d, {**state, 'ExecMainStatus': '1'}))
            path.write_text(json.dumps({'status': 'succeeded', 'cpu_audited': False}))
            self.assertFalse(S.attempt_succeeded(d, state))

    def test_gpu_loss_stops_admissions_without_retry_and_preserves_uncertain_reservations(self):
        for exited in [False, True]:
            with tempfile.TemporaryDirectory() as tmp:
                evidence = Path(tmp) / 'evidence'
                h = host()
                b = R.shared_budgets(h, ['GPU-a'])['GPU-a']
                b['gpu'] = R.asdict(R.gpu_budget(device()))
                config = {'scratch': tmp, 'max_concurrency': 1,
                          'jobs': [{'id': 'first'}, {'id': 'second'}]}
                state = {'ActiveState': 'failed' if exited else 'deactivating',
                         'ControlGroup': '', 'Result': 'signal', 'ExecMainStatus': '9'}
                def launched(config, job, budget, directory):
                    directory.mkdir()
                with patch.object(S, 'lock_fleet', return_value=[]), \
                     patch.object(S, 'verify_pins'), \
                     patch.object(S.R, 'detect_host', return_value=h), \
                     patch.object(S, 'worker_cgroup', return_value=Path('/sys/fs/cgroup/fleet.slice')), \
                     patch.object(S, 'selected_devices', return_value=[device()]), \
                     patch.object(S, 'choose_plan', return_value={'GPU-a': b}), \
                     patch.object(S, 'systemctl', return_value='[]'), \
                     patch.object(S, 'launch', side_effect=launched) as launch, \
                     patch.object(S, 'telemetry', side_effect=ValueError('GPU lost')), \
                     patch.object(S, 'unit_state', return_value=state), \
                     patch.object(S.subprocess, 'run'), \
                     patch.object(S.time, 'sleep'):
                    with self.assertRaisesRegex(ValueError, 'GPU lost'):
                        S.run(config, evidence)
                ledger = json.loads((evidence / 'ledger.json').read_text())
                self.assertEqual(launch.call_count, 1)
                self.assertEqual(ledger['status'], 'failed')
                self.assertEqual(ledger['queued'], ['second'])
                self.assertEqual(len(ledger['attempts']), 1)
                self.assertEqual(ledger['attempts'][0]['reservation_released'], exited)

    def test_unqualified_concurrent_launch_refused(self):
        b = R.shared_budgets(host(), ['GPU-a'])['GPU-a']
        b['gpu'] = R.asdict(R.gpu_budget(device()))
        with self.assertRaises(ValueError):
            S.qualification_gate({'max_concurrency': 2}, {'GPU-a': b, 'GPU-b': b})

    def test_durable_assignment_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'budget.json'
            S.durable(path, {'version': 1}, True)
            with self.assertRaises(ValueError):
                S.durable(path, {'version': 2}, True)
            self.assertEqual(json.loads(path.read_text()), {'version': 1})


if __name__ == '__main__':
    unittest.main()
