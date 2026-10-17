#!/usr/bin/env python3
import copy
import importlib
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import block_v2_phase_memory as P
import block_v2_resources as R
T = importlib.import_module('block-v2-typed-gpu-run')

class PhaseMemoryTests(unittest.TestCase):
    def test_calibration_ignores_absent_gpu_but_checks_present_driver(self):
        screen = importlib.import_module('block-v2-linux-phase-run')
        model = P.model(self.profile, 2)
        worker = dict(uuid='present', drivers=dict(nvidia='n', opencl='o'),
                      budget=dict(memory_schedule=P.schedule(model, Path('/tmp/qualification'), 1)),
                      result=dict(cpu_audited=True, fresh_proofs=8),
                      context=dict(peak_context_bytes=123))
        absent = copy.deepcopy(worker)
        absent['uuid'] = 'absent'
        doc = dict(status='succeeded', binary_sha256='hash', memory_model=model,
                   workload=self.profile, workers=[absent, worker])
        inventory = dict(present=dict(nvidia=dict(driver='n'), opencl=dict(driver='o')))
        with patch.object(screen, 'read', return_value=doc), patch.object(screen.G, 'digest', return_value='hash'):
            self.assertEqual(screen.calibration([Path('/qualification')], Path('/binary'), inventory, self.profile), {'present': 123})
            inventory['present']['nvidia']['driver'] = 'changed'
            with self.assertRaisesRegex(ValueError, 'driver changed'):
                screen.calibration([Path('/qualification')], Path('/binary'), inventory, self.profile)

    def setUp(self):
        self.profile = T.resource_profile(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json'), 'paired', 'compact')
        self.plan = P.model(self.profile, 3)
        self.host = dict(physical_bytes=64*R.GIB, available_bytes=50*R.GIB, cgroup_memory_headroom=None,
                         scratch=dict(tmpfs=True, path='/tmp', device=50, capacity_bytes=32*R.GIB, available_bytes=30*R.GIB))
    def test_only_public_prefix_is_shared_and_all_private_peaks_remain_reserved(self):
        self.assertEqual(self.plan['shared_capacity_bytes'], 2*6710886400)
        opening = next(x for x in self.plan['phases'] if x['name']=='openings')
        self.assertEqual(opening['pool'], 'late')
        state = self.plan['worst_state']
        self.assertEqual(sorted(state), ['heavy','idle','late'])
        self.assertEqual(self.plan['fleet_payload_bytes'], self.plan['shared_capacity_bytes'] + sum(self.plan['private_bounds'][s] for s in state))
        self.assertGreaterEqual(self.plan['worker_cap_bytes'], self.plan['shared_capacity_bytes']+opening['private_bytes'])
        self.assertGreaterEqual(self.plan['fleet_spill_bytes'], self.plan['shared_capacity_bytes'] + sum(self.plan['private_spill_bounds'][s] for s in state))
    def test_fleet_limit_is_not_sum_of_owner_skew_caps(self):
        b=P.admit_host(self.host,self.plan)
        self.assertLess(b['fleet_bytes'],3*b['worker_bytes'])
        self.assertGreaterEqual(b['fleet_bytes'],self.plan['fleet_payload_bytes']+b['coordinator_bytes'])
    def test_host_ram_cgroup_and_tmpfs_each_admit_independently(self):
        for change in ('ram','cgroup','tmpfs','disk'):
            h=copy.deepcopy(self.host)
            if change=='ram': h['available_bytes']=38*R.GIB
            if change=='cgroup': h['cgroup_memory_headroom']=38*R.GIB
            if change=='tmpfs': h['scratch']['available_bytes']=20*R.GIB
            if change=='disk': h['scratch']['tmpfs']=False
            with self.subTest(change=change), self.assertRaises(ValueError): P.admit_host(h,self.plan)
    def test_unqualified_geometries_and_permit_counts_rejected(self):
        with self.assertRaises(ValueError): P.model(self.profile,5)
        with self.assertRaises(ValueError): P.model(self.profile,3,heavy=2)
        p=copy.deepcopy(self.profile);p['geometry']['preprocessing_columns']=201
        with self.assertRaises(ValueError):P.model(p,3)
    def test_environment_uses_only_linux_settings(self):
        schedule=P.schedule(self.plan,Path('/tmp/private-run'),2)
        env=P.environment(schedule)
        self.assertTrue(all(k.startswith('LATTICA_V2_') for k in env))
        self.assertEqual(env['LATTICA_V2_GPU_WORKERS'],'2')
        schedule['env']['PHASE_SLOTS']='2'
        with self.assertRaises(ValueError):P.environment(schedule)

    def test_four_workers_reserve_two_idle_workers_and_keep_phase_limits(self):
        plan = P.model(self.profile, 4)
        self.assertEqual(sorted(plan['worst_state']), ['heavy', 'idle', 'idle', 'late'])
        self.assertEqual(plan['fleet_payload_bytes'] - self.plan['fleet_payload_bytes'],
                         self.plan['idle_private_bytes'])
        # Current desktop headroom cannot safely reserve this entire bound.
        with self.assertRaises(ValueError): P.admit_host(self.host, plan)
        roomy = copy.deepcopy(self.host)
        roomy['available_bytes'] = 60 * R.GIB
        budget = P.admit_host(roomy, plan)
        self.assertGreaterEqual(budget['fleet_bytes'], plan['fleet_payload_bytes'] + budget['coordinator_bytes'])

    def test_explicit_capacity_test_retains_host_worker_and_tmpfs_safeguards(self):
        plan = P.model(self.profile, 4)
        budget = P.admit_host(self.host, plan, capacity_test_fleet_bytes=36 * R.GIB)
        self.assertEqual(budget['fleet_bytes'], 36 * R.GIB)
        self.assertEqual(budget['worker_bytes'], plan['worker_cap_bytes'])
        self.assertEqual(budget['swap_bytes'], 0)
        for cap in (0, -1, True, 20 * R.GIB, 45 * R.GIB):
            with self.subTest(cap=cap), self.assertRaises(ValueError):
                P.admit_host(self.host, plan, capacity_test_fleet_bytes=cap)
        for change in ('available', 'cgroup', 'tmpfs'):
            host = copy.deepcopy(self.host)
            if change == 'available': host['available_bytes'] = 40 * R.GIB
            if change == 'cgroup': host['cgroup_memory_headroom'] = 35 * R.GIB
            if change == 'tmpfs': host['scratch']['available_bytes'] = 20 * R.GIB
            with self.subTest(change=change), self.assertRaises(ValueError):
                P.admit_host(host, plan, capacity_test_fleet_bytes=36 * R.GIB)


class BackgroundGpuTests(unittest.TestCase):
    def test_only_known_browser_gpu_renderer_is_allowed(self):
        screen = importlib.import_module('block-v2-linux-phase-run')
        with tempfile.TemporaryDirectory() as root:
            proc_root = Path(root)
            process = proc_root / '42'
            process.mkdir()
            (process / 'exe').symlink_to('/opt/brave-bin/brave')
            for cmdline in (b'/opt/brave-bin/brave\0--type=gpu-process\0',
                            b'/opt/brave-bin/brave --type=gpu-process --other=1\0'):
                (process / 'cmdline').write_bytes(cmdline)
                self.assertTrue(screen.display_process(42, 'browser', proc_root))
            for cmdline in (b'/opt/brave-bin/brave\0--type=renderer\0',
                            b'/opt/brave-bin/brave\0--type=gpu-process-fake\0'):
                (process / 'cmdline').write_bytes(cmdline)
                self.assertFalse(screen.display_process(42, 'browser', proc_root))
            (process / 'cmdline').write_bytes(b'prover\0--type=gpu-process\0')
            (process / 'exe').unlink()
            (process / 'exe').symlink_to('/tmp/prover')
            self.assertFalse(screen.display_process(42, 'browser', proc_root))
            self.assertFalse(screen.display_process(43, 'browser', proc_root))


if __name__=='__main__': unittest.main()
