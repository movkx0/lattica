#!/usr/bin/env python3
import copy
import importlib
from pathlib import Path
import unittest
import block_v2_phase_memory as P
import block_v2_resources as R
T = importlib.import_module('block-v2-typed-gpu-run')

class PhaseMemoryTests(unittest.TestCase):
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
        with self.assertRaises(ValueError): P.model(self.profile,4)
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

if __name__=='__main__': unittest.main()
