#!/usr/bin/env python3
"""Owned CLI admission failures; synthetic inputs do not qualify GPU runtime."""
import copy
import importlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import block_v2_owned_cli as O

M = importlib.import_module('block-v2-typed-multi-gpu-run')
S = importlib.import_module('block-v2-typed-shared-gpu-run')
GIB = 1 << 30
UUID = 'GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c'


class OwnedAdmission(unittest.TestCase):
    def setUp(self):
        self.host = dict(physical_bytes=64*GIB, available_bytes=48*GIB,
            cpu_capacity='8', effective_cpus=list(range(8)), cgroup_memory_headroom=None,
            scratch=dict(path='/tmp', device=42, tmpfs=True, quota_bytes=None,
                         capacity_bytes=16*GIB, available_bytes=8*GIB, page_bytes=4096))
        self.device = dict(uuid=UUID,
            nvidia=dict(uuid=UUID, total_bytes=16*GIB, free_bytes=13*GIB, driver='test'),
            opencl=dict(uuid=UUID, global_bytes=16*GIB, max_allocation_bytes=4*GIB, driver='test'))
        self.profile = M.T.resource_profile(O.WORKLOAD, 'paired', 'owned')

    def plan(self, **kwargs):
        return M.plan_budgets(self.host, [self.device], self.profile, **kwargs)[UUID]

    def test_owned_known_reservations_fit_fixed_limits_without_legacy_admission(self):
        with patch.object(M.T, 'admit_budget', side_effect=AssertionError('legacy floor')):
            budget = self.plan()
        self.assertEqual([budget['host'][k] for k in ['worker_bytes', 'coordinator_bytes', 'fleet_bytes', 'spill_bytes']],
                         [3*GIB, GIB, 4*GIB, GIB])
        self.assertEqual([budget['gpu'][k] for k in ['managed_bytes', 'context_bytes', 'headroom_bytes']],
                         [7*GIB, 4*GIB, GIB])
        self.assertEqual(budget['cpu']['allowed_cpus'], [0, 1, 2, 3])
        self.assertEqual(budget['cpu']['coordinator_capacity'], '4')
        self.assertEqual(budget['witness_reservation']['host_bytes'], 2057936284)
        self.assertEqual(budget['owned_quotient_reservation']['managed_bytes'], 5528092672)
        self.assertFalse(O.R.workload_failures(budget, self.profile))
        self.assertFalse(self.profile['complete_lifetime_qualified'])
        self.assertTrue(self.profile['owned_request_backing_includes_spill'])

    def test_generated_environment_enables_every_owned_stage(self):
        budget = self.plan()
        budget['unit'] = 'lattica-v2-multi-persistent-' + 'a'*64 + '.service'
        budget['proving_environment'] = {'LATTICA_PROVING_POLICY':'gpu-required', 'LATTICA_PROVING_REPORT':'1'}
        env = M.G.environment(budget, Path('/tmp/worker'))
        for stage in ['WITNESS', 'LOOKUP', 'QUOTIENT_EVAL', 'QUOTIENT_RESIDENT', 'OPENING_EVAL',
                      'FRI_RESIDENT', 'PCS_DEVICE_ONLY', 'RANDOMNESS', 'TRANSCRIPT']:
            self.assertEqual(env['LATTICA_V2_GPU_' + stage], '1')
        self.assertEqual(env['LATTICA_PROVING_POLICY'], 'gpu-required')
        self.assertEqual(env['LATTICA_SPILL_DIR'], budget['host']['scratch_path'])
        legacy = copy.deepcopy(budget); legacy['typed_ram_admission'] = 'compact'
        self.assertEqual(M.G.environment(legacy, Path('/tmp/worker'))['LATTICA_SPILL_DIR'], '/tmp/worker/scratch')

    def test_free_gpu_memory_and_device_allocation_are_not_relaxed(self):
        for parent, key, value in [('nvidia', 'free_bytes', 12*GIB-1),
                                   ('opencl', 'global_bytes', 12*GIB-1),
                                   ('opencl', 'max_allocation_bytes', GIB-1)]:
            with self.subTest(key=key):
                original = copy.deepcopy(self.device)
                self.device[parent][key] = value
                with self.assertRaises(ValueError): self.plan()
                self.device = original

    def test_device_identity_and_host_capacity_reject(self):
        for field, value in [('cpu_capacity', '3'), ('effective_cpus', [0, 1, 2]),
                             ('cgroup_memory_headroom', 4*GIB-1), ('available_bytes', 4*GIB)]:
            original = copy.deepcopy(self.host); self.host[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.plan()
            self.host = original
        self.device['opencl']['uuid'] = 'GPU-other'
        with self.assertRaises(ValueError): self.plan()

    def test_disk_quota_page_or_scratch_capacity_reject(self):
        for key, value in [('tmpfs', False), ('quota_bytes', 8*GIB), ('page_bytes', 8192),
                           ('available_bytes', GIB)]:
            original = copy.deepcopy(self.host); self.host['scratch'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.plan()
            self.host = original

    def test_changed_phase_geometry_and_boolean_types_reject(self):
        for field in ['heap_bytes', 'driver_host_bytes']:
            changed = copy.deepcopy(self.profile); changed['phases'][0][field] += 1
            with self.assertRaises(ValueError): M.plan_budgets(self.host, [self.device], changed)
        changed = copy.deepcopy(self.profile); changed['geometry']['gpu_witness'] = 1
        with self.assertRaises(ValueError): M.plan_budgets(self.host, [self.device], changed)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'workload.json'
            value = json.loads(O.WORKLOAD.read_text()); value['witness_bounds']['metadata_bytes'] -= 8
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError): O.resource_profile(path)

    def test_fixed_assignment_retains_limits_but_allows_live_occupancy_changes(self):
        budget = self.plan()
        assigned = dict(schema='lattica-typed-fleet-assignment-v1',
                        limits_by_gpu={UUID: M.T.resource_signature(budget)})
        self.device['nvidia']['free_bytes'] = 12*GIB
        self.plan(assignment=assigned)
        for group, key in [('host', 'worker_bytes'), ('host', 'spill_bytes'),
                           ('gpu', 'context_bytes'), ('cpu', 'rayon_threads')]:
            changed = copy.deepcopy(assigned); changed['limits_by_gpu'][UUID][group][key] -= 1
            with self.subTest(key=key), self.assertRaises(ValueError): self.plan(assignment=changed)

    def test_native_context_evidence_and_multiple_workers_do_not_qualify_cli(self):
        with self.assertRaises(ValueError): self.plan(calibrations={})
        with self.assertRaises(ValueError): M.plan_budgets(self.host, [self.device]*2, self.profile)

    def test_owned_command_requires_bounded_mode(self):
        for extra in [dict(pool_calibration=Path('/tmp/request')), dict(pool_timing_approval=['approval'])]:
            self.assertTrue(O.check_mode(SimpleNamespace(owned_public_gpu=True, gpu_uuid=[UUID], **extra)))
        with self.assertRaises(ValueError):
            O.check_mode(SimpleNamespace(owned_public_gpu=True, gpu_uuid=[UUID]))
        self.assertFalse(O.check_mode(SimpleNamespace()))
        args = S.argument_parser().parse_args(['--owned-public-gpu', '--pool-calibration', '/tmp/request', '--gpu-uuid', UUID])
        self.assertTrue(O.check_mode(args))

    def test_legacy_floor_and_other_registry_rejections_are_preserved(self):
        for kind in ['reference', 'finalized']:
            with self.assertRaises(ValueError): M.T.resource_profile(O.WORKLOAD, kind, 'owned')
        profile = M.T.resource_profile(Path(M.__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json'), 'paired', 'compact')
        self.assertEqual(M.T.minimum_ram(profile), 12457082880)
        with self.assertRaises(ValueError): M.T.admit_budget(self.plan(), profile)

    def test_recovery_reconstructs_pinned_owned_profile(self):
        config = dict(workload_path=str(O.WORKLOAD), pins={str(O.WORKLOAD):'pinned'}, workload_profile=self.profile)
        self.assertEqual(S.Calibration.source_profile(config, S), self.profile)
        config['workload_profile'] = copy.deepcopy(self.profile)
        config['workload_profile']['geometry']['gpu_witness'] = False
        with self.assertRaises(ValueError): S.Calibration.source_profile(config, S)


if __name__ == '__main__':
    unittest.main()
