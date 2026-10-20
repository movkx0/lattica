"""Controller admission tests; synthetic devices/libraries do not qualify CUDA."""
import copy
import importlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import block_v2_cuda_cli as C
import block_v2_pool_timing as Timing
import block_v2_resources as R

M = importlib.import_module('block-v2-typed-multi-gpu-run')
S = importlib.import_module('block-v2-typed-shared-gpu-run')
O = importlib.import_module('block_v2_owned_cli')
UUID = 'GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c'
GIB = 1 << 30


class CudaAdmission(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        for name in ['libnvrtc.so', 'libnvrtc-builtins.so.12.9']:
            (self.directory/name).write_bytes(b'synthetic library')
        self.binary = self.directory/'probe'; self.binary.write_bytes(b'synthetic executable')
        self.host = dict(physical_bytes=64*GIB, available_bytes=48*GIB,
            cpu_capacity='8', effective_cpus=list(range(8)), cgroup_memory_headroom=None,
            scratch=dict(path='/tmp', device=42, tmpfs=True, quota_bytes=None,
                         capacity_bytes=16*GIB, available_bytes=8*GIB, page_bytes=4096))
        self.device = dict(backend='cuda', uuid=UUID,
            nvidia=dict(uuid=UUID, name='Synthetic', total_bytes=16*GIB, free_bytes=13*GIB,
                        driver='test', pci='00000000:01:00.0'),
            cuda=dict(uuid=UUID, global_bytes=16*GIB, compute_capability=120,
                      driver_api=12090, pci='0000:01:00.0'))
        self.profile = M.T.resource_profile(C.WORKLOAD, 'paired', 'owned', backend='cuda')

    def plan(self, **kwargs):
        return M.plan_budgets(self.host, [self.device], self.profile, **kwargs)[UUID]

    def configured(self):
        budget = self.plan()
        budget.update(unit='lattica-v2-multi-persistent-'+'a'*64+'.service',
                      cuda_runtime=C.runtime(self.directory),
                      proving_environment={'LATTICA_PROVING_POLICY':'gpu-required', 'LATTICA_PROVING_REPORT':'1'})
        return budget

    def test_inventory_has_explicit_cuda_metadata_and_matches_pci_uuid(self):
        inventory = {'schema':'lattica-gpu-inventory-v1','backend':'cuda','devices':[self.device['cuda']]}
        nvidia = f'{UUID}, Synthetic, 16384, 13312, test, 00000000:01:00.0\n'
        with patch.object(R, 'command_json', return_value=inventory), patch.object(R.subprocess, 'check_output', return_value=nvidia):
            devices = R.detect_gpus(self.binary)
            self.assertEqual(devices, [self.device])
            self.assertNotIn('opencl', devices[0])
            inventory['devices'][0]['pci'] = '0000:02:00.0'
            with self.assertRaises(ValueError): R.detect_gpus(self.binary)

    def test_inventory_rejects_unknown_envelopes_duplicate_uuid_and_invalid_types(self):
        inventory = {'schema':'lattica-gpu-inventory-v1','backend':'cuda','devices':[self.device['cuda']]}
        nvidia = f'{UUID}, Synthetic, 16384, 13312, test, 00000000:01:00.0\n'
        for change in [dict(backend='auto'),dict(schema='unknown'),dict(devices=[self.device['cuda']]*2),dict(devices=True)]:
            with patch.object(R, 'command_json', return_value=inventory|change), patch.object(R.subprocess, 'check_output', return_value=nvidia):
                with self.assertRaises(ValueError): R.detect_gpus(self.binary)
        for key in ['global_bytes','compute_capability','driver_api']:
            bad=copy.deepcopy(self.device);bad['cuda'][key]=True
            with self.assertRaises(ValueError): R.gpu_budget(bad)

    def test_owned_cuda_does_not_import_opencl_reservations(self):
        with patch.object(R, 'workload_failures', side_effect=AssertionError('OpenCL phase model')):
            budget = self.plan()
        self.assertEqual([budget['host'][k] for k in ['worker_bytes','coordinator_bytes','fleet_bytes','spill_bytes']],
                         [3*GIB,GIB,4*GIB,GIB])
        self.assertEqual([budget['gpu'][k] for k in ['managed_bytes','context_bytes','headroom_bytes','max_allocation_bytes']],
                         [7*GIB,4*GIB,GIB,GIB])
        self.assertEqual(budget['gpu']['host_output_bytes'],3*GIB)
        self.assertEqual(budget['cuda']['input_values'],1<<20)
        self.assertFalse(any(k in budget for k in ['witness_reservation','randomness_reservation','transcript_reservation']))

    def test_small_memory_old_architecture_driver_and_context_calibration_reject(self):
        for group,key,value in [('nvidia','free_bytes',12*GIB-1),('cuda','global_bytes',12*GIB-1),
                                ('cuda','compute_capability',61),('cuda','driver_api',12080)]:
            original=copy.deepcopy(self.device);self.device[group][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.plan()
            self.device=original
        with self.assertRaises(ValueError):self.plan(calibrations={})
        with self.assertRaises(ValueError):R.gpu_budget(self.device, {'backend':'opencl'})
        with self.assertRaises(ValueError):R.plan(self.host,[self.device],1,self.profile)

    def test_larger_devices_keep_the_existing_headroom_margin(self):
        self.device['cuda']['global_bytes']=32*GIB
        self.device['nvidia'].update(total_bytes=32*GIB,free_bytes=30*GIB)
        budget=self.plan();self.assertGreater(budget['gpu']['headroom_bytes'],GIB)
        self.device['nvidia']['free_bytes']=11*GIB+budget['gpu']['headroom_bytes']-1
        with self.assertRaises(ValueError):self.plan()

    def test_host_scratch_and_construction_bounds_are_not_relaxed(self):
        for key,value in [('cpu_capacity','3'),('effective_cpus',[0,1,2]),('cgroup_memory_headroom',4*GIB-1)]:
            original=copy.deepcopy(self.host);self.host[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.plan()
            self.host=original
        for key in ['program_host_bytes','wires','input_values']:
            original=copy.deepcopy(self.profile);self.profile['cuda'][key]+=1
            with self.subTest(key=key),self.assertRaises(ValueError):self.plan()
            self.profile=original
        self.host['scratch']['tmpfs']=False
        with self.assertRaises(ValueError):self.plan()

    def test_fixed_assignment_binds_backend_driver_and_construction(self):
        limits=M.T.resource_signature(self.plan())
        assigned={'schema':'lattica-typed-fleet-assignment-v1','limits_by_gpu':{UUID:limits}}
        self.device['nvidia']['free_bytes']=14*GIB
        self.plan(assignment=assigned)
        for key,value in [('backend','opencl'),('cuda',{}),('drivers',{'nvidia':'other'})]:
            changed=copy.deepcopy(assigned);changed['limits_by_gpu'][UUID][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.plan(assignment=changed)

    def test_runtime_is_pinned_and_passed_without_opencl_switches(self):
        budget=self.configured();env=M.G.environment(budget,self.directory)
        self.assertEqual(env['LD_LIBRARY_PATH'],str(self.directory))
        self.assertEqual(env['LATTICA_SPILL_DIR'],'/tmp')
        self.assertEqual({k for k in env if k.startswith('LATTICA_V2_GPU_')},
                         {'LATTICA_V2_GPU_MANAGED_BYTES','LATTICA_V2_GPU_CONTEXT_BYTES'})
        (self.directory/'libnvrtc-builtins.so.12.9').write_bytes(b'changed')
        with self.assertRaises(ValueError):M.G.environment(budget,self.directory)

    def test_runtime_symlink_escape_and_missing_stage_reports_reject(self):
        budget=self.configured();budget['proving_environment']['LATTICA_PROVING_REPORT']='0'
        with self.assertRaises(ValueError):M.G.environment(budget,self.directory)
        (self.directory/'libnvrtc.so').unlink();(self.directory/'libnvrtc.so').symlink_to('/bin/true')
        with self.assertRaises(ValueError):C.runtime(self.directory)

    def test_timing_identity_distinguishes_cuda_and_binds_library_hashes(self):
        budget=self.configured();env=M.G.environment(budget,self.directory)
        binding=Timing.binding(self.binary,self.device,budget,self.profile,env)
        self.assertEqual(binding['backend'],'cuda');self.assertNotIn('opencl',binding['drivers'])
        self.assertEqual(binding['drivers']['cuda_driver_api'],12090)
        self.assertNotEqual(Timing.fingerprints(binding),Timing.fingerprints(binding|{'backend':'opencl'}))
        with self.assertRaises(ValueError):Timing.binding(self.binary,self.device,budget,self.profile,env|{'LD_LIBRARY_PATH':'/other'})
        with self.assertRaises(ValueError):Timing.binding(self.binary,self.device,budget,self.profile|{'backend':'opencl'},env)

    def test_cli_requires_explicit_cuda_owned_bounded_mode(self):
        args=SimpleNamespace(gpu_backend='cuda',cuda_library_path=self.directory,owned_public_gpu=True,gpu_uuid=[UUID],pool_calibration=self.directory/'request')
        self.assertTrue(O.check_mode(args))
        for key,value in [('owned_public_gpu',False),('cuda_library_path',None),('calibration_trial',['old'])]:
            changed=copy.copy(args);setattr(changed,key,value)
            with self.subTest(key=key),self.assertRaises(ValueError):O.check_mode(changed)
        parsed=S.argument_parser().parse_args(['--gpu-backend','cuda','--cuda-library-path',str(self.directory),'--owned-public-gpu','--gpu-uuid',UUID,'--pool-calibration','/tmp/request'])
        self.assertTrue(O.check_mode(parsed))

    def test_recovery_retains_backend_and_capacity_profile(self):
        for capacity in [64,128]:
            path=C.workload_path(capacity);profile=C.resource_profile(path,capacity)
            config=dict(workload_path=str(path),pins={str(path):'pinned'},workload_profile=profile)
            self.assertEqual(S.Calibration.source_profile(config,S),profile)
        with self.assertRaises(ValueError):M.T.resource_profile(C.WORKLOAD,'paired','owned')

    def test_dedicated_scope_requires_bounded_owned_mode_and_preserves_names(self):
        scope=S.PoolScope
        self.addCleanup(scope.configure,None,M.G,Timing)
        name='lattica-v2-multi-cuda-pool-test.slice'
        args=SimpleNamespace(fleet_slice=name,owned_public_gpu=True,pool_calibration='/request')
        scope.select(args,M.G,Timing)
        self.assertEqual(M.G.SLICE,name)
        self.assertEqual(Timing.COORDINATOR_SLICE,'lattica-v2-multi-cuda-pool-test-coordinator.slice')
        self.assertEqual(self.plan()['slice'],name)
        for invalid in ['other.slice','../lattica-v2-multi-x.slice','lattica-v2-multi-.slice',
                        'lattica-v2-multi-x--y.slice','lattica-v2-multi-coordinator.slice']:
            with self.subTest(invalid=invalid),self.assertRaises(ValueError):scope.validate(invalid)
        args.owned_public_gpu=False
        with self.assertRaises(ValueError):scope.select(args,M.G,Timing)

    def test_shared_launcher_propagates_scope_to_controller_and_owner_modules(self):
        self.addCleanup(S.configure_fleet_scope, None)
        name='lattica-v2-multi-cuda-pool-test.slice'
        args=SimpleNamespace(fleet_slice=name,owned_public_gpu=True,pool_calibration='/request')
        S.select_fleet_scope(args)
        for gpu in (M.G,S.G,S.Controller.G,S.Bootstrap.G):
            self.assertEqual(gpu.SLICE,name)
        self.assertEqual(Timing.COORDINATOR_SLICE,name.removesuffix('.slice')+'-coordinator.slice')
        args.fleet_slice=None
        S.select_fleet_scope(args)
        for gpu in (M.G,S.G,S.Controller.G,S.Bootstrap.G):
            self.assertEqual(gpu.SLICE,S.PoolScope.DEFAULT)

    def test_completion_rejects_missing_cuda_work_wrong_counts_and_retained_owners(self):
        budget=self.plan();budget['pool_job_limit']=4
        stats=dict.fromkeys(['live_bytes','allocations','modules','pending_commands','public_program_bytes','public_programs'],0)
        stats.update(peak_bytes=8,completed_commands=1,uploaded_bytes=8,downloaded_bytes=8)
        event=dict(backend='cuda',cpu_only=False,owned_public_worker=True,production_ready=False,recursive_proofs=4,cuda=stats)
        C.validate_completion(event,budget,4)
        with self.assertRaises(ValueError):C.validate_completion(event,budget,3)
        with self.assertRaises(ValueError):C.validate_completion(event|{'backend':'opencl'},budget,4)
        with self.assertRaises(ValueError):C.validate_completion(event|{'recursive_proofs':5},budget)
        for key in ['live_bytes','modules','pending_commands','public_program_bytes']:
            with self.subTest(key=key),self.assertRaises(ValueError):
                C.validate_completion(event|{'cuda':stats|{key:1}},budget)
        for value in [True,0,8*GIB]:
            with self.subTest(value=value),self.assertRaises(ValueError):
                C.validate_completion(event|{'cuda':stats|{'peak_bytes':value}},budget)
        pooled = stats | dict(event_pairs=0, peak_event_pairs=2,
                              event_pairs_created=2, event_pairs_reused=16)
        C.validate_completion(event | {'cuda': pooled}, budget, 4)
        for key in ['event_pairs', 'peak_event_pairs', 'event_pairs_created', 'event_pairs_reused']:
            missing = dict(pooled); del missing[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                C.validate_completion(event | {'cuda': missing}, budget)
            for value in [True, -1, '0']:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    C.validate_completion(event | {'cuda': pooled | {key: value}}, budget)
        for changed in [dict(event_pairs=1), dict(peak_event_pairs=65)]:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                C.validate_completion(event | {'cuda': pooled | changed}, budget)


if __name__=='__main__':unittest.main()
