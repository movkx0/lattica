import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import gpu_aggregation_memory as memory


class MemoryPolicyTests(unittest.TestCase):
    def test_auto_budget_keeps_reserve_headroom_and_physical_limit(self):
        G = memory.GIB
        self.assertEqual(memory.budget('auto', 16*G, int(15.1*G), 4*G), int(10.5*G))
        self.assertEqual(memory.budget('auto', 16*G, int(15.1*G), 2*G), 12*G)
        self.assertEqual(memory.budget('auto', 13*G, 16*G, 4*G), int(8.5*G))
        for request, total, free, reserve in [('12288', 16*G, 15*G, 4*G),
                ('auto', 12*G, 16*G, 4*G), ('8193', 16*G, 16*G, 2*G),
                ('8192', 16*G, 16*G, G)]:
            with self.subTest(request=request, reserve=reserve), self.assertRaises(RuntimeError):
                memory.budget(request, total, free, reserve)

    def certificate(self):
        return dict(schema='ringct-gpu-memory-qualification-v1', source_sha3='source',
            executable_sha3='exe', device_uuid='GPU-test', driver='driver', query_gather='batch',
            verified=True, max_rows=1 << 19, context_bytes=2*memory.GIB,
            opaque_peak_bytes=memory.GIB, geometries=[dict(rows=1 << 19, public_values=46)])

    def test_qualification_binds_source_binary_device_driver_and_geometry(self):
        value = self.certificate()
        binding = {k:value[k] for k in ('source_sha3','executable_sha3','device_uuid','driver')}
        self.assertEqual(memory.validate_certificate(value, binding, 'batch'), (2*memory.GIB,1 << 19))
        for key, changed in [('source_sha3','other'), ('executable_sha3','other'), ('driver','other'),
                ('device_uuid','other'), ('query_gather','scalar'), ('verified',False),
                ('opaque_peak_bytes',2*memory.GIB), ('context_bytes',memory.GIB), ('geometries',[])]:
            bad = dict(value, **{key:changed})
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                memory.validate_certificate(bad,binding,'batch')

    def test_prepare_resolves_once_using_opencl_and_current_free_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            executable=Path(tmp)/'worker';executable.write_bytes(b'qualified executable')
            plan=dict(command=[str(executable)], environment=dict(LATTICA_GPU_DEVICE_UUID='GPU-test'),
                gpu_aggregation=dict(profile='grouped-v4',command='screen',values={}))
            physical=dict(source_sha3='source',device=dict(uuid='GPU-test',driver='driver',
                global_bytes=16*memory.GIB,max_allocation_bytes=4*memory.GIB))
            with patch.object(memory,'inventory',return_value=dict(device_uuid='GPU-test',driver='driver',free_bytes=15*memory.GIB)), \
                    patch.object(memory.subprocess,'run',return_value=SimpleNamespace(stdout='GPU_AGGREGATION_DEVICE '+json.dumps(physical))):
                memory.prepare(plan,{})
            self.assertEqual(plan['gpu_aggregation']['memory']['managed_bytes'],int(10.5*memory.GIB))
            self.assertEqual(json.loads(plan['environment']['LATTICA_V2_GPU_AGGREGATION_MEMORY']),plan['gpu_aggregation']['memory'])

    def test_legacy_and_native_preparation_do_not_change_memory_environment(self):
        for profile,command in [('grouped-v3','screen'),('grouped-v4','prepare-inputs')]:
            plan=dict(environment={'original':'value'},gpu_aggregation=dict(profile=profile,command=command))
            with patch.object(memory,'inventory',side_effect=AssertionError('unexpected device query')):
                memory.prepare(plan,{})
            self.assertEqual(plan['environment'],{'original':'value'})

    def test_merge_keeps_worst_observation_and_union_of_geometries(self):
        with tempfile.TemporaryDirectory() as tmp:
            a,b=self.certificate(),self.certificate()
            b.update(opaque_peak_bytes=int(1.75*memory.GIB),geometries=[dict(rows=1 << 18,public_values=64)])
            for item,name in [(a,'a'),(b,'b')]:
                item.update(managed_bytes_tested=8*memory.GIB,checkpoints=[])
                Path(tmp,name).write_text(json.dumps(item))
            value=memory.merge_qualifications([Path(tmp,'a'),Path(tmp,'b')],Path(tmp,'out'))
            self.assertEqual(value['context_bytes'],int(2.25*memory.GIB))
            self.assertEqual(len(value['geometries']),2)
            with self.assertRaises(FileExistsError):
                memory.merge_qualifications([Path(tmp,'a')],Path(tmp,'out'))

    def test_publication_requires_success_and_terminal_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp,'qualification')
            plan=dict(status='failed_or_incomplete',gpu_memory_qualification=self.certificate(),
                gpu_aggregation=dict(values={'--output':str(output)}))
            memory.publish(plan);self.assertFalse(output.exists())
            plan['status']='passed'
            with self.assertRaises(RuntimeError):memory.publish(plan)
            plan.update(source_inputs_unchanged=True,executable_unchanged=True,all_subprocesses_terminal_and_reaped=True)
            memory.publish(plan);self.assertEqual(json.loads(output.read_text()),self.certificate())


if __name__ == '__main__':
    unittest.main()
