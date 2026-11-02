import copy
import json
import unittest
from unittest.mock import patch
import opencl_private_spend_validate as runner
from test_opencl_private_spend_validate import arguments
from native_metadata_profile import validate

class NativeMetadataProfileTests(unittest.TestCase):
    def test_exact_cpu_profile_and_physical_workers_are_required(self):
        command=['/tmp/native-profile','component_tree::native_shape::profiling::tests::native_metadata_profile',
                 '--exact','--ignored','--test-threads=1','--nocapture']
        args=arguments(profile='research-compile-large',expect_tests=True,build_label='build',command=command)
        args.native_metadata_profile=True
        with patch.object(runner,'identity_physical_cpus',return_value=list(range(16))):
            plan=runner.build_plan(args)
            self.assertEqual(plan['cpu_quota'],'1600%')
            self.assertEqual(plan['memory_max_bytes'],32 << 30)
            self.assertEqual(plan['environment']['LATTICA_PROVING_POLICY'],'cpu-required')
            self.assertEqual(plan['environment']['RAYON_NUM_THREADS'],'2')
            args.command=command[:1]+['another-test']+command[2:]
            with self.assertRaises(ValueError): runner.build_plan(args)
            args.command=command; args.metadata_cpu_qualification=True
            with self.assertRaises(ValueError): runner.build_plan(args)

    def fixture(self):
        families=['aes','shake','transcript','sparse','uniform','statement','private','affine','ntt','mul','g_bound','permutation','linear_map']
        cold=dict(preflight_ns=1,key_ns=1,lookup_ns=1,periodic_ns=1,symbolic_ns=1,lowering_ns=1,finalization_ns=1)
        warm={k:(1 if k in ['preflight_ns','key_ns','lookup_ns'] else 0) for k in cold}
        rows=[dict(name=str(i),family=families[i%13],key=[i]+[0]*31,values=[1]*8,geometry=[1]*5,
                   cold_ns=10,warm_total_ns=10,warm_calls=8,cold_phases=cold.copy(),warm_phases=warm.copy(),
                   original_host_bytes=2 << 30,counts_equal=True) for i in range(39)]
        summary=dict(cases=39,gpu_used=False,cold_ns=390,warm_total_ns=390,fingerprint_cold_ns=1,
                     fingerprint_warm_ns=1,catalogue_ns=1,original_host_bytes_peak=2 << 30,
                     cache=dict(hits=312,misses=39,entries=39,evictions=0,failed_computations=0,reserved_host_bytes=2 << 20))
        return rows,summary
    def text(self,rows,summary):
        return '\n'.join('NATIVE_METADATA_PROFILE_ROW '+json.dumps(r) for r in rows)+'\nNATIVE_METADATA_PROFILE '+json.dumps(summary)
    def test_receipts_refuse_overlap_duplicate_keys_gpu_and_warm_compilation(self):
        rows,summary=self.fixture(); validate(self.text(rows,summary))
        for mutate in [lambda r,s:r[0]['warm_phases'].update(lowering_ns=1),
                       lambda r,s:r[0]['cold_phases'].update(lowering_ns=20),
                       lambda r,s:r[0].update(key=r[1]['key']),
                       lambda r,s:s.update(gpu_used=True),lambda r,s:s['cache'].update(hits=1)]:
            bad,bads=copy.deepcopy(rows),copy.deepcopy(summary);mutate(bad,bads)
            with self.assertRaises(ValueError):validate(self.text(bad,bads))

    def test_pcs_substages_are_complete_and_do_not_overlap(self):
        rows, summary = self.fixture()
        rows[0]['lowering_phases'] = dict(setup_ns=0, pcs_ns=1, selectors_ns=0,
            periodic_ns=0, quotient_ns=0, constraints_ns=0, pcs_setup_ns=0,
            pcs_query_ns=0, pcs_opening_ns=1, pcs_reduction_ns=0, pcs_folding_ns=0)
        validate(self.text(rows,summary))
        rows[0]['lowering_phases']['pcs_folding_ns'] = 1
        with self.assertRaises(ValueError): validate(self.text(rows,summary))
        del rows[0]['lowering_phases']['pcs_folding_ns']
        with self.assertRaises(ValueError): validate(self.text(rows,summary))

    def test_periodic_substages_are_complete_and_disjoint(self):
        rows, summary = self.fixture()
        phases = ['setup_ns','pcs_ns','selectors_ns','periodic_ns','quotient_ns','constraints_ns',
                  'pcs_setup_ns','pcs_query_ns','pcs_opening_ns','pcs_reduction_ns','pcs_folding_ns',
                  'periodic_specialization_ns','periodic_interpolation_ns','periodic_emission_ns']
        rows[0]['lowering_phases'] = dict.fromkeys(phases, 0)
        detail = rows[0]['lowering_phases']
        detail.update(periodic_ns=1, periodic_emission_ns=1)
        validate(self.text(rows, summary))
        detail['periodic_interpolation_ns'] = 1
        with self.assertRaises(ValueError): validate(self.text(rows, summary))
        del detail['periodic_emission_ns']
        with self.assertRaises(ValueError): validate(self.text(rows, summary))
