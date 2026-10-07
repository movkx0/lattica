#!/usr/bin/env python3
"""Synthetic controller checks; no GPU qualification is inferred from them."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('matrix',Path(__file__).with_name('block-v2-typed-count-matrix.py'))
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)


class CountMatrix(unittest.TestCase):
    def test_selection_requires_explicit_unique_counts_and_devices(self):
        self.assertEqual(M.validate_selection([1,2],['GPU-a','GPU-b']),
                         [(1,'GPU-a'),(1,'GPU-b'),(2,'GPU-a'),(2,'GPU-b')])
        for counts,uuids in (([],['GPU-a']),([4,4],['GPU-a']),([7],['GPU-a']),
                             ([True],['GPU-a']),([1],[]),([1],['GPU-a','GPU-a']),([1],['0'])):
            with self.assertRaises(ValueError):M.validate_selection(counts,uuids)

    def test_subsets_never_establish_complete_count_coverage(self):
        trials=[{'count':4,'gpu_uuid':'GPU-a','cpu_audited':True}]
        result=M.coverage([4],['GPU-a'],trials)
        self.assertTrue(result['all_requested_counts_passed'])
        self.assertFalse(result['all_required_counts_passed'])
        result=M.coverage(list(M.T.COUNTS),['GPU-a','GPU-b'],trials)
        self.assertEqual(result['completed'],1)
        self.assertEqual(len(result['pending']),17)
        self.assertFalse(result['all_required_counts_passed'])

    def test_missing_or_duplicate_device_count_cannot_qualify(self):
        for trials in ([{'count':4,'gpu_uuid':'GPU-a','cpu_audited':False}],
                       [{'count':4,'gpu_uuid':'GPU-b','cpu_audited':True}],
                       [{'count':4,'gpu_uuid':'GPU-a','cpu_audited':True}]*2):
            with self.assertRaises(ValueError):M.coverage([4],['GPU-a'],trials)

    def test_every_required_count_is_checked_on_each_selected_device(self):
        trials=[{'count':c,'gpu_uuid':u,'cpu_audited':True} for c in M.T.COUNTS for u in ('GPU-a','GPU-b')]
        result=M.coverage(list(M.T.COUNTS),['GPU-a','GPU-b'],trials)
        self.assertTrue(result['all_required_counts_passed'])
        self.assertEqual(result['pending'],[])
        result=M.coverage(list(M.T.COUNTS),['GPU-a','GPU-b'],trials[:-1])
        self.assertEqual(result['pending'],[{'count':64,'gpu_uuid':'GPU-b'}])

    def test_reusing_a_root_requires_its_exact_fixture_profile_auditor_and_gpu(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);worker=root/'001-typed';worker.mkdir();fixture=root/'fixture';fixture.mkdir()
            for name in (*M.T.public_names('paired'),'wallet.0'):
                (fixture/name).write_text('262144' if name=='height.json' else 'synthetic-'+name)
            cpu=root/'cpu';cpu.write_text('synthetic CPU binary')
            profile=M.T.resource_profile(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json'),'paired','compact')
            config={'fixture':str(fixture),'workload':profile,'cpu_binary':str(cpu),
                    'pins':{str(p):M.G.digest(p) for p in (cpu,*fixture.iterdir())}}
            (root/'config.json').write_text(json.dumps(config))
            result={'count':1,'profile_sha256':M.G.profile_digest(config),
                    'budget':{'gpu':{'uuid':'GPU-a'}},'artifacts':{}}
            (worker/'result.json').write_text(json.dumps(result))
            (root/'summary.json').write_text(json.dumps({'attempt':{'uuid':'GPU-a'}}))
            pins={p.name:M.G.digest(p) for p in fixture.iterdir()}
            checked={'context_measurement':{'uuid':'GPU-a'},'cpu_audited':True}
            args=(root,'paired',profile,'GPU-hash',M.G.digest(cpu),pins)
            with patch.object(M.F,'calibration_assignment',return_value=({},None,[])), \
                 patch.object(M.C,'checked_trial',side_effect=lambda *a:dict(checked)):
                self.assertEqual(M.checked_trial(*args)['count'],1)
                changed={**pins,'wallet.0':'changed'}
                with self.assertRaises(ValueError):M.checked_trial(*args[:-1],changed)
                result['budget']['gpu']['uuid']='GPU-b';(worker/'result.json').write_text(json.dumps(result))
                with self.assertRaisesRegex(ValueError,'GPU identity'):M.checked_trial(*args)
                result['profile_sha256']='different';(worker/'result.json').write_text(json.dumps(result))
                with self.assertRaisesRegex(ValueError,'profile'):M.checked_trial(*args)
                cpu.write_text('different auditor')
                with self.assertRaises(ValueError):M.checked_trial(*args)


if __name__=='__main__':unittest.main()
