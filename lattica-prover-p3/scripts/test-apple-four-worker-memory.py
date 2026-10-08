#!/usr/bin/env python3
"""Acceptance and conditional-follow-up checks; no proving work."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
import json
spec=importlib.util.spec_from_file_location('four_memory',Path(__file__).with_name('report-apple-four-worker-memory.py'))
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
class Acceptance(unittest.TestCase):
    def row(self):
        return dict(valid=True,audited=True,rate=225.,failure=None,resources=dict(pressure_levels=[1],swap_growth_bytes=0,compressor_growth_bytes=2*M.GIB))
    def test_interleaved_progress_does_not_erase_complete_peak(self):
        interrupted = 'metal_worker_memory_progress pid=64980 elapsed_ms=host_timeline_interval thread=0 name="verify"'
        self.assertIsNone(M.memory_sample(interrupted))
        complete = 'metal_worker_memory peak_rss_bytes=100 peak_footprint_bytes=200 sample_ms=500 gpu_bytes_overlap_process_memory=true'
        self.assertEqual(M.memory_sample(complete), dict(peak=200,final=True))
        progress = 'metal_worker_memory_progress pid=1 peak_footprint_bytes=150 sample_ms=500'
        self.assertEqual(M.memory_sample(progress), dict(peak=150,final=False))

    def test_five_worker_evidence_requires_all_distinct_audits_and_proofs(self):
        workers = [dict(index=i, proofs=7) for i in range(5)]
        window = dict(jobs=[dict(index=i, verified=True) for i in range(5)])
        self.assertTrue(M.audited_jobs(window, workers, 5))
        self.assertFalse(M.audited_jobs(dict(jobs=window['jobs'][:4]), workers, 5))
        self.assertFalse(M.audited_jobs(window, workers[:4], 5))
        duplicate = copy.deepcopy(window); duplicate['jobs'][-1]['index'] = 0
        self.assertFalse(M.audited_jobs(duplicate, workers, 5))
        unaudited = copy.deepcopy(window); unaudited['jobs'][-1]['verified'] = False
        self.assertFalse(M.audited_jobs(unaudited, workers, 5))
        imbalanced = copy.deepcopy(workers); imbalanced[0]['proofs'] = 8; imbalanced[-1]['proofs'] = 6
        self.assertFalse(M.audited_jobs(window, imbalanced, 5))
        self.assertTrue(M.audited_jobs(dict(jobs=window['jobs'][:4]), workers[:4], 4))

    def test_acceptance_and_throughput_boundary(self):
        r=self.row();self.assertTrue(M.decision(r,250)['accepted'])
        r['rate']=224.99;d=M.decision(r,250);self.assertFalse(d['accepted']);self.assertEqual(d['followup'],'query_two_gib')
    def test_memory_failure_takes_precedence_over_low_throughput(self):
        for change in [dict(pressure_levels=[1,2]),dict(swap_growth_bytes=1),dict(compressor_growth_bytes=6*M.GIB+1)]:
            r=self.row();r['rate']=100;r['resources'].update(change)
            self.assertEqual(M.decision(r,250)['followup'],'late_one')
        r=self.row();r.update(valid=False,audited=False,rate=None,failure='memory pressure invalidates screen');r['resources']['pressure_levels']=[1,2]
        self.assertEqual(M.decision(r,250)['followup'],'late_one')
    def test_correctness_failure_does_not_trigger_full_rerun(self):
        r=self.row();r.update(valid=False,audited=False,rate=None,failure='audit failed')
        d=M.decision(r,250);self.assertFalse(d['accepted']);self.assertIsNone(d['followup'])
    def test_resources_count_growth_not_existing_swap(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'resources.jsonl'
            rows=[]
            for i,compressor in enumerate([100,300,150]):
                rows.append(dict(monotonic=float(i),aggregate_rss=(i+1)*10,swap_used_bytes=20,pressure=1,
                    vm_stat=f'Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages occupied by compressor: {compressor}.\n'))
            p.write_text(''.join(json.dumps(r)+'\n' for r in rows));r=M.resource_summary(p)
            self.assertEqual(r['swap_growth_bytes'],0);self.assertEqual(r['compressor_growth_bytes'],200*16384)
            self.assertEqual(r['aggregate_peak_rss_bytes'],30)
if __name__=='__main__':unittest.main()
