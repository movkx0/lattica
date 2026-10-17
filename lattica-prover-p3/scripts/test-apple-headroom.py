#!/usr/bin/env python3
"""Headroom acceptance thresholds and resource accounting; no benchmarks."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('headroom',Path(__file__).with_name('report-apple-headroom.py'))
H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)

class Headroom(unittest.TestCase):
    def setUp(self):
        self.baseline=dict(transaction_equivalents_per_hour=230,worst_worker_peak_footprint_bytes=1000,
                           resources=dict(compressor_growth_bytes=1000))
        self.candidate=dict(valid=True,transaction_equivalents_per_hour=207,worst_worker_peak_footprint_bytes=850,
                            resources=dict(compressor_growth_bytes=999))

    def test_exact_ten_percent_and_fifteen_percent_boundaries(self):
        self.assertTrue(H.evaluate(self.baseline,self.candidate)['accepted'])
        for delta in [dict(transaction_equivalents_per_hour=206.99),dict(worst_worker_peak_footprint_bytes=851)]:
            self.assertFalse(H.evaluate(self.baseline,{**self.candidate,**delta})['accepted'])
        self.assertFalse(H.evaluate(self.baseline,{**self.candidate,'resources':dict(compressor_growth_bytes=1000)})['accepted'])

    def test_followup_only_for_more_headroom_at_acceptable_throughput(self):
        self.assertFalse(H.evaluate(self.baseline,self.candidate)['conditional_followup_eligible'])
        self.assertTrue(H.evaluate(self.baseline,{**self.candidate,'worst_worker_peak_footprint_bytes':851})['conditional_followup_eligible'])
        self.assertFalse(H.evaluate(self.baseline,{**self.candidate,'transaction_equivalents_per_hour':206.99,'worst_worker_peak_footprint_bytes':851})['conditional_followup_eligible'])

    def test_pressure_stop_is_eligible_but_proof_failure_is_not(self):
        for failure,eligible in [('memory pressure invalidates screen',True),('proof failed',False)]:
            r=H.evaluate(self.baseline,{**self.candidate,'valid':False,'failure':failure,
                                        'transaction_equivalents_per_hour':None,'worst_worker_peak_footprint_bytes':None})
            self.assertFalse(r['accepted'])
            self.assertEqual(r['conditional_followup_eligible'],eligible)

    def test_compressor_physical_growth_excludes_preexisting_usage(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'resources.jsonl'
            rows=[]
            for compressed,free in [(5,10),(7,8),(6,11)]:
                rows.append(dict(vm_stat=f'Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: {free}.\nPages occupied by compressor: {compressed}.\nPages stored in compressor: 100.\n'))
            path.write_text(''.join(json.dumps(row)+'\n' for row in rows))
            r=H.resource_metrics(path)
            self.assertEqual(r['compressor_initial_bytes'],5*16384)
            self.assertEqual(r['compressor_peak_bytes'],7*16384)
            self.assertEqual(r['compressor_growth_bytes'],2*16384)
            self.assertEqual(r['minimum_free_bytes'],8*16384)

if __name__=='__main__':
    unittest.main()
