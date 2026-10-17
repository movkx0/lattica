#!/usr/bin/env python3
"""Diagnostic interpretation tests; no benchmark or GPU workload."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('analysis',Path(__file__).with_name('analyze-apple-hardware.py'))
A=importlib.util.module_from_spec(spec);spec.loader.exec_module(A)

class Analysis(unittest.TestCase):
    def test_union_never_adds_overlapping_intervals(self):
        self.assertEqual(A.union_ns([(0,10),(2,7),(8,15),(20,25)]),20)
        self.assertEqual(A.union_ns([]),0)
        with self.assertRaises(ValueError):A.union_ns([(5,4)])

    def test_quoted_phase_names_and_explicit_trace_gaps(self):
        self.assertEqual(A.fields('x name="native batch prove" dropped=2'),{'name':'native batch prove','dropped':'2'})
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'worker.log'
            command={'kind':'command','id':1,'phase':'ntt_tile','dispatches':8,'submitted_ns':1,
                     'gpu_start_ns':100,'gpu_end_ns':200,'timestamp_valid':True}
            records=[command,{**command,'id':2,'gpu_start_ns':150,'gpu_end_ns':250},
                     {'kind':'wait','id':1,'thread':'ThreadId(1)','start_ns':90,'end_ns':200},
                     {'kind':'wait','id':1,'thread':'ThreadId(2)','start_ns':150,'end_ns':210}]
            path.write_text('\n'.join('metal_profile '+json.dumps(r) for r in records)+'\n'+
                'metal_profile_checkpoint dropped=3 outstanding=0\n'+
                'host_timeline_checkpoint dropped=5 malformed=0\n'+
                'host_timeline_interval thread=0 target="test" name="parent" start_ns=0 end_ns=5\n'+
                'host_timeline_interval thread=0 target="test" name="child" start_ns=5 end_ns=10\n'+
                'host_timeline_clock timeline_ns=20 mach_before_ns=1000 mach_after_ns=1010\n')
            r=A.analyze_log(path)
            self.assertEqual(r['phases']['ntt_tile']['commands'],2)
            self.assertEqual(r['phases']['ntt_tile']['dispatches'],16)
            self.assertAlmostEqual(r['phases']['ntt_tile']['gpu_seconds'],150/1e9)
            self.assertAlmostEqual(r['phases']['ntt_tile']['gpu_duration_sum_seconds'],200/1e9)
            self.assertAlmostEqual(r['cpu_wait_union_seconds'],120/1e9)
            self.assertAlmostEqual(r['cpu_wait_thread_seconds'],170/1e9)
            self.assertEqual(r['quality']['host_thread_interval_overlaps'],0)
            self.assertEqual(r['quality']['metal_dropped'],3)
            self.assertEqual(r['quality']['host_dropped'],5)
            self.assertEqual(r['clock_correlations'],[{'offset_ns':985,'uncertainty_ns':10}])

if __name__=='__main__':unittest.main()
