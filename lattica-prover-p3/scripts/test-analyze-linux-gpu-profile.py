#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest

import numpy as np

spec=importlib.util.spec_from_file_location('analysis',Path(__file__).with_name('analyze-linux-gpu-profile.py'))
A=importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)


class AnalysisTests(unittest.TestCase):
    def clocks(self):
        db=sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.executescript('CREATE TABLE StringIds(id INTEGER,value TEXT); CREATE TABLE NVTX_EVENTS(start INTEGER,text TEXT,textId INTEGER);')
        db.executemany('insert into NVTX_EVENTS values(?,?,NULL)',[(100,'lattica_clock:0'),(200,'lattica_clock:1')])
        records=[dict(type='clock',sequence=0,before_ns=1098,after_ns=1102),
                 dict(type='clock',sequence=1,before_ns=1208,after_ns=1212)]
        return db,records

    def test_clock_reports_empirical_jitter_instead_of_false_precision(self):
        db,records=self.clocks()
        offset,stats=A.align_clock(db,records)
        self.assertEqual(offset,1005)
        self.assertEqual(stats['uncertainty_ns'],14)
        self.assertFalse(stats['constant_offset_brackets_intersect'])

    def test_missing_anchors_and_large_clock_error_rejected(self):
        db,records=self.clocks()
        with self.assertRaisesRegex(ValueError,'loss'):
            A.align_clock(db,records[:1])
        records[1].update(before_ns=3_000_000,after_ns=3_000_010)
        with self.assertRaisesRegex(ValueError,'1 ms'):
            A.align_clock(db,records)

    def test_cpu_children_are_summed_without_double_counting_parent(self):
        def p(pid,ticks,start=100):
            return dict(pid=pid,start_ticks=start,user_ticks=ticks,system_ticks=0)
        records=[dict(type='metadata',ticks_per_second=100),
                 dict(type='clock',before_ns=2_000_000_000,processes=[p(1,100)]),
                 dict(type='clock',before_ns=3_000_000_000,processes=[p(1,160),p(2,20,210)]),
                 dict(type='clock',before_ns=4_000_000_000,processes=[p(1,180)])]
        rows,pids,vanished=A.cpu_intervals(records)
        self.assertAlmostEqual(rows[0]['cores'],0.8)
        self.assertAlmostEqual(rows[1]['cores'],0.2)
        self.assertEqual(pids,[1,2])
        self.assertEqual(vanished,1)

    def test_weighted_clipping_and_overlapping_windows(self):
        starts=np.array([0,10,20]);ends=starts+10
        w=A.weights(starts,ends,[(5,25)])
        np.testing.assert_allclose(w,np.array([5,10,5])/1e9)
        self.assertAlmostEqual(A.describe(np.array([0,50,100]),w)['mean'],50)
        with self.assertRaisesRegex(ValueError,'overlapping'):
            A.weights(starts,ends,[(0,20),(10,30)])

    def test_metric_mapping_uses_names_and_verifies_uuid(self):
        db=sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.executescript('CREATE TABLE TARGET_INFO_GPU(id,name,uuid,memoryBandwidth); CREATE TABLE TARGET_INFO_GPU_METRICS(typeId,metricId,metricName); CREATE TABLE GPU_METRICS(typeId,metricId,timestamp,value);')
        db.execute("insert into TARGET_INFO_GPU values(4,'test','uuid',100)")
        for i,name in enumerate(A.METRICS.values(),100):
            db.execute('insert into TARGET_INFO_GPU_METRICS values(99,?,?)',(i,name))
            db.executemany('insert into GPU_METRICS values(99,?,?,?)',[(i,1_000_000,10),(i,2_000_000,20)])
        starts,ends,values,metadata=A.load_metrics(db,'GPU-uuid',4,100)
        self.assertEqual(metadata['type_id'],99)
        np.testing.assert_array_equal(values['sm'],[10,20])
        np.testing.assert_array_equal(ends,[1_000_100,2_000_100])
        with self.assertRaisesRegex(ValueError,'identity'):
            A.load_metrics(db,'wrong',4,100)

    def test_partial_device_union_is_labeled_and_nested_spans_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            log=Path(temp)/'log'
            log.write_text('gpu_timeline_interval label="job" kind=ntt start_ns=10 end_ns=30 clock=opencl_device\n'
                'gpu_timeline_interval label="job" kind=copy start_ns=20 end_ns=40 clock=opencl_device\n'
                'gpu_timeline_checkpoint label="job" events=2 dropped=5 clock=opencl_device\n'
                'performance_span target="test" name="outer" calls=1 total_ns=100 max_ns=100\n'
                'performance_span target="test" name="inner" calls=1 total_ns=60 max_ns=60\n')
            result=A.operation_timings(log)
            self.assertAlmostEqual(result['recorded_gpu_union_seconds'],30e-9)
            self.assertEqual(result['gpu_timeline_checkpoints'][0]['dropped'],5)
            self.assertEqual(len(result['inclusive_cpu_spans']),2)


if __name__=='__main__':
    unittest.main()
