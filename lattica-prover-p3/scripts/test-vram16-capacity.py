#!/usr/bin/env python3
"""Reject device, process and budget mismatches in capacity evidence."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('capacity',Path(__file__).with_name('qualify-vram16-capacity.py'))
C=importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)

class Samples(unittest.TestCase):
    def check(self, samples):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'prove.log'
            path.write_text('\n'.join('bounded_gpu_context '+json.dumps(s) for s in samples))
            return C.context_peaks(path,'GPU-a',123,dict(managed_bytes=70,context_bytes=20,total_bytes=90))

    def sample(self, **change):
        return dict(dict(uuid='GPU-a',pid=123,limit_bytes=90,managed_live_bytes=60,
                         context_bytes=10,process_bytes=70),**change)

    def test_retains_separate_sampled_peaks(self):
        result=self.check([self.sample(),self.sample(managed_live_bytes=55,context_bytes=15,process_bytes=70)])
        self.assertEqual(result['samples'],2)
        self.assertEqual(result['sampled_peak_process_bytes'],70)
        self.assertEqual(result['sampled_peak_managed_bytes'],60)
        self.assertEqual(result['sampled_peak_context_bytes'],15)

    def test_missing_samples_fail(self):
        with self.assertRaises(ValueError):self.check([])

    def test_wrong_gpu_or_pid_fails(self):
        for change in [dict(uuid='GPU-b'),dict(pid=124)]:
            with self.subTest(change=change),self.assertRaises(ValueError):self.check([self.sample(**change)])

    def test_any_budget_violation_fails(self):
        for change in [dict(limit_bytes=91),dict(managed_live_bytes=71),dict(context_bytes=21),
                       dict(process_bytes=91),dict(process_bytes=0),dict(context_bytes=-1)]:
            with self.subTest(change=change),self.assertRaises(ValueError):self.check([self.sample(**change)])

if __name__=='__main__':unittest.main()
