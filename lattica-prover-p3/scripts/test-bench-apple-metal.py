#!/usr/bin/env python3
"""Check the experiment matrix and CPU audit isolation without running proofs."""
import collections
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("bench", Path(__file__).with_name("bench-apple-metal.py"))
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)

class Experiment(unittest.TestCase):
    def test_schedule_has_45_balanced_measured_trials_after_two_pilots(self):
        schedule = B.schedule()
        self.assertEqual([a["phase"] for a in schedule[:2]], ["pilot", "pilot"])
        measured = schedule[2:]
        self.assertEqual(len(measured), 45)
        counts = collections.Counter((a["backend"], a["threads"], a["level"]) for a in measured)
        self.assertEqual(len(counts), 15)
        self.assertEqual(set(counts.values()), {3})
        first = [(a["backend"], a["threads"]) for a in measured[:9]]
        second = [(a["backend"], a["threads"]) for a in measured[9:18]]
        self.assertEqual(first, second[::-1])

    def test_cpu_audit_children_receive_all_gpu_and_fusion_switches_disabled(self):
        for config in B.schedule():
            env = B.environment(config, Path("/tmp/example"), False)
            self.assertTrue(all(env["LATTICA_V2_GPU_" + key] == "0" for key in B.GPU_KEYS))
            self.assertEqual(env["LATTICA_V2_QUOTIENT_FUSION"], "0")
            self.assertEqual(env["LATTICA_SPILL_MAX_BYTES"], str(34 << 30))

    def test_shared_copy_pairs_only_change_storage_mode(self):
        for level in ("baseline", "readback", "fusion", "quotient"):
            a = B.environment(B.arm("shared", 24, level), Path("/tmp/example"), True)
            b = B.environment(B.arm("copy", 24, level), Path("/tmp/example"), True)
            self.assertEqual({k for k in a if a[k] != b[k]}, {"LATTICA_V2_METAL_MEMORY"})
            self.assertEqual(a["LATTICA_V2_GPU_QUOTIENT_LDE"], str(int(level == "quotient")))
            if level == "quotient":
                self.assertEqual(a["LATTICA_V2_QUOTIENT_FUSION"], "1")
                self.assertEqual(a["LATTICA_V2_GPU_RESIDENT_LDE"], "1")

if __name__ == "__main__":
    unittest.main()
