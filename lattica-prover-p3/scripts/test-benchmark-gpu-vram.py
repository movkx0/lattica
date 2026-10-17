#!/usr/bin/env python3
"""The experimental VRAM ceiling must preserve physical and context margins."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('vram_benchmark', Path(__file__).with_name('benchmark-gpu-vram.py'))
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
GIB = 1 << 30


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.base = {
            'gpu': {'managed_bytes': 7 * GIB, 'context_bytes': 4 * GIB,
                    'headroom_bytes': GIB, 'usable_bytes': 16 * GIB,
                    'max_allocation_bytes': GIB, 'total_bytes': 11 * GIB},
            'detected_gpu': {'opencl': {'max_allocation_bytes': 3 * GIB}},
            'host': {'worker_bytes': 3 * GIB, 'fleet_bytes': 4 * GIB, 'swap_bytes': 0},
            'cpu': {'rayon_threads': 4, 'quota_percent': '400%'},
            'lde_workspace_bytes': 0,
        }

    def test_exact_free_capacity_includes_both_context_and_headroom(self):
        admitted = M.variant_budget(self.base, 'wide', 14 * GIB)
        self.assertEqual(admitted['gpu']['total_bytes'] + admitted['gpu']['headroom_bytes'], 14 * GIB)
        with self.assertRaisesRegex(ValueError, 'insufficient free VRAM'):
            M.variant_budget(self.base, 'wide', 14 * GIB - 1)

    def test_physical_usable_capacity_also_constrains_admission(self):
        self.base['gpu']['usable_bytes'] = 14 * GIB - 1
        with self.assertRaisesRegex(ValueError, 'insufficient free VRAM'):
            M.variant_budget(self.base, 'cached', 16 * GIB)

    def test_single_allocation_cap_never_exceeds_hardware(self):
        self.base['detected_gpu']['opencl']['max_allocation_bytes'] = 2 * GIB - 1
        with self.assertRaisesRegex(ValueError, 'per-buffer budget'):
            M.variant_budget(self.base, 'wide', 16 * GIB)
        M.variant_budget(self.base, 'roomy', 16 * GIB)

    def test_variants_preserve_cpu_ram_and_reserves_and_do_not_mutate_baseline(self):
        before = copy.deepcopy(self.base)
        for name in M.VARIANTS:
            result = M.variant_budget(self.base, name, 16 * GIB)
            self.assertEqual(result['cpu'], before['cpu'])
            self.assertEqual(result['host'], before['host'])
            for key in ['context_bytes', 'headroom_bytes']:
                self.assertEqual(result['gpu'][key], before['gpu'][key])
            self.assertLessEqual(result['lde_workspace_bytes'], result['gpu']['managed_bytes'] // 4)
        self.assertEqual(self.base, before)


if __name__ == '__main__':
    unittest.main()
