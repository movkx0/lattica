#!/usr/bin/env python3
import copy
import importlib.util
import json
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("retention", Path(__file__).with_name("block-v2-retention-model.py"))
MODEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODEL)
EVIDENCE = Path(__file__).resolve().parents[2] / "docs/evidence/block-v2-gpu-hash-2026-09-30.json"


class Tests(unittest.TestCase):
    def test_baseline_model_matches_every_historical_node(self):
        model = MODEL.geometry()
        self.assertEqual(MODEL.validate_evidence(json.loads(EVIDENCE.read_text()), model), 35)
        self.assertEqual(model['retained_lde_bytes'], 39 * MODEL.GIB)
        self.assertEqual(model['cache_hit_h2d_bytes'], 44023413504)
        self.assertEqual(model['cache_hit_d2h_full_tree_bytes'], 5368707328)
        self.assertEqual(model['logical_retained_lde_salts_trees_bytes'], 59592668896)

    def test_changed_profile_or_counter_is_not_silently_accepted(self):
        original = json.loads(EVIDENCE.read_text())
        changed = copy.deepcopy(original)
        changed['profile']['fri_queries'] = 96
        with self.assertRaises(ValueError):
            MODEL.validate_evidence(changed, MODEL.geometry())
        changed = copy.deepcopy(original)
        changed['trials'][0]['nodes'][0]['gpu_delta']['uploaded_bytes'] += 1
        with self.assertRaises(ValueError):
            MODEL.validate_evidence(changed, MODEL.geometry())

    def test_lower_degree_thought_experiment_is_not_a_memory_win(self):
        baseline = MODEL.geometry()
        alternative = MODEL.geometry(main_width=180, quotient_chunks=8)
        self.assertEqual(alternative['retained_lde_bytes'] - baseline['retained_lde_bytes'], 3.75 * MODEL.GIB)
        self.assertEqual(alternative['cache_hit_h2d_bytes'] - baseline['cache_hit_h2d_bytes'], -0.25 * MODEL.GIB)
        self.assertFalse(alternative['measured_peak_ram'])

    def test_invalid_model_geometry_rejects(self):
        for height in (0, 7, 9, 1 << 28):
            with self.subTest(height=height), self.assertRaises(ValueError):
                MODEL.geometry(height=height)
        with self.assertRaises(ValueError):
            MODEL.geometry(quotient_chunks=0)


if __name__ == '__main__':
    unittest.main()
