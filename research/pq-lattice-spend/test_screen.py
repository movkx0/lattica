import copy
import math
import unittest

import linear_size_floor as linear
import screen

REVISION = "18b6814bc81ebcdf1c6b7e033fe648d35005937d"

class ScreeningAudit(unittest.TestCase):
    def setUp(self):
        self.valid = dict(schema="lattice-parameter-screen-v2", binary_polynomials=104,
                          backend_revision=REVISION,
                          degree=256, modulus=274877906837, backend_status=0,
                          zero_knowledge_requested=True, zero_knowledge_stage_selected=True,
                          proof_generated=False, serialized_bytes_measured=False,
                          full_ringct_relation=False, security_equivalence_established=False,
                          estimated_proof_bits=918936, estimated_proof_bytes_ceil=114867,
                          reduction_rounds=9)

    def test_accept_estimate_with_explicit_limitations(self):
        screen.validate_case(self.valid, 104, REVISION)

    def test_reject_misleading_security_size_or_relation_claims(self):
        mutations = {
            "zero_knowledge_requested": False, "zero_knowledge_stage_selected": False,
            "proof_generated": True, "serialized_bytes_measured": True,
            "full_ringct_relation": True, "security_equivalence_established": True,
            "binary_polynomials": 512, "modulus": 2**32-99, "degree": 64,
            "backend_status": 1, "estimated_proof_bytes_ceil": 24000,
            "estimated_proof_bits": -1, "reduction_rounds": True,
            "schema": "other", "zero_knowledge_stage_selected_integer": 1,
            "backend_revision": "c1ae0e612d5accd9e7d9d1c264951c1afe949c83",
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                record = copy.deepcopy(self.valid)
                key = "zero_knowledge_stage_selected" if field.endswith("_integer") else field
                record[key] = value
                with self.assertRaises(ValueError):
                    screen.validate_case(record, 104, REVISION)

    def test_missing_privacy_or_scope_flags_rejected(self):
        for key in ("zero_knowledge_stage_selected", "full_ringct_relation", "serialized_bytes_measured"):
            with self.subTest(key=key):
                record = dict(self.valid)
                del record[key]
                with self.assertRaises(ValueError):
                    screen.validate_case(record, 104, REVISION)

    def test_original_source_formulas_match_integer_evaluation(self):
        # Differential check of the rational calculation against the upstream
        # floating-point formulas, including changes at sampler boundaries.
        for count in range(1, 104 * 256 + 1):
            sigma = 14 * 140 * math.ceil(math.sqrt(count))
            exponent = math.log2(sigma / 1.55)
            lo = 1.55 * 2**math.floor(exponent)
            hi = 1.55 * 2**math.ceil(exponent)
            rounded = lo if sigma - lo <= hi - sigma else hi
            expected = math.ceil(math.log2(rounded) + 2.5)
            self.assertEqual(linear.response_bits_per_coefficient(count), expected)

    def test_original_floor_excludes_smaller_size_claim(self):
        report = linear.source_checked_report()
        self.assertEqual(report["partitions_checked"], 105)
        self.assertGreater(report["partial_estimator_bytes_floor"], 47632)
        self.assertFalse(report["serialized_bytes_measured"])


if __name__ == "__main__":
    unittest.main()
