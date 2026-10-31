import unittest

import privacy_screen as model


class ClearOpeningPrivacyScreen(unittest.TestCase):
    def test_both_secrets_share_one_valid_public_relation(self):
        relation = model.binary_relation(8)
        for prime in (17, model.BN254_FR):
            self.assertTrue(model.valid_witness(relation, [1, 0], prime))
            self.assertTrue(model.valid_witness(relation, [1, 1], prime))
            self.assertFalse(model.valid_witness(relation, [1, 2], prime))

    def test_unmasked_opening_distinguishes_witnesses(self):
        relation = model.binary_relation(8)
        for alpha in ([0, 0, 0], [1, 1, 1], [2, 3, 4], [16, 0, 1]):
            left = model.clear_openings(relation, [1, 0], alpha, 17)
            right = model.clear_openings(relation, [1, 1], alpha, 17)
            self.assertEqual(left, [0, 16, 0])
            self.assertEqual(right, [1, 0, 0])
            self.assertNotEqual(left, right)

    def test_all_small_field_points_and_large_field_samples(self):
        report = model.run_screen()
        self.assertEqual(report["challenge_points_checked"], 17**3 + 128)
        self.assertEqual(report["valid_witness_checks"], 2 * (17**3 + 128))
        self.assertFalse(report["upstream_prover_executed"])
        self.assertFalse(report["proof_generated"])
        self.assertFalse(report["full_zero_knowledge_admissible"])

    def test_dimension_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            model.clear_openings(model.binary_relation(4), [1, 0], [2, 3, 4], 17)


if __name__ == "__main__":
    unittest.main()
