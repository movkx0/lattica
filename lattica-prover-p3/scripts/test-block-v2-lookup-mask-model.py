#!/usr/bin/env python3
from collections import Counter
from fractions import Fraction
import importlib.util
from itertools import product
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("mask_model", Path(__file__).with_name("block-v2-lookup-mask-model.py"))
MODEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODEL)


class Tests(unittest.TestCase):
    def test_cubic_relation_and_nonzero_inversion(self):
        for p in (3, MODEL.GOLDILOCKS):
            x = (0, 1, 0)
            self.assertEqual(MODEL.power(x, 3, p), (1, 1, 0))
            for a in (MODEL.ONE, x, (1, 2, 1)):
                self.assertEqual(MODEL.mul(a, MODEL.inverse(a, p), p), MODEL.ONE)
        with self.assertRaises(ZeroDivisionError):
            MODEL.inverse(MODEL.ZERO, 3)

    def test_exhaustive_toy_field_rank_and_uniform_denominators(self):
        # X^3-X-1 has no root over F3, so this is F27, not a weakened STARK.
        p = 3
        elements = list(product(range(p), repeat=3))
        for beta in elements:
            full_rank = MODEL.masking_determinant(beta, p) != 0
            self.assertEqual(full_rank, beta[1:] != (0, 0))
            combined = [MODEL.combine([1, 2, *mask], beta, p) for mask in elements]
            if full_rank:
                self.assertEqual(Counter(combined), Counter(elements))
                self.assertEqual(len({MODEL.inverse(x, p) for x in combined if x != MODEL.ZERO}), 26)
            else:
                self.assertLess(len(set(combined)), 27)

    def test_actual_profile_basis_and_upstream_horner_order(self):
        p = MODEL.GOLDILOCKS
        for beta in ((0, 1, 0), (7, 3, 9), (p-1, p-2, p-3), (0, 0, 1)):
            self.assertNotEqual(MODEL.masking_determinant(beta, p), 0)
            expected = MODEL.add(MODEL.power(beta, 2, p), MODEL.add(beta, MODEL.ONE, p), p)
            self.assertEqual(MODEL.combine([0, 0, 1, 1, 1], beta, p), expected)
        for beta in ((0, 0, 0), (1, 0, 0), (p-1, 0, 0)):
            self.assertEqual(MODEL.masking_determinant(beta, p), 0)

    def test_cycle_preserves_sum_and_nonzero_masks_are_not_perfectly_uniform(self):
        p = 3
        field = list(product(range(p), repeat=3))
        terminal = (1, 2, 0)
        outputs = Counter()
        for left, right in product(field[1:], repeat=2):
            out = MODEL.balanced_terminals([terminal, MODEL.neg(terminal, p)], [left, right], p)
            self.assertEqual(MODEL.add(out[0], out[1], p), MODEL.ZERO)
            outputs[out[0]] += 1
        distance = sum(abs(Fraction(outputs[x], 26**2) - Fraction(1, 27)) for x in field) / 2
        self.assertEqual(distance, Fraction(1, 27 * 26))
        self.assertLessEqual(distance, Fraction(2, 27))

    def test_report_cannot_be_mistaken_for_complete_security_accounting(self):
        report = MODEL.describe()
        self.assertEqual(report["conditional_component_error_bound"]["floor_inverse_bits"], 120)
        bound = report["conditional_component_error_bound"]
        self.assertIsInstance(report["base_modulus"], str)
        p = int(report["base_modulus"])
        self.assertEqual(Fraction(int(bound["numerator"]), int(bound["denominator"])),
                         191 * (Fraction(1, p**2) + Fraction(2, p**3)))
        self.assertFalse(report["implemented_in_prover"])
        self.assertFalse(report["complete_tree_security_bound"])
        self.assertGreater(len(report["not_established"]), 5)


if __name__ == "__main__":
    unittest.main()
