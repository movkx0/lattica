import itertools
import unittest

from cycle_mask_screen import (NATIVE_Q, TOY_UPSTREAM_Q, bit_difference,
                               coefficient_packing_probe, cycle_map, cycle_preimage,
                               modular_packed_check, reconstruct_head, run_screen,
                               weighted_sum)


class CycleMaskScreenTests(unittest.TestCase):
    def test_exhaustive_four_bit_balance(self):
        for a, b, c, d in itertools.product(range(16), repeat=4):
            difference = bit_difference((a, b), (c, d), 4)
            self.assertEqual(weighted_sum(difference), c+d-a-b)
            if a+b == c+d:
                self.assertEqual(cycle_map(cycle_preimage(difference)), difference)
            else:
                with self.assertRaises(ValueError):
                    cycle_preimage(difference)

    def test_cycle_map_and_bounded_reconstruction(self):
        for interior in itertools.product(range(-2, 3), repeat=3):
            image = cycle_map(interior)
            self.assertEqual(weighted_sum(image), 0)
            self.assertEqual(cycle_preimage(image), interior)
            self.assertEqual(reconstruct_head(image[1:], 6), image[0])
        self.assertEqual(cycle_map(()), (0,))
        self.assertEqual(cycle_preimage((0,)), ())
        self.assertEqual(reconstruct_head((), 0), 0)

    def test_modular_alias_and_noncanonical_residue(self):
        for lane in range(4):
            c = bit_difference((1, 1), (NATIVE_Q+1, 1), 64)
            packed = [0] * 256
            for j, value in enumerate(c):
                packed[4*j+lane] = value % NATIVE_Q
            self.assertTrue(modular_packed_check(packed, 64, NATIVE_Q))
            self.assertNotEqual(weighted_sum(c), 0)
            with self.assertRaises(ValueError):
                reconstruct_head(c[1:], NATIVE_Q//2)
            packed[lane] += NATIVE_Q
            with self.assertRaises(ValueError):
                modular_packed_check(packed, 64, NATIVE_Q)

    def test_invalid_inputs_and_response_mutation(self):
        for values in ((-1, 0), (1 << 52, 0), (True, 0), (0,), (0, 0, 0)):
            with self.assertRaises(ValueError):
                bit_difference(values, (0, 0))
        with self.assertRaises(ValueError):
            bit_difference((0, 0), (0, 0), 0)
        for values in ((), (False,), (0,) * 65):
            with self.assertRaises(ValueError):
                cycle_preimage(values)
        with self.assertRaises(ValueError):
            reconstruct_head((4,), 7)
        self.assertEqual(reconstruct_head((4,), 8), -8)
        for bits in (0, 52, -1):
            with self.assertRaises(ValueError):
                modular_packed_check([0] * 256, bits, NATIVE_Q)
        c = list(cycle_map((1,) * 51))
        for j in range(52):
            changed = c.copy()
            changed[j] += 1
            with self.assertRaises(ValueError):
                cycle_preimage(changed)

    def test_coefficient_packing_is_not_a_balance_preserving_module(self):
        for modulus in (NATIVE_Q, TOY_UPSTREAM_Q):
            result = coefficient_packing_probe(modulus)
            self.assertEqual(result["product_weighted_sums"], [(1 << 64)+1, 0, 0, 0])
            self.assertFalse(result["modeled_modular_check_accepts"])
            self.assertEqual(result["challenge_nonzero_coefficients"], 44)
            self.assertFalse(result["native_partial_ntt_modeled"])

    def test_source_bound_full_screen(self):
        result = run_screen()
        self.assertEqual(result["balanced_cases"], 1027)
        self.assertEqual(len(result["modular_aliases"]), 2)
        for field in ("full_relation", "proof_generated", "upstream_executed",
                      "zero_knowledge_established", "serialized_bytes_measured",
                      "replacement_qualified"):
            self.assertIs(result[field], False)


if __name__ == "__main__":
    unittest.main()
