import unittest
from qualification import compare, gate


class QualificationTests(unittest.TestCase):
    def test_both_workloads_and_consistency_are_required(self):
        good = compare([100] * 5, [90, 92, 94, 96, 101])
        modest = compare([100] * 5, [99] * 5)
        self.assertTrue(gate([good, modest]))
        self.assertFalse(gate([good, compare([100] * 5, [101] * 5)]))
        inconsistent = compare([100] * 5, [80, 80, 80, 101, 101])
        self.assertFalse(gate([inconsistent, modest]))
        self.assertFalse(gate([modest, modest]))

    def test_partial_or_unbalanced_campaign_is_rejected(self):
        for left, right in [([1] * 4, [1] * 4), ([1] * 5, [1] * 6), ([1] * 5, [0] * 5)]:
            with self.assertRaises(ValueError):
                compare(left, right)


if __name__ == '__main__':
    unittest.main()
