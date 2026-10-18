#!/usr/bin/env python3
"""Check energy-window accounting without a GPU or driver."""
import sys
import unittest

sys.dont_write_bytecode = True
from power import Meter


def reading(seconds, power_w, energy_mj):
    return dict(monotonic_seconds=seconds, power_w=power_w,
                energy_mj=energy_mj, read_duration_ms=0.1)


class EnergyWindowTests(unittest.TestCase):
    def meter(self, rows):
        meter = object.__new__(Meter)
        meter.rows = rows
        return meter

    def test_irregular_samples_use_elapsed_time_and_exclude_other_windows(self):
        start = reading(0, 100, 100000)
        end = reading(3, 100, 550000)
        rows = [reading(-1, 999, 0), start, reading(1, 200, 250000),
                end, reading(4, 999, 1500000)]
        result = self.meter(rows).window(start, end)
        self.assertEqual(result['samples'], 3)
        self.assertEqual(result['energy_j'], 450)
        self.assertEqual(result['energy_wh'], 0.125)
        self.assertEqual(result['average_power_w'], 150)
        self.assertEqual(result['integrated_average_power_w'], 150)
        self.assertEqual(result['sampled_peak_power_w'], 200)
        self.assertEqual(result['max_sample_gap_seconds'], 2)

    def test_counter_delta_is_independent_of_sampled_power_integral(self):
        start, end = reading(0, 100, 0), reading(2, 100, 300000)
        result = self.meter([start, end]).window(start, end)
        self.assertEqual(result['energy_j'], 300)
        self.assertEqual(result['average_power_w'], 150)
        self.assertEqual(result['integrated_power_j'], 200)

    def test_counter_reset_inside_window_is_rejected(self):
        rows = [reading(0, 100, 0), reading(1, 100, 200000),
                reading(2, 100, 100000), reading(3, 100, 300000)]
        with self.assertRaisesRegex(RuntimeError, 'counter decreased'):
            self.meter(rows).window(rows[0], rows[-1])

    def test_invalid_window_is_rejected(self):
        for start, end in ((reading(1, 100, 0), reading(0, 100, 1000)),
                           (reading(0, 100, 1000), reading(1, 100, 1000))):
            with self.subTest(start=start, end=end):
                with self.assertRaisesRegex(RuntimeError, 'invalid power window'):
                    self.meter([start, end]).window(start, end)


if __name__ == '__main__':
    unittest.main()
