"""Mutation tests for the component timing acceptance boundary."""
import unittest
import direct_ring_component_timing_guard as guard


class ComponentTimingTests(unittest.TestCase):
    def content(self, value='103'):
        return (guard.OUTER_REPORT + '{}\n' + guard.TIMING + ' elapsed_ns=' + value
                + '\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n')

    def accept(self, text, child=100, outer=3, wall=104):
        return guard.component(text, text.index('test result:'),
                               {'total_proving_lifecycle_ns': child},
                               {'total_qualification_ns': outer}, wall)

    def test_exact_boundary_and_truthful_scope(self):
        result = self.accept(self.content(), wall=103)
        self.assertEqual(result['fresh_child_to_outer_component_ns'], 103)
        self.assertFalse(result['complete_ringct_workflow'])
        self.assertFalse(result['performance_qualified'])
        self.accept(self.content(str(guard.U128_MAX)), wall=guard.U128_MAX)

    def test_missing_duplicate_noncanonical_overflow_and_suffixes_refuse(self):
        values = ['', '0', '-1', '+103', '0103', '1.03e2', '103.0', '１０３',
                  '103 ', '103\r', str(1 << 128), '1' * 40]
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.accept(self.content(value))
        for text in [self.content().replace(guard.TIMING, 'missing'),
                     self.content() + guard.TIMING,
                     self.content() + self.content(),
                     self.content().replace(guard.TIMING, 'prefix ' + guard.TIMING)]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.accept(text)

    def test_marker_order_and_unrelated_census_refuse(self):
        lines = self.content().splitlines(True)
        for text in [lines[1] + lines[0] + lines[2],
                     lines[0] + lines[2] + lines[1],
                     self.content() + guard.ORCHESTRATION]:
            with self.assertRaises(ValueError):
                self.accept(text)

    def test_phase_sum_and_runner_observation_are_mandatory_typed_and_bounded(self):
        for field in ('child', 'outer', 'wall'):
            for value in [None, False, True, 0, -1, 1.0, '100', 1 << 128]:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.accept(self.content(), **{field: value})
        for kwargs in [dict(child=101), dict(outer=4), dict(wall=102)]:
            with self.assertRaises(ValueError):
                self.accept(self.content(), **kwargs)

    def test_child_only_rejects_outer_evidence(self):
        guard.child_only('child report')
        for text in [guard.TIMING, guard.ORCHESTRATION]:
            with self.assertRaises(ValueError):
                guard.child_only(text)

    def test_optional_census_and_exact_original_allowance(self):
        self.assertIsNone(guard.orchestration('caller', 0))
        marker = guard.ORCHESTRATION + ' actual=32768 timing_additional=1 allowance=32768\n'
        result = guard.orchestration(marker + 'caller', len(marker))
        self.assertEqual(result['allowance_bytes'], 32768)
        mutations = [marker + marker, marker.replace('32768', '32769', 1),
                     marker.replace('additional=1 ', 'additional=32768 '),
                     marker.replace('additional=1 ', 'additional=0 '),
                     marker.replace('actual=32768', 'actual=032768'),
                     marker.replace('allowance=32768', 'allowance=65536'),
                     marker + guard.TIMING, 'prefix ' + marker]
        for text in mutations:
            with self.subTest(text=text), self.assertRaises(ValueError):
                guard.orchestration(text, len(text))
        with self.assertRaises(ValueError):
            guard.orchestration(marker, 0)


if __name__ == '__main__':
    unittest.main()
