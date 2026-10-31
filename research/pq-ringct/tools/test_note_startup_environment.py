import unittest
import note_startup_environment as env

UUID = 'GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c'


class NoteStartupEnvironmentTests(unittest.TestCase):
    def pairs(self):
        return list(env.build_environment(0, UUID)[0].items())

    def test_fixed_policy_and_descriptive_identity_are_bounded(self):
        values, report = env.build_environment(0, UUID)
        self.assertEqual(values['HOME'], '/home/access')
        self.assertEqual(values['LATTICA_V2_HOST_OUTPUT_BYTES'], str(24 << 30))
        self.assertEqual(values['LATTICA_V2_GPU_MANAGED_BYTES'], str(8 << 30))
        self.assertLessEqual(report['serialized_bytes'], env.MAX_ENVIRONMENT_BYTES)
        self.assertEqual(report['entry_count'], len(env.KNOWN))
        self.assertFalse(report['dispatch_authority'])
        self.assertFalse(report['complete_external_admission'])
        self.assertFalse(report['physical_identity_verified'])
        self.assertEqual(env.validate_environment(list(reversed(self.pairs())))[1], report)

    def test_unknown_duplicate_and_missing_variables_are_rejected(self):
        pairs = self.pairs()
        for changed in [pairs + [('LD_PRELOAD', 'x')], pairs + [pairs[0]], pairs[:-1]]:
            with self.assertRaises(ValueError):
                env.validate_environment(changed)

    def test_fixed_policy_mutations_are_rejected(self):
        for key in env.FIXED.keys() | env.BASE.keys():
            changed = dict(self.pairs())
            changed[key] = 'changed'
            with self.subTest(key=key), self.assertRaises(ValueError):
                env.validate_environment(list(changed.items()))

    def test_device_identity_syntax_and_types_are_checked(self):
        for index in [True, -1, 1000, '0']:
            with self.assertRaises(ValueError):
                env.build_environment(index, UUID)
        for uuid in [None, UUID[:-1], UUID + '0', UUID.replace('-', '/', 1), UUID + '\0']:
            with self.assertRaises(ValueError):
                env.build_environment(0, uuid)
        for index in ['00', '+1', '1 ', '١']:
            changed = dict(self.pairs())
            changed['LATTICA_V2_GPU_DEVICE'] = index
            with self.assertRaises(ValueError):
                env.validate_environment(list(changed.items()))

    def test_input_limits_fail_before_unbounded_encoding_or_copy(self):
        for pairs in [self.pairs() * 3, [('', 'x')], [('A=B', 'x')],
                      [('x' * 97, 'x')], [('HOME', 'x' * 1025)],
                      [('HOME', 'é' * 513)], [('HOME', '\ud800')],
                      [('HOME', 'a\0b')], [('HOME',)], {'HOME': '/home/access'}]:
            with self.subTest(pairs=type(pairs)), self.assertRaises(ValueError):
                env.validate_environment(pairs)

    def test_physical_selection_changes_environment_digest(self):
        _, initial = env.build_environment(0, UUID)
        for args in [(1, UUID), (0, UUID[:-1] + 'd')]:
            _, changed = env.build_environment(*args)
            self.assertNotEqual(initial['sha256_sorted_name_equals_value_nul'],
                                changed['sha256_sorted_name_equals_value_nul'])


if __name__ == '__main__':
    unittest.main()
