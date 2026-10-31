"""Synthetic isolation checks for the existing HashX qualification guards."""
import unittest

import test_hashx_first_leaf_guard as leaf
import test_hashx_root_public_gpu_guard as public
import test_hashx_sequence_preissue_guard as preissue
import test_hashx_sequence_refusal_guard as refusal
import test_native_hashx_scratch_guard as native
import test_hashx_root_transport_gpu_guard as transport
import test_hashx_root_transport_capacity_guard as capacity


class RootOpeningReciprocalGuardTests(unittest.TestCase):
    def test_existing_environment_helpers_refuse_opening_option(self):
        for fixture in (public, preissue, refusal, transport):
            with self.subTest(mode=fixture.__name__), self.assertRaises(ValueError):
                fixture.guard.build_environment(
                    fixture.arguments(owned_hashx_root_opening_test='gpu'),
                    fixture.base_environment(), fixture.ROOT, 'baseline', 'host')
        for mode in leaf.guard.SELECTORS:
            with self.subTest(mode='leaf-' + mode), self.assertRaises(ValueError):
                leaf.environment(leaf.arguments(mode, owned_hashx_root_opening_test='gpu'))
        for mode in native.guard.SELECTORS:
            with self.subTest(mode='native-' + mode), self.assertRaises(ValueError):
                native.environment(native.args(mode, owned_hashx_root_opening_test='gpu'))

    def test_existing_bindings_refuse_opening_receipt(self):
        for fixture in (public, preissue, refusal, transport):
            plan = fixture.bound_plan()
            plan['owned_hashx_root_opening_environment'] = {}
            with self.subTest(mode=fixture.__name__), self.assertRaises(ValueError):
                fixture.guard.bind_execution(plan, plan['input_sha256'], plan['executable_provenance'], fixture.ROOT)
        for fixture in (leaf, native):
            for mode in fixture.guard.SELECTORS:
                plan, sources, executable = fixture.identities(mode)
                plan['owned_hashx_root_opening_environment'] = {}
                with self.subTest(mode=fixture.__name__ + '-' + mode), self.assertRaises(ValueError):
                    fixture.guard.bind_execution(plan, sources, executable, fixture.ROOT)


    def test_transport_capacity_helper_and_binding_refuse_opening_option_and_receipt(self):
        with self.assertRaises(ValueError):
            capacity.guard.build_environment(capacity.arguments(owned_hashx_root_opening_test='gpu'),
                capacity.base_environment(), capacity.ROOT, 'baseline', 'device')
        plan = capacity.bound_plan()
        plan['owned_hashx_root_opening_environment'] = {}
        with self.assertRaises(ValueError):
            capacity.guard.bind_execution(plan, plan['input_sha256'], plan['executable_provenance'], capacity.ROOT)


if __name__ == '__main__':
    unittest.main()
