#!/usr/bin/env python3
"""Selection contracts; fake native screening here, real qualification retained separately."""

import struct
from types import SimpleNamespace
import unittest
import block_v2_pending_candidate as B

H = B.H


def arrival(name, kind=0):
    return {'receipt': {'request_id': name}, 'body': b'LBV2BD01' + struct.pack('<I', 1) + bytes([kind])}


class Selection(unittest.TestCase):
    def choose(self, pool, policy, *, bad=None, limit=4, complete=True):
        verifier = SimpleNamespace(_policy=H.IssuancePolicy({11: policy}))
        verifier.preflight_prefix = lambda history, body, height: {'grants': verifier._policy.for_prefix(height, body[8])}
        host = SimpleNamespace(verifier=verifier)
        checked, attempts = [], []

        def screen(row, position, prefix):
            name = row['receipt']['request_id']
            checked.append((name, position, prefix['grants'][position]))
            if name == bad:
                raise H.RejectedBlock('explicit fake invalid proof')
            return {'checked': name}

        result = B._choose(host, SimpleNamespace(state={'height': 10}), [], pool, limit, screen, attempts, complete=complete)
        return [r['receipt']['request_id'] for r in result], checked, attempts

    def test_early_issuance_moves_to_its_independent_slot(self):
        names, checked, _ = self.choose([arrival('issuance', 3), arrival('a'), arrival('b', 2), arrival('c', 1)], {3: 7})
        self.assertEqual(names, ['a', 'b', 'c', 'issuance'])
        self.assertEqual(checked[-1], ('issuance', 3, 7))

    def test_invalid_wallet_does_not_block_later_valid_arrivals(self):
        pool = [arrival('bad'), arrival('issuance', 3), arrival('a'), arrival('b'), arrival('c')]
        names, checked, attempts = self.choose(pool, {3: 7}, bad='bad')
        self.assertEqual(names, ['a', 'b', 'c', 'issuance'])
        self.assertEqual(sum(n == 'bad' for n, _, _ in checked), 1)
        self.assertEqual(attempts[0]['status'], 'rejected_by_cpu_wallet_verification')

    def test_missing_required_issuance_cannot_be_sealed_as_smaller_batch(self):
        with self.assertRaises(H.RejectedBlock):
            self.choose([arrival('a'), arrival('b'), arrival('c')], {3: 7})
        with self.assertRaises(H.RejectedBlock):
            self.choose([arrival('issuance', 3), arrival('a')], {3: 7}, limit=2)

    def test_invalid_wallet_is_not_rechecked_after_issuance(self):
        names, checked, _ = self.choose([arrival('bad'), arrival('a'), arrival('m', 3), arrival('b')], {1: 7}, bad='bad')
        self.assertEqual(names, ['a', 'm', 'b'])
        self.assertEqual(sum(n == 'bad' for n, _, _ in checked), 1)

    def test_ungranted_issuance_is_left_out(self):
        names, checked, _ = self.choose([arrival('issuance', 3), arrival('a'), arrival('b')], {})
        self.assertEqual(names, ['a', 'b'])
        self.assertFalse(any(n == 'issuance' for n, _, _ in checked))

    def test_arbitrary_policy_slots_preserve_order_within_roles(self):
        names, checked, _ = self.choose([arrival('a'), arrival('m1', 3), arrival('b'), arrival('m2', 3)], {0: 7, 2: 9})
        self.assertEqual(names, ['m1', 'a', 'm2', 'b'])
        self.assertEqual([g for _, _, g in checked], [7, 0, 9, 0])

    def test_prefix_grants_never_waive_complete_policy(self):
        policy = H.IssuancePolicy({11: {3: 7}})
        self.assertEqual(policy.for_prefix(11, 2), (0, 0))
        with self.assertRaises(H.RejectedBlock):
            policy.for_block(11, 2)
        self.assertEqual(policy.for_block(11, 4), (0, 0, 0, 7))

    def test_unsealed_prefix_can_precede_required_later_issuance(self):
        names, _, _ = self.choose([arrival('a'), arrival('b')], {3: 7}, limit=2, complete=False)
        self.assertEqual(names, ['a', 'b'])
        with self.assertRaises(H.RejectedBlock):
            self.choose([arrival('a'), arrival('b')], {3: 7}, limit=2)


if __name__ == '__main__':
    unittest.main()
