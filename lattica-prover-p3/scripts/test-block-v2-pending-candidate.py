#!/usr/bin/env python3
"""Selection contracts; fake native screening here, real qualification retained separately."""

import struct
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import block_v2_pending_candidate as B

H = B.H


class PreparationConfiguration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.journal, self.registry = self.root / 'journal', self.root / 'registry'
        self.journal.mkdir(); self.registry.mkdir()
        self.cpu, self.config = self.root / 'cpu', self.root / 'host.json'
        self.cpu.write_bytes(b'explicit-noncryptographic-probe')
        self.config.write_bytes(b'{}')
        self.configuration = {'verifier': 'explicit-noncryptographic-stub'}
        self.host = SimpleNamespace(directory=self.journal,
            verifier=SimpleNamespace(configuration=dict(self.configuration)), snapshot=Mock())
        self.intake = SimpleNamespace(host=self.host,
            configuration=H.sha(H.canonical(self.configuration)), candidate_input_refs=Mock())

    def prepare_rejected(self, message):
        independent = SimpleNamespace(verifier=SimpleNamespace(configuration=self.configuration))
        output = self.root / 'output'
        with patch.object(B.N, 'open_host', return_value=independent), self.assertRaisesRegex(H.RejectedBlock, message):
            B.prepare(self.intake, self.config, self.registry, self.cpu, output)
        self.host.snapshot.assert_not_called()
        self.intake.candidate_input_refs.assert_not_called()
        self.assertEqual(B.N.read(output / 'manifest.json')['status'], 'failed')

    def test_intake_configuration_must_match_even_when_its_store_is_reused(self):
        self.intake.configuration = '99' * 32
        self.prepare_rejected('candidate builder and intake use different native configurations')

    def test_changed_cached_verifier_configuration_rejects_before_reading_arrivals(self):
        self.host.verifier.configuration['verifier'] = 'substituted'
        self.prepare_rejected('cached native store differs from pinned configuration')


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
