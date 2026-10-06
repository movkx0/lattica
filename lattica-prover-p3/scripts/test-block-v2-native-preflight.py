#!/usr/bin/env python3
"""Preflight ABI framing tests with an explicit non-cryptographic fake call."""
import ctypes
import struct
from types import SimpleNamespace
import unittest

import block_v2_host_store as H


class Preflight(unittest.TestCase):
    def setUp(self):
        self.verifier = object.__new__(H.NativeVerifier)
        self.verifier._context = bytes([3] * 32 + [4] * 32)
        self.verifier._registry = b'LBV2RG01fake'
        self.verifier._genesis = b'LBV2GN01' + struct.pack('<Q', 9) + bytes(52)
        self.verifier._policy = H.IssuancePolicy({10: {3: 7}})
        self.expected = b'LBV2EX01' + self.verifier._context + struct.pack('<QQQQQ', 1, 2, 3, 4, 4)
        self.packet = b'LBV2PF01' + self.expected
        for kind in range(4):
            width = 31 if kind in (1, 2) else 26
            self.packet += bytes([kind, width]) + bytes(width * 8)

    def test_exact_abi_arguments_keep_native_history_and_independent_policy(self):
        calls = []
        packet = self.packet
        class Call:
            def __call__(self, *args):
                calls.append(args)
                ctypes.memmove(args[13], packet, len(packet))
                ctypes.cast(args[15], ctypes.POINTER(ctypes.c_size_t))[0] = len(packet)
                return 0
        self.verifier._lib = SimpleNamespace(lattica_v2_research_candidate_preflight_v1=Call())
        body = b'LBV2BD01' + struct.pack('<I', 4) + b'fake-complete-body'
        result = self.verifier.preflight([], body, 10)
        self.assertEqual(result['expected'], self.expected)
        self.assertEqual([t['kind'] for t in result['body']['transactions']],
                         ['joinsplit', 'htlc_redeem', 'htlc_refund', 'issuance'])
        args = calls[0]
        self.assertEqual(len(args), 16)
        self.assertEqual(ctypes.string_at(args[6], args[7]), b'LBV2RP01' + struct.pack('<I', 0))
        self.assertEqual(ctypes.string_at(args[8], args[9]), body)
        self.assertEqual(args[10], 10)
        self.assertEqual(ctypes.string_at(args[11], args[12]), struct.pack('<QQQQ', 0, 0, 0, 7))

    def test_bad_context_count_shapes_trailing_data_and_fields_are_rejected(self):
        packets = [self.packet[:119], self.packet + b'junk', b'badmagic' + self.packet[8:]]
        for offset, value in [(16, 99), (112, 3), (120, 4), (121, 31)]:
            changed = bytearray(self.packet); changed[offset] = value; packets.append(bytes(changed))
        changed = bytearray(self.packet)
        changed[122:130] = struct.pack('<Q', 0xffff_ffff_0000_0001)
        packets.append(bytes(changed))
        for packet in packets:
            with self.subTest(length=len(packet)), self.assertRaises(H.RejectedBlock):
                self.verifier._decode_preflight(packet, 4, 10, [0, 0, 0, 7])

    def test_missing_native_support_fails_without_a_fallback(self):
        self.verifier._lib = SimpleNamespace()
        with self.assertRaisesRegex(H.RejectedBlock, 'lacks candidate preflight'):
            self.verifier.preflight([], b'LBV2BD01' + struct.pack('<I', 4), 10)


if __name__ == '__main__':
    unittest.main()
