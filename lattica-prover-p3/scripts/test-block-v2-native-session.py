#!/usr/bin/env python3
"""Session cache/recovery unit tests. The model below is NOT proof evidence."""
import ctypes
import struct
import threading
import unittest

import block_v2_host_store as H
from block_v2_native_session import NativeSessionVerifier


def row(blocks, height):
    result = bytearray(H.STATE_BYTES)
    result[:8] = b'LBV2ST01'
    struct.pack_into('<QQQQQ', result, 168, 0, 0, 0, blocks, height)
    return bytes(result)


class SessionModel(NativeSessionVerifier):
    def __init__(self, limit=4096):
        self.history_limit = limit
        self._session_mutex = threading.RLock()
        self._handle, self._record_ids, self._states = 0, [], []
        self._registry, self._context = b'LBV2RG01', bytes(64)
        self._genesis = b'LBV2GN01' + struct.pack('<Q', 9) + bytes(52)
        self._policy = H.IssuancePolicy({})
        self.opens = self.applies = self.closes = self.native_blocks = 0
        self._session_calls = {'apply': self._apply, 'close': self._close}

    def _open(self):
        self.opens += 1
        self._handle = self.opens
        self.native_blocks = 0
        self._states = [self._decode_state(row(0, 9), 0, 9)]

    def _close(self, handle):
        self.closes += 1
        return 0

    def _apply(self, handle, packet, length, output, capacity):
        self.applies += 1
        if packet.raw[:length].endswith(b'invalid'):
            return -2
        height = struct.unpack_from('<Q', packet.raw, 12)[0]
        self.native_blocks += 1
        ctypes.memmove(output, row(self.native_blocks, height), H.STATE_BYTES)
        return 0


def candidate(height, proof=b'public-test-model'):
    return H.Candidate(height, b'LBV2BD01' + struct.pack('<I', 1), proof)


class SessionTests(unittest.TestCase):
    def test_only_new_suffix_is_applied_and_returned_state_is_not_mutable_cache(self):
        verifier = SessionModel()
        history = [candidate(10), candidate(11)]
        first = verifier.replay(history[:1])
        first[-1]['height'] = 999
        self.assertEqual(verifier.replay(history[:1])[-1]['height'], 10)
        self.assertEqual(verifier.applies, 1)
        self.assertEqual(verifier.replay(history)[-1]['blocks'], 2)
        self.assertEqual((verifier.opens, verifier.applies), (1, 2))

    def test_reorg_changed_bytes_and_shorter_history_reconstruct_from_genesis(self):
        verifier = SessionModel()
        history = [candidate(10), candidate(11)]
        verifier.replay(history)
        verifier.replay([candidate(10), candidate(11, b'other public proof')])
        self.assertEqual((verifier.opens, verifier.applies), (2, 4))
        verifier.replay(history[:1])
        self.assertEqual((verifier.opens, verifier.applies), (3, 5))

    def test_more_than_128_records_stream_without_legacy_history_buffer(self):
        verifier = SessionModel()
        history = [candidate(height) for height in range(10, 160)]
        states = verifier.replay(history)
        self.assertEqual(len(states), 151)
        self.assertEqual(states[-1]['blocks'], 150)
        self.assertEqual(verifier.applies, 150)
        verifier.replay(history)
        self.assertEqual(verifier.applies, 150)

    def test_native_failure_discards_every_cached_state(self):
        verifier = SessionModel()
        verifier.replay([candidate(10)])
        with self.assertRaises(H.RejectedBlock):
            verifier.replay([candidate(10), candidate(11, b'invalid')])
        self.assertEqual((verifier._handle, verifier._record_ids, verifier._states), (0, [], []))
        verifier.replay([candidate(10)])
        self.assertEqual(verifier.opens, 2)

    def test_declared_limit_and_state_invariants_are_enforced(self):
        verifier = SessionModel(limit=1)
        with self.assertRaises(H.RejectedBlock):
            verifier.replay([candidate(10), candidate(11)])
        self.assertEqual(verifier.opens, 0)
        with self.assertRaises(H.RejectedBlock):
            verifier._decode_state(row(1, 10), 2, 10)
        malformed = bytearray(row(0, 9)); malformed[104] = 1
        with self.assertRaises(H.RejectedBlock):
            verifier._decode_state(bytes(malformed), 0, 9)


if __name__ == '__main__':
    unittest.main()
