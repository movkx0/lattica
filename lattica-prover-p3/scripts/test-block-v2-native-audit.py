#!/usr/bin/env python3
"""Audit transport/journal boundary tests. The native model is NOT proof evidence."""
import ctypes
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
import weakref

import block_v2_host_store as H
from block_v2_native_audit import NativeReplayAuditor


def encoded_state(index):
    row = bytearray(H.STATE_BYTES)
    row[:8] = b'LBV2ST01'
    struct.pack_into('<QQQQQ', row, 168, index, index * 2, 0, index, 9 + index)
    return bytes(row)


def state(index):
    return {'state_root': '00' * 32, 'event_root': '00' * 32, 'anchor': '00' * 32,
            'supply': dict(issued='0', burned='0', shielded_pool='0', fees_paid='0'),
            'nullifiers': index, 'outputs': index * 2, 'events': 0, 'blocks': index, 'height': 9 + index}


def candidate(index, proof=b'model-root'):
    return H.Candidate(10 + index, b'LBV2BD01' + struct.pack('<I', 1), proof)


class NativeModel:
    def __init__(self):
        self.calls, self.mode, self.packet_grants = 0, None, []

    def __call__(self, _registry, _registry_len, _context, _context_len, _genesis, _genesis_len,
                 count, callback, context, output, capacity):
        self.calls += 1
        assert capacity == (count + 1) * H.STATE_BYTES
        if self.mode == 'before': self.before()
        packet = ctypes.create_string_buffer(H.MAX_BODY_BYTES + H.MAX_PROOF_BYTES + 1024)
        for index in range(count):
            if self.mode == 'skip': break
            requested = count if self.mode == 'index' else index
            length = ctypes.c_size_t()
            if callback(context, requested, packet, 1 if self.mode == 'capacity' else len(packet), ctypes.byref(length)) != 0:
                return 0 if self.mode == 'ignore-error' else -3
            raw = packet.raw[:length.value]
            assert raw[:8] == b'LBV2RP01' and struct.unpack_from('<I', raw, 8)[0] == 1
            self.packet_grants.append(struct.unpack_from('<Q', raw, 36)[0])
            if raw.endswith(b'invalid'):
                return -2
        if self.mode == 'after': self.after()
        result = b''.join(encoded_state(index) for index in range(count + 1))
        if self.mode == 'state': result = b'X' + result[1:]
        ctypes.memmove(output, result, len(result))
        return 0


class VerifierModel:
    def __init__(self, limit=150):
        self.history_limit = limit
        self.native = NativeModel()
        self._lib = SimpleNamespace(lattica_v2_research_host_audit_v2=self.native)
        self._registry, self._context = b'LBV2RG01model', bytes(64)
        self._genesis = b'LBV2GN01' + struct.pack('<Q', 9) + bytes(52)
        self._policy = H.IssuancePolicy({})
        self.configuration = dict(schema='audit-boundary-model', limit=limit)
        self.identity = dict(kind='explicit-noncryptographic-test-model')

    def replay(self, history):
        return [state(index) for index in range(len(history) + 1)]


class AuditTests(unittest.TestCase):
    def test_150_records_stream_once_without_retaining_candidates(self):
        verifier = VerifierModel()
        auditor = NativeReplayAuditor(verifier)
        references, calls = [], []
        def provider(index):
            self.assertTrue(all(ref() is None for ref in references))
            value = candidate(index, b'p' * (256 * 1024))
            references.append(weakref.ref(value)); calls.append(index)
            return value
        self.assertEqual(auditor.replay(150, provider), [state(i) for i in range(151)])
        self.assertEqual(calls, list(range(150)))
        self.assertTrue(all(ref() is None for ref in references))

    def test_declared_bounds_and_missing_abi_fail_before_native_work(self):
        verifier = VerifierModel()
        for count in [-1, 151, True, 1.5]:
            with self.subTest(count=count), self.assertRaises(H.RejectedBlock):
                NativeReplayAuditor(verifier).replay(count, candidate)
        for limit in [0, 151, True, 4097]:
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                NativeReplayAuditor(verifier, history_limit=limit)
        self.assertEqual(verifier.native.calls, 0)
        verifier._lib = SimpleNamespace()
        with self.assertRaises(H.HostStoreError): NativeReplayAuditor(verifier)

    def test_provider_exception_never_crosses_ffi_and_remains_the_cause(self):
        verifier = VerifierModel(); verifier.native.mode = 'ignore-error'
        error = RuntimeError('input became unavailable')
        def provider(_): raise error
        with self.assertRaises(H.RejectedBlock) as raised:
            NativeReplayAuditor(verifier).replay(1, provider)
        self.assertIs(raised.exception.__cause__, error)

    def test_invalid_callback_sequence_capacity_and_output_reject(self):
        for mode in ['index', 'skip', 'capacity', 'state']:
            with self.subTest(mode=mode), self.assertRaises(H.RejectedBlock):
                verifier = VerifierModel(); verifier.native.mode = mode
                NativeReplayAuditor(verifier).replay(2, candidate)

    def test_invalid_candidate_height_and_native_rejection_leave_no_cached_state(self):
        verifier = VerifierModel(); auditor = NativeReplayAuditor(verifier)
        for provider in [lambda _: candidate(1), lambda _: object(), lambda _: candidate(0, b'invalid')]:
            with self.subTest(provider=provider), self.assertRaises(H.RejectedBlock): auditor.replay(1, provider)
            self.assertEqual(auditor.replay(1, candidate), [state(0), state(1)])

    def test_issuance_authorization_comes_from_trusted_host(self):
        verifier = VerifierModel(); verifier._policy = H.IssuancePolicy({10: {0: 7}})
        NativeReplayAuditor(verifier).replay(1, candidate)
        self.assertEqual(verifier.native.packet_grants, [7])
        verifier._policy = H.IssuancePolicy({10: {1: 7}})
        with self.assertRaises(H.RejectedBlock): NativeReplayAuditor(verifier).replay(1, candidate)

    def journal(self, directory, count=2):
        verifier = VerifierModel()
        store = H.Store.create(Path(directory) / 'journal', verifier)
        if count:
            store._replace([candidate(i) for i in range(count)], expected_head=store.read().token, ancestor='current')
        return verifier, store

    def test_journal_audit_is_read_only_and_does_not_assert_durability(self):
        with tempfile.TemporaryDirectory() as directory:
            verifier, store = self.journal(directory, 150)
            pins = {str(p): H.sha(p.read_bytes()) for p in store.directory.rglob('*') if p.is_file()}
            result = NativeReplayAuditor(verifier).audit_journal(store.directory)
            self.assertEqual(result['verified_history_blocks'], 150)
            self.assertEqual(result['states'], [state(i) for i in range(151)])
            self.assertEqual(result['head']['token'], store.published_head_token())
            self.assertFalse(result['durability_confirmed'])
            self.assertFalse(result['head']['durability_confirmed'])
            self.assertEqual(result['native_blocks_applied'], 0)
            self.assertEqual(pins, {str(p): H.sha(p.read_bytes()) for p in store.directory.rglob('*') if p.is_file()})

    def test_journal_record_mutation_and_symlinks_reject(self):
        for symlink in [False, True]:
            with self.subTest(symlink=symlink), tempfile.TemporaryDirectory() as directory:
                verifier, store = self.journal(directory)
                tip = json.loads((store.directory / 'HEAD.json').read_bytes())['tip']
                path = store.directory / 'records' / (tip + '.json')
                if symlink:
                    target = Path(directory) / 'external'; target.write_bytes(path.read_bytes())
                    path.unlink(); path.symlink_to(target)
                else: path.write_bytes(path.read_bytes() + b' ')
                with self.assertRaises((H.CorruptStore, OSError)):
                    NativeReplayAuditor(verifier).audit_journal(store.directory)

    def test_record_is_reauthenticated_when_native_requests_it(self):
        with tempfile.TemporaryDirectory() as directory:
            verifier, store = self.journal(directory)
            tip = json.loads((store.directory / 'HEAD.json').read_bytes())['tip']
            path = store.directory / 'records' / (tip + '.json')
            verifier.native.mode = 'before'
            verifier.native.before = lambda: path.write_bytes(b'changed after inventory')
            with self.assertRaises(H.RejectedBlock) as raised:
                NativeReplayAuditor(verifier).audit_journal(store.directory)
            self.assertIsInstance(raised.exception.__cause__, H.CorruptStore)

    def test_changed_head_or_configuration_during_audit_reject(self):
        for name in ['HEAD.json', 'configuration.json']:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                verifier, store = self.journal(directory)
                verifier.native.mode = 'after'
                verifier.native.after = lambda: (store.directory / name).write_bytes(b'changed')
                with self.assertRaises(H.StaleHead): NativeReplayAuditor(verifier).audit_journal(store.directory)

    def test_recorded_head_state_is_not_verification_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            verifier, store = self.journal(directory)
            path = store.directory / 'HEAD.json'; head = json.loads(path.read_bytes())
            head['state']['anchor'] = '11' * 32; path.write_bytes(H.canonical(head))
            with self.assertRaises(H.CorruptStore): NativeReplayAuditor(verifier).audit_journal(store.directory)

    def test_journal_declared_history_limit_is_enforced_before_native_work(self):
        with tempfile.TemporaryDirectory() as directory:
            verifier, store = self.journal(directory)
            with self.assertRaises(H.CorruptStore):
                NativeReplayAuditor(verifier, history_limit=1).audit_journal(store.directory)
            self.assertEqual(verifier.native.calls, 0)


if __name__ == '__main__':
    unittest.main()
