#!/usr/bin/env python3
"""History lifetime/corruption tests. The native model is NOT proof evidence."""
import base64
from dataclasses import replace
import importlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import time
import tracemalloc
import unittest
from unittest.mock import patch

if reference := os.environ.get('LATTICA_HISTORY_REFERENCE_SOURCE'):
    sys.path.insert(0, reference)

import block_v2_host_store as H

Session = importlib.import_module('test-block-v2-native-session')


class StorageModel(Session.SessionModel):
    configuration = {'schema': 'history-storage-model', 'verifier': 'explicit-test-stub'}
    identity = {'kind': 'explicit-test-stub', 'cryptographic_verification': False}


def fixture(path, count, proof_bytes=128):
    """Write canonical model records directly; do not claim native acceptance."""
    verifier = StorageModel(limit=151)
    store = H.Store.create(path, verifier)
    tip = None
    proof = b'model:' + bytes(proof_bytes - 6)
    encoded_proof = base64.b64encode(proof).decode()
    proof_sha = H.sha(proof)
    for index in range(1, count + 1):
        height = 9 + index
        body = b'LBV2BD01' + struct.pack('<IQ', 1, height)
        state = verifier._decode_state(Session.row(index, height), index, height)
        record = dict(schema=H.SCHEMA, configuration_sha256=store._configuration_sha,
            parent=tip, height=height, body=base64.b64encode(body).decode(), body_sha256=H.sha(body),
            proof=encoded_proof, proof_sha256=proof_sha, state=state, verified_by=verifier.identity)
        raw = H.canonical(record); tip = H.sha(raw)
        (store.directory / 'records' / (tip + '.json')).write_bytes(raw)
    state = verifier._decode_state(Session.row(count, 9 + count), count, 9 + count)
    store._publish(H.canonical(store._head(tip, state, count)))
    return store


def memory_measurement(count):
    with tempfile.TemporaryDirectory(prefix='lattica-history-model-') as directory:
        store = fixture(Path(directory) / 'journal', count, H.MAX_PROOF_BYTES)
        tracemalloc.start(); started = time.monotonic()
        view, history = store.snapshot()
        retained, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
        assert len(history) == count and view.state['blocks'] == count
        assert store.verifier.applies == count
        return dict(records=count, proof_bytes_per_record=H.MAX_PROOF_BYTES,
            retained_python_bytes=retained, peak_python_bytes=peak,
            snapshot_seconds=time.monotonic() - started,
            native_proofs_verified=0, explicit_storage_model=True)


class HistoryTests(unittest.TestCase):
    def test_full_size_records_do_not_accumulate_proof_payloads(self):
        small, large = memory_measurement(2), memory_measurement(150)
        print('history_memory ' + json.dumps(dict(small=small, large=large)), flush=True)
        self.assertLess(large['retained_python_bytes'], 4 << 20)
        self.assertLess(large['peak_python_bytes'], 32 << 20)
        self.assertLess(large['peak_python_bytes'] - small['peak_python_bytes'], 4 << 20)

    def test_lazy_slices_equality_and_unchanged_prefix_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            store = fixture(Path(directory) / 'journal', 3)
            view, history = store.snapshot()
            self.assertIsInstance(history, H.HistorySnapshot)
            self.assertEqual(history, tuple(history))
            self.assertEqual(history[::-1], tuple(reversed(tuple(history))))
            self.assertEqual(history[:0], ())
            self.assertEqual(history[-1].height, 12)
            for index in [3, -4]:
                with self.assertRaises(IndexError): history[index]
            # A native session already verified these exact pinned candidates.
            # Reuse must neither load every payload nor reapply its prefix.
            with patch.object(H.Store, '_read_record', side_effect=AssertionError('warm prefix reloaded')):
                self.assertEqual(store.verifier.replay(history)[-1], view.state)
            self.assertEqual(store.verifier.applies, 3)
            next_candidate = Session.candidate(13)
            applied = store.commit(next_candidate, expected_head=view.token)
            self.assertEqual(applied.state['blocks'], 4)
            self.assertEqual(store.verifier.applies, 4)
            self.assertEqual(len(history), 3)
            with self.assertRaises(H.StaleHead):
                store.commit(Session.candidate(14), expected_head=view.token)

    def test_changed_or_removed_pinned_record_rejects_and_discards_cold_session(self):
        with tempfile.TemporaryDirectory() as directory:
            store = fixture(Path(directory) / 'journal', 2)
            view, history = store.snapshot()
            path = store.directory / 'records' / (view.tip + '.json')
            original = path.read_bytes()
            for mutate in [lambda: path.write_bytes(b'changed'), path.unlink]:
                mutate(); store.verifier.close()
                with self.assertRaises(H.CorruptStore): store.verifier.replay(history)
                self.assertEqual((store.verifier._handle, store.verifier._record_ids, store.verifier._states), (0, [], []))
                with self.assertRaises(H.CorruptStore): store.read()
                path.write_bytes(original)
                self.assertEqual(store.read(), view)

    def test_warm_store_reauthenticates_records_before_cached_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            store = fixture(Path(directory) / 'journal', 2)
            view = store.read()
            path = store.directory / 'records' / (view.tip + '.json')
            path.write_bytes(b'changed after a successful native replay')
            with patch.object(store.verifier, 'replay', side_effect=AssertionError('unauthenticated replay')):
                with self.assertRaises(H.CorruptStore): store.snapshot()

    def test_loaded_bytes_must_match_the_cache_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            store = fixture(Path(directory) / 'journal', 1)
            _, history = store.snapshot()
            store.verifier.close()
            changed = H.HistorySnapshot(history._directory, history._configuration_sha,
                [replace(history._entries[0], identity='0' * 64)])
            with self.assertRaises(H.CorruptStore): store.verifier.replay(changed)
            self.assertEqual(store.verifier.applies, 1)
            self.assertEqual((store.verifier._handle, store.verifier._record_ids, store.verifier._states), (0, [], []))

    def test_self_consistent_changed_proof_requires_native_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            store = fixture(Path(directory) / 'journal', 2)
            store.read()
            head_path = store.directory / 'HEAD.json'; head = json.loads(head_path.read_bytes())
            row = json.loads((store.directory / 'records' / (head['tip'] + '.json')).read_bytes())
            row['proof'] = base64.b64encode(b'invalid').decode(); row['proof_sha256'] = H.sha(b'invalid')
            raw = H.canonical(row); head['tip'] = H.sha(raw)
            (store.directory / 'records' / (head['tip'] + '.json')).write_bytes(raw)
            head_path.write_bytes(H.canonical(head))
            with self.assertRaises(H.RejectedBlock): store.read()
            self.assertEqual((store.verifier._handle, store.verifier._record_ids, store.verifier._states), (0, [], []))

    def test_state_metadata_cannot_replace_the_removed_payload_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            store = fixture(Path(directory) / 'journal', 1)
            head_path = store.directory / 'HEAD.json'; head = json.loads(head_path.read_bytes())
            row = json.loads((store.directory / 'records' / (head['tip'] + '.json')).read_bytes())
            row['state']['padding'] = 'x' * (H.MAX_STATE_JSON_BYTES + 1)
            raw = H.canonical(row); head['tip'] = H.sha(raw)
            (store.directory / 'records' / (head['tip'] + '.json')).write_bytes(raw)
            head_path.write_bytes(H.canonical(head))
            with patch.object(store.verifier, 'replay', side_effect=AssertionError('oversized metadata admitted')):
                with self.assertRaises(H.CorruptStore): store.snapshot()

    def test_lazy_reads_keep_record_and_directory_symlink_guards(self):
        with tempfile.TemporaryDirectory() as directory:
            store = fixture(Path(directory) / 'journal', 1)
            view, history = store.snapshot()
            path = store.directory / 'records' / (view.tip + '.json')
            target = Path(directory) / 'other-record'; target.write_bytes(path.read_bytes())
            path.unlink(); path.symlink_to(target)
            with self.assertRaises(OSError): history[0]
            path.unlink(); path.write_bytes(target.read_bytes())
            records = store.directory / 'records'; moved = store.directory / 'retained-records'
            records.rename(moved); records.symlink_to(moved, target_is_directory=True)
            with self.assertRaises(H.CorruptStore): history[0]


if __name__ == '__main__':
    if sys.argv[1:] == ['--measure']:
        print(json.dumps(dict(measurements=[memory_measurement(2), memory_measurement(150)],
            source='retained-reference' if reference else 'current', native_proofs_verified=0)))
    else:
        unittest.main()
