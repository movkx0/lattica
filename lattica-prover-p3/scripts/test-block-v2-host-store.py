#!/usr/bin/env python3
"""Persistence/fault tests with a declared stub, never cryptographic qualification."""
import base64
import copy
import errno
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

import block_v2_host_store as H


class TestVerifier:
    configuration = {'schema': 'persistence-test-only', 'verifier': 'explicit-unit-test-stub'}
    identity = {'kind': 'explicit-unit-test-stub', 'cryptographic_verification': False}

    def replay(self, candidates):
        state = {'state_root': H.sha(b'genesis'), 'event_root': H.sha(b'events'),
                 'anchor': H.sha(b'anchor'), 'height': 9, 'blocks': 0,
                 'nullifiers': 0, 'outputs': 128, 'events': 0,
                 'supply': {'issued': '100', 'burned': '0', 'shielded_pool': '100', 'fees_paid': '0'}}
        states, spent = [copy.deepcopy(state)], set()
        for candidate in candidates:
            candidate.validate()
            if (candidate.height != state['height'] + 1 or candidate.body in spent or
                    candidate.proof != b'test-proof:' + H.sha(candidate.body).encode()):
                raise H.RejectedBlock('test verifier rejected invalid height, spend or stub proof')
            spent.add(candidate.body)
            count = H.body_count(candidate.body)
            state['state_root'] = H.sha(bytes.fromhex(state['state_root']) + candidate.body)
            state['event_root'] = H.sha(bytes.fromhex(state['event_root']) + candidate.body)
            state['anchor'] = H.sha(bytes.fromhex(state['anchor']) + candidate.body)
            state['height'] = candidate.height
            state['blocks'] += 1
            state['nullifiers'] += 2 * count
            state['outputs'] += 2 * count
            state['events'] += count // 4
            issued = str(int(state['supply']['issued']) + 7 * (count // 4))
            state['supply'].update(issued=issued, shielded_pool=issued)
            states.append(copy.deepcopy(state))
        return states


def candidate(height=10, label=b'first', count=4):
    data = b'LBV2BD01' + struct.pack('<I', count) + label
    return H.Candidate(height, data, b'test-proof:' + H.sha(data).encode())


def store(path):
    return H.Store.create(path, TestVerifier())


def rewrite_tip(directory, mutate):
    head_path = directory / 'HEAD.json'
    head = json.loads(head_path.read_bytes())
    record_path = directory / 'records' / (head['tip'] + '.json')
    row = json.loads(record_path.read_bytes())
    mutate(row)
    encoded = H.canonical(row)
    tip = H.sha(encoded)
    (directory / 'records' / (tip + '.json')).write_bytes(encoded)
    head['tip'] = tip
    head_path.write_bytes(H.canonical(head))


class HostStoreTests(unittest.TestCase):
    def test_head_observation_does_not_replay_or_grant_validity(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            current = store(Path(directory) / 'store')
            verified = current.read()
            with patch.object(current.verifier, 'replay', side_effect=AssertionError('observation replayed')):
                self.assertEqual(current.published_head_token(), verified.token)
                path = current.directory / 'HEAD.json'
                path.write_bytes(b'changed but unverified head')
                self.assertNotEqual(current.published_head_token(), verified.token)
            with self.assertRaises(H.CorruptStore):
                current.snapshot()

    def test_head_observation_retains_file_size_and_symlink_guards(self):
        with tempfile.TemporaryDirectory() as directory:
            current = store(Path(directory) / 'store')
            path = current.directory / 'HEAD.json'
            path.write_bytes(b'x' * 16385)
            with self.assertRaises(H.CorruptStore):
                current.published_head_token()
            path.unlink()
            target = Path(directory) / 'other-head'
            target.write_bytes(b'other-head')
            path.symlink_to(target)
            with self.assertRaises(OSError):
                current.published_head_token()

    def test_exact_application_recovery_reconstructs_parent_without_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            current = store(Path(directory) / 'store')
            parent = current.read()
            applied = current.commit(candidate(), expected_head=parent.token)
            reopened = H.Store(current.directory, TestVerifier())
            published, previous = reopened.recover_application(
                candidate(), expected_parent=parent.token, expected_generation=parent.generation)
            self.assertEqual((published, previous), (applied, parent))
            self.assertEqual(reopened.read(), applied)
            self.assertEqual(len(reopened.snapshot()[1]), 1)

    def test_application_recovery_rejects_other_proof_parent_and_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            current = store(Path(directory) / 'store')
            parent = current.read()
            current.commit(candidate(), expected_head=parent.token)
            for proof, token, generation in (
                    (candidate(label=b'other'), parent.token, 0),
                    (H.Candidate(10, candidate().body, b'other-proof'), parent.token, 0),
                    (candidate(), 'ff' * 32, 0),
                    (candidate(), parent.token, 1)):
                with self.subTest(token=token, generation=generation, proof=proof):
                    with self.assertRaises(H.StaleHead):
                        current.recover_application(proof, expected_parent=token,
                                                    expected_generation=generation)
            with self.assertRaises(H.RejectedBlock):
                current.recover_application(candidate(), expected_parent=parent.token,
                                            expected_generation=False)

    def test_application_recovery_rejects_same_block_republished_after_reorg(self):
        with tempfile.TemporaryDirectory() as directory:
            current = store(Path(directory) / 'store')
            parent = current.read()
            applied = current.commit(candidate(), expected_head=parent.token)
            replacement = current.reorganize(None, [candidate()], expected_head=applied.token)
            self.assertEqual(replacement.tip, applied.tip)
            with self.assertRaises(H.StaleHead):
                current.recover_application(candidate(), expected_parent=parent.token,
                                            expected_generation=parent.generation)

    def test_application_recovery_rejects_head_change_after_verified_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            current = store(Path(directory) / 'store')
            parent = current.read()
            current.commit(candidate(), expected_head=parent.token)
            original = current.snapshot
            def changed():
                snapshot = original()
                current.commit(candidate(11, b'next'), expected_head=snapshot[0].token)
                return snapshot
            current.snapshot = changed
            with self.assertRaises(H.StaleHead):
                current.recover_application(candidate(), expected_parent=parent.token,
                                            expected_generation=parent.generation)

    def test_snapshot_fences_multi_height_and_reorg_results(self):
        with tempfile.TemporaryDirectory() as directory:
            current = store(Path(directory) / 'store')
            genesis, branch = current.snapshot()
            self.assertEqual(branch, ())
            first = candidate(10)
            committed = current.commit(first, expected_head=genesis.token)
            snapshot, branch = current.snapshot()
            self.assertEqual(snapshot, committed)
            self.assertEqual(branch, (first,))
            second = candidate(11, count=3)
            with self.assertRaises(H.StaleHead):
                current.commit(second, expected_head=genesis.token)
            advanced = current.commit(second, expected_head=snapshot.token)
            self.assertEqual(current.snapshot()[1], (first, second))
            rolled_back = current.reorganize(snapshot.tip, [], expected_head=advanced.token)
            self.assertEqual(rolled_back.state, snapshot.state)
            self.assertNotEqual(rolled_back.token, snapshot.token)
            with self.assertRaises(H.StaleHead):
                current.commit(second, expected_head=snapshot.token)
            self.assertEqual(current.snapshot()[1], branch)

    def test_commit_and_restart_preserve_verified_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'store'
            original = store(path)
            before = original.read()
            after = original.commit(candidate(), expected_head=before.token)
            recovered = H.Store(path, TestVerifier()).read()
            self.assertEqual(after, recovered)
            self.assertEqual(recovered.state['nullifiers'], 8)
            self.assertEqual(recovered.state['events'], 1)
            self.assertEqual(recovered.state['supply']['issued'], '107')
            self.assertTrue(recovered.durability_confirmed)

    def test_invalid_proof_and_height_never_publish(self):
        with tempfile.TemporaryDirectory() as tmp:
            current = store(Path(tmp) / 'store')
            before = current.read()
            for c in (H.Candidate(10, candidate().body, b'invalid'), candidate(11)):
                with self.assertRaises(H.RejectedBlock):
                    current.commit(c, expected_head=before.token)
                self.assertEqual(before, current.read())
                self.assertEqual(list((current.directory / 'records').glob('*.json')), [])

    def test_stale_head_and_rollback_aba_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            current = store(Path(tmp) / 'store')
            before = current.read()
            first = current.commit(candidate(), expected_head=before.token)
            with self.assertRaises(H.StaleHead):
                current.commit(candidate(11, b'next'), expected_head=before.token)
            rolled = current.reorganize(None, [], expected_head=first.token)
            self.assertEqual(rolled.state, before.state)
            self.assertNotEqual(rolled.token, before.token)
            with self.assertRaises(H.StaleHead):
                current.commit(candidate(), expected_head=before.token)
            applied = current.commit(candidate(), expected_head=rolled.token)
            self.assertEqual(applied.state, first.state)

    def test_reorg_restores_all_native_state_and_retains_old_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            current = store(Path(tmp) / 'store')
            first = current.commit(candidate(), expected_head=current.read().token)
            second = current.commit(candidate(11, b'second'), expected_head=first.token)
            branch = current.reorganize(first.tip, [candidate(11, b'alternate', 1)], expected_head=second.token)
            expected = TestVerifier().replay([candidate(), candidate(11, b'alternate', 1)])[-1]
            self.assertEqual(branch.state, expected)
            self.assertEqual(branch.state['events'], 1)
            self.assertEqual(branch.state['supply']['issued'], '107')
            self.assertEqual(branch.state['nullifiers'], 10)
            self.assertEqual(len(list((current.directory / 'records').glob('*.json'))), 3)
            self.assertEqual(H.Store(current.directory, TestVerifier()).read(), branch)

    def test_invalid_reorg_suffix_and_unknown_ancestor_preserve_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            current = store(Path(tmp) / 'store')
            first = current.commit(candidate(), expected_head=current.read().token)
            for ancestor, suffix in ((None, [candidate(), H.Candidate(11, candidate(11).body, b'bad')]),
                                     ('f' * 64, [])):
                with self.assertRaises(H.HostStoreError):
                    current.reorganize(ancestor, suffix, expected_head=first.token)
                self.assertEqual(first, current.read())
                self.assertEqual(len(list((current.directory / 'records').glob('*.json'))), 1)

    def test_changed_trusted_configuration_rejects_before_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            current = store(Path(tmp) / 'store')
            verifier = TestVerifier()
            verifier.configuration = {**verifier.configuration, 'genesis': 'different'}
            with self.assertRaises(H.CorruptStore):
                H.Store(current.directory, verifier).read()

    def test_hash_corruption_and_self_consistent_invalid_proof_reject(self):
        for kind in ('raw', 'proof', 'state'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                current = store(Path(tmp) / 'store')
                view = current.commit(candidate(), expected_head=current.read().token)
                if kind == 'raw':
                    path = current.directory / 'records' / (view.tip + '.json')
                    path.write_bytes(path.read_bytes() + b' ')
                elif kind == 'proof':
                    rewrite_tip(current.directory, lambda r: r.update(
                        proof=base64.b64encode(b'bad').decode(), proof_sha256=H.sha(b'bad')))
                else:
                    rewrite_tip(current.directory, lambda r: r['state'].update(nullifiers=0))
                with self.assertRaises(H.HostStoreError):
                    H.Store(current.directory, TestVerifier()).read()

    def test_missing_record_duplicate_json_and_symlinks_fail_closed(self):
        for kind in ('missing', 'duplicate', 'symlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                current = store(Path(tmp) / 'store')
                view = current.commit(candidate(), expected_head=current.read().token)
                if kind == 'missing':
                    (current.directory / 'records' / (view.tip + '.json')).unlink()
                elif kind == 'duplicate':
                    path = current.directory / 'HEAD.json'
                    path.write_bytes(b'{"schema":"duplicate",' + path.read_bytes()[1:])
                else:
                    head = current.directory / 'HEAD.json'
                    backup = Path(tmp) / 'external.json'
                    head.rename(backup)
                    head.symlink_to(backup)
                with self.assertRaises((H.HostStoreError, OSError)):
                    current.read()

    def test_storage_failures_before_publication_leave_old_head_and_allow_retry(self):
        for stage in ('record_file_synced', 'record_directory_synced', 'head_file_synced'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as tmp:
                current = store(Path(tmp) / 'store')
                before = current.read()

                def fail(actual):
                    if actual == stage:
                        raise OSError(errno.ENOSPC, 'injected no space')

                failing = H.Store(current.directory, TestVerifier(), fault_hook=fail)
                with self.assertRaises(OSError):
                    failing.commit(candidate(), expected_head=before.token)
                self.assertEqual(current.read(), before)
                after = current.commit(candidate(), expected_head=before.token)
                self.assertEqual(after.state['blocks'], 1)

    def test_failure_after_head_replace_requires_recovery_and_fences_retry(self):
        for stage in ('head_replaced', 'head_directory_synced'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as tmp:
                current = store(Path(tmp) / 'store')
                before = current.read()

                def fail(actual):
                    if actual == stage:
                        raise OSError(errno.EIO, 'injected sync uncertainty')

                failing = H.Store(current.directory, TestVerifier(), fault_hook=fail)
                with self.assertRaises(H.CommitIndeterminate):
                    failing.commit(candidate(), expected_head=before.token)
                after = H.Store(current.directory, TestVerifier()).read()
                self.assertEqual(after.state['blocks'], 1)
                with self.assertRaises(H.StaleHead):
                    current.commit(candidate(), expected_head=before.token)

    def test_real_process_exit_at_each_publication_boundary(self):
        stages = ('record_file_synced', 'record_directory_synced', 'head_file_synced',
                  'head_replaced', 'head_directory_synced')
        for stage in stages:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as tmp:
                current = store(Path(tmp) / 'store')
                before = current.read()
                result = subprocess.run([sys.executable, __file__, '--crash-at', str(current.directory), stage],
                                        capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 77, result.stderr)
                after = H.Store(current.directory, TestVerifier()).read()
                published = stage in ('head_replaced', 'head_directory_synced')
                self.assertEqual(after.state['blocks'], int(published))
                if not published:
                    self.assertEqual(after, before)
                    self.assertEqual(current.commit(candidate(), expected_head=after.token).state['blocks'], 1)
                else:
                    self.assertEqual(current.commit(candidate(11, b'next'), expected_head=after.token).state['blocks'], 2)

    def test_competing_processes_cannot_publish_from_same_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            current = store(Path(tmp) / 'store')
            before = current.read()
            commands = [[sys.executable, __file__, '--compete', str(current.directory), before.token, label]
                        for label in ('alpha', 'beta')]
            processes = [subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for command in commands]
            results = [(p.communicate(timeout=20), p.returncode) for p in processes]
            self.assertEqual(sorted(code for _, code in results), [0, 78], results)
            self.assertEqual(current.read().state['blocks'], 1)

    def test_input_and_history_caps_and_independent_issuance_policy(self):
        policy = H.IssuancePolicy({10: {3: 7}})
        self.assertEqual(policy.for_block(10, 4), (0, 0, 0, 7))
        with self.assertRaises(H.RejectedBlock):
            policy.for_block(10, 3)
        for grants in ({True: {0: 7}}, {10: {64: 7}}, {10: {3: 0}}, {10: {3: 2**52}}):
            with self.assertRaises(ValueError):
                H.IssuancePolicy(grants)
        for c in (candidate(count=0), candidate(count=65), H.Candidate(True, candidate().body, b'x'),
                  H.Candidate(10, b'statement-only-json', b'x'), H.Candidate(10, candidate().body, b'')):
            with self.assertRaises(H.RejectedBlock):
                c.validate()
        with tempfile.TemporaryDirectory() as tmp:
            current = store(Path(tmp) / 'store')
            before = current.read()
            with self.assertRaises(H.RejectedBlock):
                current.reorganize(None, [candidate()] * (H.MAX_BLOCKS + 1), expected_head=before.token)
            self.assertEqual(before, current.read())


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--crash-at':
        directory, stage = sys.argv[2:]

        def crash(actual):
            if actual == stage:
                os._exit(77)

        current = H.Store(directory, TestVerifier(), fault_hook=crash)
        current.commit(candidate(), expected_head=current.read().token)
        raise SystemExit(79)
    if len(sys.argv) == 5 and sys.argv[1] == '--compete':
        directory, token, label = sys.argv[2:]
        try:
            H.Store(directory, TestVerifier()).commit(candidate(label=label.encode()), expected_head=token)
        except H.StaleHead:
            raise SystemExit(78)
        raise SystemExit(0)
    unittest.main()
