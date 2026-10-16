#!/usr/bin/env python3
"""Durable intake contracts with explicit non-cryptographic native-host stubs."""

from concurrent.futures import ThreadPoolExecutor
import multiprocessing
from pathlib import Path
import sqlite3
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import block_v2_native_arrivals as A

H = A.H
HEAD = '11' * 32


def body(index):
    return b'LBV2BD01' + struct.pack('<II', 1, index)


class StubHost:
    def __init__(self):
        self.verifier = SimpleNamespace(configuration={'kind': 'explicit-non-cryptographic-stub'})
        self.view = SimpleNamespace(token=HEAD, generation=0)

    def read(self):
        return self.view


class StubCandidate:
    def __init__(self, fixture, host, count=2):
        self.fixture, self.store, self.count = fixture, host, count
        self.head = SimpleNamespace(token=host.read().token)
        self.binding = {'head_token': list(bytes.fromhex(self.head.token)), 'generation': 0,
                        'expected': {'count': count, 'block_height': 10}}
        self.manifest_pin = {'sha256': '22' * 32}
        self.receipt = None
        self.replays = 0

    def check(self, binding):
        if binding != self.binding or self.store.read().token != self.head.token:
            raise H.StaleHead('stub native head changed')

    def verify_application(self, receipt, proof, binding):
        self.replays += 1
        if binding != self.binding or receipt != self.receipt or proof != b'audited-root':
            raise H.RejectedBlock('stub native replay rejected application')


def child_submit(directory, stage):
    import os
    host = StubHost()
    store = A.Store(directory, host, fault_hook=lambda point: os._exit(73) if point == stage else None)
    store.submit('crash', expected_head=HEAD, body=body(90), wallet=b'wallet')


class IntakeTests(unittest.TestCase):
    def test_input_references_preserve_order_bytes_and_snapshot_receipts(self):
        for index in [2, 0, 1]:
            self.submit(index)
        requests = ['request-0', 'request-1']
        eager = self.store.candidate_inputs(expected_head=HEAD, request_ids=requests)
        refs = self.store.candidate_input_refs(expected_head=HEAD, request_ids=requests)
        self.assertEqual([[ref[key] for key in ['receipt', 'body', 'wallet']] for ref in refs],
                         [[row[key] for key in ['receipt', 'body', 'wallet']] for row in eager])
        changed = refs[0]['receipt']
        changed['metadata']['changed'] = True
        self.assertEqual(refs[0]['receipt'], eager[0]['receipt'])
        with self.assertRaises(KeyError):
            refs[0]['untrusted-column']
        import block_v2_pending_candidate as B
        self.assertEqual(B._complete(refs), B._complete(eager))

    def test_input_references_allow_late_arrivals_without_changing_the_snapshot(self):
        self.submit(0)
        refs = self.store.candidate_input_refs(expected_head=HEAD)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(self.submit, 1).result(timeout=5)
        self.assertEqual([ref['receipt']['request_id'] for ref in refs], ['request-0'])
        self.assertEqual(refs[0]['wallet'], b'\0wallet')

    def test_input_reference_payload_hashes_are_checked_on_every_fetch(self):
        self.submit(0)
        ref = self.store.candidate_input_refs(expected_head=HEAD)[0]
        for name, original in [('body', body(0)), ('wallet', b'\0wallet')]:
            with self.subTest(name=name):
                changed = original[:-1] + bytes([original[-1] ^ 1])
                with self.store._transaction() as connection:
                    connection.execute('UPDATE arrivals SET ' + name + '=? WHERE request_id=?',
                                       (changed, 'request-0'))
                # Reading metadata is not proof or payload authentication.
                pending = self.store.candidate_input_refs(expected_head=HEAD)[0]
                for retained in [ref, pending]:
                    with self.assertRaisesRegex(A.IntakeError, 'payload changed'):
                        retained[name]
                with self.store._transaction() as connection:
                    connection.execute('UPDATE arrivals SET ' + name + '=? WHERE request_id=?',
                                       (original, 'request-0'))
                self.assertEqual(ref[name], original)

    def test_input_reference_rejects_self_consistent_replacement_and_metadata_change(self):
        self.submit(0)
        ref = self.store.candidate_input_refs(expected_head=HEAD)[0]
        with self.store._transaction() as connection:
            connection.execute('UPDATE arrivals SET wallet=?,wallet_sha256=? WHERE request_id=?',
                               (b'changed', H.sha(b'changed'), 'request-0'))
        with self.assertRaisesRegex(A.IntakeError, 'receipt changed'):
            ref['wallet']
        replacement = self.store.candidate_input_refs(expected_head=HEAD)[0]
        self.assertEqual(replacement['wallet'], b'changed')
        with self.store._transaction() as connection:
            connection.execute('UPDATE arrivals SET received_unix_ns=? WHERE request_id=?', ('1', 'request-0'))
        with self.assertRaisesRegex(A.IntakeError, 'receipt changed'):
            replacement['body']

    def test_input_reference_rejects_claimed_and_deleted_arrivals(self):
        self.submit(0)
        self.submit(1)
        refs = self.store.candidate_input_refs(expected_head=HEAD)
        self.store.seal(self.candidate, ['request-0', 'request-1'])
        for key in ['body', 'wallet']:
            with self.assertRaisesRegex(A.IntakeError, 'already sealed or applied'):
                refs[0][key]
        self.submit(2)
        ref = self.store.candidate_input_refs(expected_head=HEAD)[0]
        with self.store._transaction() as connection:
            connection.execute('DELETE FROM arrivals WHERE request_id=?', ('request-2',))
        with self.assertRaises(A.IntakeError):
            ref['wallet']

    def test_reference_bounds_reject_before_materializing_oversized_payloads(self):
        store = A.Store.create(self.root / 'larger', self.host,
                               A.Limits(16, 4 * 1024**2, 8 * 1024**2, 64))
        store.submit('one', expected_head=HEAD, body=body(0), wallet=b'wallet')
        ref = store.candidate_input_refs(expected_head=HEAD)[0]
        for name, size, original in [('body', H.MAX_BODY_BYTES + 1, body(0)),
                                     ('wallet', H.MAX_PROOF_BYTES + 1, b'wallet'),
                                     ('metadata', 4097, H.canonical({}))]:
            with self.subTest(name=name):
                with store._transaction() as connection:
                    connection.execute('UPDATE arrivals SET ' + name + '=zeroblob(?) WHERE request_id=?', (size, 'one'))
                with self.assertRaisesRegex(A.IntakeError, 'oversized arrival reference'):
                    store.candidate_input_refs(expected_head=HEAD)
                with self.assertRaisesRegex(A.IntakeError, 'oversized arrival reference'):
                    ref['wallet']
                with store._transaction() as connection:
                    connection.execute('UPDATE arrivals SET ' + name + '=? WHERE request_id=?', (original, 'one'))
        self.assertEqual(ref['body'], body(0))

    def test_input_reference_snapshot_keeps_head_order_and_count_guards(self):
        original = self.submit(0)
        for limit in [0, 4097, True]:
            with self.assertRaises(ValueError):
                self.store.candidate_input_refs(expected_head=HEAD, limit=limit)
        with self.assertRaises(ValueError):
            self.store.candidate_input_refs(expected_head=HEAD, request_ids=['request-0', 'request-0'])
        self.host.view = SimpleNamespace(token='33' * 32, generation=1)
        with self.assertRaises(H.StaleHead):
            self.store.candidate_input_refs(expected_head=HEAD)
        refs = self.store.candidate_input_refs(expected_head=self.host.view.token)
        self.assertEqual(refs[0]['receipt'], original)
        self.assertEqual(refs[0]['wallet'], b'\0wallet')

    def test_bounded_seal_clock_is_durable_and_cannot_be_refreshed_by_resealing(self):
        import block_v2_pool_seal as S
        boot = '01234567-89ab-cdef-0123-456789abcdef'
        workflow = {'schema_version': 1, 'boot_id': boot, 'started_monotonic_ms': 100000,
                    'deadline_monotonic_ms': 700000}
        self.submit(0)
        self.submit(1)
        with patch.object(S.T, 'workflow_clock', return_value=(boot, 200000)):
            selected = self.store.seal(self.candidate, ['request-0', 'request-1'], pool_workflow=workflow)
        self.assertEqual(selected['pool_seal']['sealed_monotonic_ms'], 200000)
        self.assertEqual(selected['pool_seal']['deadline_monotonic_ms'], 380000)
        reopened = A.Store(self.directory, self.host)
        self.assertEqual(reopened.check_selection(selected['selection_id'], self.candidate), selected)
        before = reopened.snapshot()
        with patch.object(S.T, 'workflow_clock', return_value=(boot, 210000)), self.assertRaises(A.IntakeError):
            reopened.seal(self.candidate, ['request-0', 'request-1'], pool_workflow=workflow)
        self.assertEqual(reopened.snapshot(), before)
        self.assertEqual(reopened.check_selection(selected['selection_id'], self.candidate), selected)

    def test_seal_expiring_during_validation_cannot_publish_claims(self):
        import block_v2_pool_seal as S
        boot = '01234567-89ab-cdef-0123-456789abcdef'
        workflow = {'schema_version': 1, 'boot_id': boot, 'started_monotonic_ms': 100000,
                    'deadline_monotonic_ms': 700000}
        self.submit(0)
        self.submit(1)
        before = self.store.snapshot()
        with patch.object(S.T, 'workflow_clock', side_effect=[(boot, 200000), (boot, 380000)]), self.assertRaises(ValueError):
            self.store.seal(self.candidate, ['request-0', 'request-1'], pool_workflow=workflow)
        self.assertEqual(self.store.snapshot(), before)

    def test_application_recovery_accepts_sealed_or_exact_applied_receipt(self):
        selected = self.seal()
        receipt = {'head_token': '55' * 32, 'generation': 1}
        self.host.view = SimpleNamespace(token=receipt['head_token'], generation=1)
        self.candidate.current_head = self.host.view
        self.candidate.recovered_receipt = self.candidate.receipt = receipt
        self.candidate.check = lambda binding: self.assertEqual(binding, self.candidate.binding)
        self.assertEqual(self.store.check_selection(selected['selection_id'], self.candidate), selected)
        applied = self.store.record_application(selected['selection_id'], self.candidate, receipt, b'audited-root')
        self.assertEqual(self.store.check_selection(selected['selection_id'], self.candidate), applied)
        events = self.store.snapshot()['events']
        self.assertEqual(self.store.record_application(selected['selection_id'], self.candidate,
                                                       receipt, b'audited-root'), applied)
        self.assertEqual(self.store.snapshot()['events'], events)
        self.candidate.recovered_receipt = receipt | {'generation': 2}
        with self.assertRaises(A.IntakeError):
            self.store.check_selection(selected['selection_id'], self.candidate)
        self.candidate.recovered_receipt = receipt
        self.host.view = SimpleNamespace(token='66' * 32, generation=2)
        with self.assertRaises(H.StaleHead):
            self.store.check_selection(selected['selection_id'], self.candidate)

    def test_unsealed_prefix_checks_receipts_without_claiming_or_sealing(self):
        candidate = self.revalidated_candidate([self.submit(0), self.submit(1)])
        candidate.prefix = True
        before = self.store.snapshot()
        self.store.check_prefix(candidate)
        self.assertEqual(self.store.snapshot(), before)
        with self.assertRaises(A.IntakeError):
            self.store.seal(candidate, ['request-0', 'request-1'])
        self.assertEqual(self.store.snapshot(), before)

    def revalidated_candidate(self, receipts):
        self.host.view = SimpleNamespace(token='22' * 32, generation=1)
        candidate = StubCandidate(self.fixture, self.host)
        pending = {'native_head': candidate.head.token,
                   'host_configuration_sha256': self.store.configuration,
                   'request_ids': [r['request_id'] for r in receipts], 'arrivals': receipts}
        path = self.fixture / 'pending-arrivals.json'
        data = H.canonical(pending)
        path.write_bytes(data)
        manifest = {'arrival_head_revalidation': True, 'preparation_backend': 'durable-pending-arrivals',
                    'status': 'succeeded', 'native_state_preflight_passed': True,
                    'independently_cpu_verified_wallets': 2, 'parent_head_token': candidate.head.token,
                    'request_ids': pending['request_ids'], 'revalidated_request_ids': pending['request_ids'],
                    'sources': [{'path': str(path), 'sha256': H.sha(data), 'bytes': len(data)}]}
        candidate.manifest_path = self.fixture / 'manifest.json'
        candidate.manifest_path.write_bytes(H.canonical(manifest))
        candidate.manifest_pin = {'sha256': H.sha(H.canonical(manifest))}
        return candidate

    def test_revalidated_selection_preserves_original_receipts_and_retry(self):
        receipts = [self.submit(0), self.submit(1)]
        candidate = self.revalidated_candidate(receipts)
        pool = self.store.candidate_inputs(expected_head=candidate.head.token)
        self.assertEqual([r['receipt'] for r in pool], receipts)
        with self.assertRaises(A.IntakeError):
            self.store.pending_inputs(expected_head=candidate.head.token)
        selected = self.store.seal(candidate, ['request-0', 'request-1'])
        self.store.check_selection(selected['selection_id'], candidate)
        self.assertEqual([self.submit(0), self.submit(1)], receipts)
        snapshot = self.store.snapshot()
        self.assertEqual([r['head_token'] for r in snapshot['arrivals']], [HEAD, HEAD])
        self.assertEqual([r['status'] for r in snapshot['arrivals']], ['sealed', 'sealed'])
        self.assertEqual(len(snapshot['events'][-1]['document']['revalidated_arrivals']), 2)
        self.store.cancel(selected['selection_id'], 'operator_cancelled')
        self.assertEqual([r['status'] for r in self.store.snapshot()['arrivals']], ['stale', 'stale'])

    def test_changed_original_receipt_cannot_authorize_revalidation(self):
        receipts = [self.submit(0), self.submit(1)]
        receipts[0] = receipts[0] | {'received_unix_ns': '1'}
        candidate = self.revalidated_candidate(receipts)
        with self.assertRaises(H.StaleHead):
            self.store.seal(candidate, ['request-0', 'request-1'])
        self.assertEqual(self.store.snapshot()['selections'], [])

    def test_revalidation_is_fenced_by_native_head(self):
        candidate = self.revalidated_candidate([self.submit(0), self.submit(1)])
        self.host.view = SimpleNamespace(token='33' * 32, generation=2)
        with self.assertRaises(H.StaleHead):
            self.store.seal(candidate, ['request-0', 'request-1'])
        self.assertEqual(self.store.snapshot()['selections'], [])

    def test_revalidation_requires_pinned_cpu_checked_preparation(self):
        candidate = self.revalidated_candidate([self.submit(0), self.submit(1)])
        changed = H._json(candidate.manifest_path.read_bytes())
        changed['independently_cpu_verified_wallets'] = 1
        candidate.manifest_path.write_bytes(H.canonical(changed))
        with self.assertRaises(A.IntakeError):
            self.store.seal(candidate, ['request-0', 'request-1'])
        self.assertEqual(self.store.snapshot()['selections'], [])

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.host = StubHost()
        self.directory = self.root / 'intake'
        self.limits = A.Limits(16, 1024**2, 2 * 1024**2, 64)
        self.store = A.Store.create(self.directory, self.host, self.limits)
        self.fixture = self.root / 'fixture'
        self.fixture.mkdir()
        for i in range(3):
            (self.fixture / f'complete-body.{i}').write_bytes(body(i))
            (self.fixture / f'wallet.{i}').write_bytes(bytes([i]) + b'wallet')
        self.candidate = StubCandidate(self.fixture, self.host)

    def submit(self, index, request=None):
        return self.store.submit(request or f'request-{index}', expected_head=HEAD, body=body(index),
                                 wallet=bytes([index]) + b'wallet')

    def seal(self):
        self.submit(0)
        self.submit(1)
        return self.store.seal(self.candidate, ['request-0', 'request-1'])

    def test_receipt_survives_reopen_and_exact_retry(self):
        received = self.submit(0)
        reopened = A.Store(self.directory, self.host)
        self.assertEqual(reopened.submit('request-0', expected_head=HEAD, body=body(0), wallet=b'\0wallet'), received)
        snap = reopened.snapshot()
        self.assertEqual(len(snap['events']), 1)
        self.assertEqual(snap['arrivals'][0]['status'], 'pending')
        self.assertEqual(received['validation'], 'pending_native_candidate_and_proof')

    def test_request_substitution_and_duplicate_transaction_rejected(self):
        self.submit(0)
        with self.assertRaises(A.IntakeError):
            self.submit(1, 'request-0')
        with self.assertRaises(A.DuplicateTransaction):
            self.submit(0, 'different-id')
        self.assertEqual(len(self.store.snapshot()['events']), 1)

    def test_stale_head_rejected_but_old_receipt_can_be_retried(self):
        original = self.submit(0)
        self.host.view = SimpleNamespace(token='33' * 32, generation=1)
        with self.assertRaises(H.StaleHead):
            self.submit(1)
        self.assertEqual(self.submit(0), original)
        self.assertEqual(self.store.snapshot()['arrivals'][0]['status'], 'stale')

    def test_pending_snapshot_preserves_arrival_or_explicit_host_order(self):
        for index in [2, 0, 1]:
            self.submit(index)
        automatic = self.store.pending_inputs(expected_head=HEAD, limit=2)
        self.assertEqual([r['receipt']['request_id'] for r in automatic], ['request-2', 'request-0'])
        ordered = self.store.pending_inputs(expected_head=HEAD, request_ids=['request-0', 'request-1'])
        self.assertEqual([r['body'] for r in ordered], [body(0), body(1)])
        self.assertEqual(len(self.store.snapshot()['events']), 3)
        self.store.seal(self.candidate, ['request-0', 'request-1'])
        self.assertEqual(len(self.store.pending_inputs(expected_head=HEAD)), 1)
        with self.assertRaises(A.IntakeError):
            self.store.pending_inputs(expected_head=HEAD, request_ids=['request-0'])

    def test_pending_snapshot_uses_the_native_128_profile_limit(self):
        self.submit(0)
        self.host.verifier.capacity = 128
        self.assertEqual(len(self.store.pending_inputs(expected_head=HEAD, limit=128)), 1)
        with self.assertRaises(ValueError):
            self.store.pending_inputs(expected_head=HEAD, limit=129)

    def test_pending_snapshot_rejects_changed_head_and_invalid_bounds(self):
        self.submit(0)
        for limit in (0, 65, True):
            with self.assertRaises(ValueError):
                self.store.pending_inputs(expected_head=HEAD, limit=limit)
        self.host.view = SimpleNamespace(token='33' * 32, generation=1)
        with self.assertRaises(H.StaleHead):
            self.store.pending_inputs(expected_head=HEAD)
        with self.assertRaises(H.StaleHead):
            self.store.pending_inputs(expected_head='33' * 32, request_ids=['request-0'])

    def test_seal_freezes_order_and_late_arrivals_remain_pending(self):
        sealed = self.seal()
        self.submit(2)
        reopened = A.Store(self.directory, self.host)
        self.assertEqual(reopened.check_selection(sealed['selection_id'], self.candidate), sealed)
        self.assertEqual([r['status'] for r in reopened.snapshot()['arrivals']], ['sealed', 'sealed', 'pending'])
        self.assertEqual(reopened.seal(self.candidate, ['request-0', 'request-1']), sealed)
        self.assertEqual(len(reopened.snapshot()['events']), 4)

    def test_seal_rejects_reordered_missing_or_substituted_payloads(self):
        self.submit(0)
        self.submit(1)
        for ids in (['request-1', 'request-0'], ['request-0', 'missing']):
            with self.assertRaises(A.IntakeError):
                self.store.seal(self.candidate, ids)
        (self.fixture / 'wallet.1').write_bytes(b'wrong')
        with self.assertRaises(A.IntakeError):
            self.store.seal(self.candidate, ['request-0', 'request-1'])
        self.assertFalse(self.store.snapshot()['selections'])

    def test_one_arrival_cannot_belong_to_two_active_selections(self):
        self.seal()
        self.candidate.manifest_pin['sha256'] = '44' * 32
        with self.assertRaises(A.IntakeError):
            self.store.seal(self.candidate, ['request-0', 'request-1'])

    def test_cancel_releases_claims_but_preserves_history(self):
        selection = self.seal()
        self.store.cancel(selection['selection_id'], 'proving_failed')
        self.assertEqual([r['status'] for r in self.store.snapshot()['arrivals']], ['pending', 'pending'])
        self.candidate.manifest_pin['sha256'] = '44' * 32
        next_selection = self.store.seal(self.candidate, ['request-0', 'request-1'])
        self.assertNotEqual(selection['selection_id'], next_selection['selection_id'])
        self.assertEqual(len(self.store.snapshot()['selections']), 2)

    def test_application_requires_native_replay_and_actual_intake_host_head(self):
        selected = self.seal()
        receipt = {'head_token': '55' * 32, 'generation': 1}
        with self.assertRaises(H.RejectedBlock):
            self.store.record_application(selected['selection_id'], self.candidate, receipt, b'audited-root')
        self.candidate.receipt = receipt
        with self.assertRaises(H.StaleHead):
            self.store.record_application(selected['selection_id'], self.candidate, receipt, b'audited-root')
        self.host.view = SimpleNamespace(token=receipt['head_token'], generation=1)
        applied = self.store.record_application(selected['selection_id'], self.candidate, receipt, b'audited-root')
        self.assertEqual(applied['status'], 'applied')
        self.assertEqual(self.store.verify_recorded_application(selected['selection_id'], self.candidate, receipt, b'audited-root'), applied)
        self.assertEqual(self.store.record_application(selected['selection_id'], self.candidate, receipt, b'audited-root'), applied)
        self.assertEqual(len(self.store.snapshot()['events']), 4)
        with self.assertRaises(A.IntakeError):
            self.store.cancel(selected['selection_id'], 'operator_cancelled')

    def test_payload_and_event_limits_rollback_whole_transaction(self):
        small = A.Store.create(self.root / 'small', self.host, A.Limits(1, 50, 128 * 1024, 1))
        small.submit('one', expected_head=HEAD, body=body(0), wallet=b'wallet')
        with self.assertRaises(A.IntakeError):
            small.submit('two', expected_head=HEAD, body=body(1), wallet=b'wallet')
        other = A.Store.create(self.root / 'event-bound', self.host, A.Limits(4, 100, 128 * 1024, 1))
        other.submit('one', expected_head=HEAD, body=body(0), wallet=b'wallet')
        with self.assertRaises(A.IntakeError):
            other.submit('two', expected_head=HEAD, body=body(1), wallet=b'wallet')
        self.assertEqual(len(other.snapshot()['arrivals']), 1)

    def test_failed_or_ambiguous_commit_has_recoverable_outcome(self):
        def fail(stage):
            if stage == 'before_commit':
                raise OSError('injected before commit')
        self.store.fault_hook = fail
        with self.assertRaises(OSError):
            self.submit(0)
        self.assertFalse(self.store.snapshot()['arrivals'])
        self.store.fault_hook = lambda stage: (_ for _ in ()).throw(OSError('after commit')) if stage == 'after_commit' else None
        with self.assertRaises(A.IntakeCommitIndeterminate):
            self.submit(0)
        self.store.fault_hook = None
        self.assertEqual(self.submit(0)['request_id'], 'request-0')
        self.assertEqual(len(self.store.snapshot()['events']), 1)

    def test_database_page_limit_preserves_previous_receipts(self):
        store = A.Store.create(self.root / 'database-bound', self.host,
                               A.Limits(16, 127 * 1024, 128 * 1024, 64))
        first = store.submit('first', expected_head=HEAD, body=body(0), wallet=b'x' * 50_000)
        with self.assertRaises(sqlite3.OperationalError):
            store.submit('second', expected_head=HEAD, body=body(1), wallet=b'y' * 50_000)
        snapshot = store.snapshot()
        self.assertEqual(len(snapshot['arrivals']), 1)
        self.assertEqual(snapshot['arrivals'][0]['transaction_sha256'], first['transaction_sha256'])
        self.assertLessEqual((store.directory / 'arrivals.sqlite3').stat().st_size, 128 * 1024)

    def test_fresh_process_recovers_both_crash_boundaries(self):
        for stage, expected in [('before_commit', 0), ('after_commit', 1)]:
            with self.subTest(stage=stage):
                directory = self.root / stage
                A.Store.create(directory, self.host, self.limits)
                process = multiprocessing.get_context('fork').Process(target=child_submit, args=(directory, stage))
                process.start()
                process.join(10)
                if process.is_alive():
                    process.kill()
                    process.join()
                    self.fail('crash child did not exit')
                self.assertEqual(process.exitcode, 73)
                recovered = A.Store(directory, self.host)
                self.assertEqual(len(recovered.snapshot()['arrivals']), expected)
                recovered.submit('crash', expected_head=HEAD, body=body(90), wallet=b'wallet')
                self.assertEqual(len(recovered.snapshot()['events']), 1)

    def test_concurrent_submitters_do_not_duplicate_receipts(self):
        def submit(_):
            return A.Store(self.directory, self.host).submit('same', expected_head=HEAD, body=body(0), wallet=b'wallet')
        with ThreadPoolExecutor(max_workers=4) as pool:
            receipts = list(pool.map(submit, range(8)))
        self.assertTrue(all(receipt == receipts[0] for receipt in receipts))
        self.assertEqual(len(self.store.snapshot()['events']), 1)

    def test_host_configuration_substitution_and_symlink_rejected(self):
        wrong = StubHost()
        wrong.verifier.configuration = {'kind': 'different-stub'}
        with self.assertRaises(A.IntakeError):
            A.Store(self.directory, wrong).snapshot()
        linked = self.root / 'linked'
        linked.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(A.IntakeError):
            A.Store(linked, self.host).snapshot()

    def test_retained_payload_and_selection_corruption_rejected(self):
        sealed = self.seal()
        connection = sqlite3.connect(self.directory / 'arrivals.sqlite3')
        connection.execute('UPDATE arrivals SET wallet=? WHERE request_id=?', (b'corrupt', 'request-0'))
        connection.commit()
        with self.assertRaises(A.IntakeError):
            self.store.check_selection(sealed['selection_id'], self.candidate)
        connection.execute('UPDATE selections SET document=? WHERE selection_id=?', (H.canonical({}), sealed['selection_id']))
        connection.commit()
        connection.close()
        with self.assertRaises(A.IntakeError):
            self.store.check_selection(sealed['selection_id'], self.candidate)

    def test_input_bounds_and_metadata_validation(self):
        for request in ('', '../outside', 'x' * 129):
            with self.assertRaises(ValueError):
                self.store.submit(request, expected_head=HEAD, body=body(0), wallet=b'w')
        for metadata in ([], {'value': float('nan')}, {'large': 'x' * 4096}):
            with self.assertRaises((ValueError, H.CorruptStore)):
                self.store.submit('invalid', expected_head=HEAD, body=body(0), wallet=b'w', metadata=metadata)
        self.assertFalse(self.store.snapshot()['arrivals'])


if __name__ == '__main__':
    unittest.main()
