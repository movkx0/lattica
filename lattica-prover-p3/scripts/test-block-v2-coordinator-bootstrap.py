#!/usr/bin/env python3
"""Admission and fail-closed recovery checks; no GPU work or synthetic proofs."""
import copy
import json
import os
import shutil
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import block_v2_coordinator_bootstrap as B


class CoordinatorBootstrap(unittest.TestCase):
    def recovering(self):
        self.plan['recover_from'] = '/old/owner/proofs'
        self.config['recover_from'] = self.plan['recover_from']
        self.plan_path.write_text(json.dumps(self.plan))
        self.config_path.write_text(json.dumps(self.config))
        shutil.rmtree(self.gate)
        B.create(self.config_path, self.root / 'controller.py')
        return self.owner / 'proofs'

    def test_interrupted_recovery_before_admission_retries_original_journal(self):
        proofs = self.recovering()
        proofs.mkdir()
        (proofs / 'coordinator.json').write_text('{partial')
        receipt = B.reconcile(self.config_path)
        self.assertFalse(receipt['abandoned_incomplete_new_candidate'])
        self.assertTrue(receipt['interrupted_existing_journal'])
        self.assertIsNone(receipt['recovery_admission'])
        self.assertEqual(receipt['retry_source'], '/old/owner/proofs')
        self.assertEqual((proofs / 'coordinator.json').read_text(), '{partial')

    def test_admitted_recovery_preserves_generation_and_recovered_proof_export(self):
        proofs = self.recovering()
        proofs.mkdir()
        state = dict(schema_version=1, epoch=2, durable_runtime='/old/owner/proofs/execution')
        admission = dict(schema_version=1, source=self.plan['recover_from'], state=state)
        for name, value in {'recovery-state.json': state, 'recovery-admission.json': admission,
                            'fleet-plan.json': self.plan, 'coordinator.json': {}, 'expected.json': {}}.items():
            (proofs / name).write_text(json.dumps(value))
        proof = proofs / 'node.1.0'
        proof.write_bytes(b'retained export; not a cryptographic fixture')
        receipt = B.reconcile(self.config_path)
        self.assertFalse(receipt['abandoned_incomplete_new_candidate'])
        self.assertEqual(receipt['retry_source'], str(proofs))
        self.assertEqual(receipt['recovery_admission'], admission)
        self.assertTrue(proof.exists())
        admission['state'] = dict(state, epoch=3)
        (proofs / 'recovery-admission.json').write_text(json.dumps(admission))
        with self.assertRaisesRegex(ValueError, 'metadata differs'):
            B.reconcile(self.config_path)

    def test_interrupted_recovery_cannot_hide_admitted_workers(self):
        proofs = self.recovering()
        path = proofs / 'execution/worker-0-startup/authorization.json'
        path.parent.mkdir(parents=True)
        path.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'work admitted before initialization'):
            B.reconcile(self.config_path)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.owner = self.root / 'owner'
        self.owner.mkdir()
        self.gate = self.owner / 'coordinator-startup'
        self.unit = 'lattica-v2-multi-owner-' + 'a' * 64 + '.service'
        self.plan = dict(startup_fenced=True, coordinator_bootstrap_guard=str(self.gate),
                         recover_from=None, workers=[])
        self.plan_path = self.root / 'fleet-plan.json'
        self.plan_path.write_text(json.dumps(self.plan))
        self.config = dict(owner_directory=str(self.owner), owner_unit=self.unit,
                           coordinator_bootstrap_guard=str(self.gate), fleet_plan=str(self.plan_path))
        self.config_path = self.root / 'config.json'
        self.config_path.write_text(json.dumps(self.config))
        B.create(self.config_path, self.root / 'controller.py')
        self.state = dict(LoadState='not-found', ActiveState='inactive', SubState='dead',
                          MainPID=0, ControlPID=0, Job='', InvocationID='', ControlGroup='')
        self.observer = mock.patch.object(B, 'observation', return_value=self.state)
        self.observer.start()
        self.fd_count = len(B._lifetime_fds)

    def tearDown(self):
        self.observer.stop()
        for fd in B._lifetime_fds[self.fd_count:]:
            os.close(fd)
        del B._lifetime_fds[self.fd_count:]
        self.temporary.cleanup()

    def started(self, **changes):
        value = dict(pid=99999999, start_ticks=1, boot=B.boot(), unit=self.unit,
                     invocation='b' * 32, group='/' + self.unit, device=1, inode=1)
        value.update(changes)
        (self.gate / 'started.json').write_text(json.dumps(value))
        return value

    def test_never_entered_candidate_is_fenced_and_delayed_entry_rejected(self):
        receipt = B.reconcile(self.config_path)
        self.assertTrue(receipt['abandoned_incomplete_new_candidate'])
        self.assertTrue(receipt['future_entry_fenced'])
        self.assertTrue(receipt['process_and_service_quiescent'])
        self.assertEqual(receipt['accepted_proofs_discarded'], 0)
        with self.assertRaisesRegex(ValueError, 'revoked or already consumed'):
            B.enter(self.config_path)
        self.assertEqual(B.reconcile(self.config_path), receipt)

    def test_enter_holds_lifetime_lock_and_consumes_service_once(self):
        value = B.read(self.gate / 'intent.json')
        state = dict(self.state, ActiveState='active', SubState='running',
            MainPID=os.getpid(), InvocationID='b' * 32, ControlGroup='/' + self.unit)
        original_bytes = Path.read_bytes
        original_text = Path.read_text

        def read_bytes(path):
            if path == Path('/proc/self/cmdline'):
                return b'\0'.join(os.fsencode(arg) for arg in value['command']) + b'\0'
            return original_bytes(path)

        def read_text(path, *args, **kwargs):
            if path == Path('/proc/self/cgroup'):
                return '0::/' + self.unit + '\n'
            return original_text(path, *args, **kwargs)

        with mock.patch.object(B, 'observation', return_value=state), \
                mock.patch.object(B, 'group_path', return_value=self.owner), \
                mock.patch.object(Path, 'read_bytes', read_bytes), \
                mock.patch.object(Path, 'read_text', read_text), \
                mock.patch.dict(os.environ, INVOCATION_ID='b' * 32):
            started = B.enter(self.config_path)
        self.assertEqual(started['pid'], os.getpid())
        with self.assertRaises(BlockingIOError):
            B.lock(self.gate)
        os.close(B._lifetime_fds.pop())
        with self.assertRaisesRegex(ValueError, 'revoked or already consumed'):
            B.enter(self.config_path)

    def test_different_process_arguments_cannot_enter(self):
        with self.assertRaisesRegex(ValueError, 'executable or arguments differ'):
            B.enter(self.config_path)
        self.assertFalse((self.gate / 'started.json').exists())

    def test_changed_config_or_plan_cannot_recover(self):
        for path in (self.config_path, self.plan_path):
            with self.subTest(path=path):
                original = path.read_bytes()
                path.write_bytes(original + b' ')
                with self.assertRaisesRegex(ValueError, 'intent or pinned inputs changed'):
                    B.reconcile(self.config_path)
                path.write_bytes(original)

    def test_active_or_pending_service_is_not_revoked(self):
        for changes in (dict(ActiveState='active', MainPID=15), dict(Job='123/start'), dict(ControlPID=15)):
            with self.subTest(changes=changes), mock.patch.object(B, 'observation',
                    return_value=dict(self.state, **changes)):
                with self.assertRaisesRegex(ValueError, 'not quiescent'):
                    B.reconcile(self.config_path)
                self.assertFalse((self.gate / 'revoked.json').exists())

    def test_observation_change_keeps_future_entry_fenced(self):
        with mock.patch.object(B, 'observation', side_effect=[self.state, dict(self.state, LoadState='loaded')]):
            with self.assertRaisesRegex(ValueError, 'changed during reconciliation'):
                B.reconcile(self.config_path)
        self.assertTrue((self.gate / 'revoked.json').exists())

    def test_retained_live_process_blocks_recovery(self):
        self.started(pid=os.getpid(), start_ticks=B.birth(os.getpid()))
        with self.assertRaisesRegex(ValueError, 'process is still alive'):
            B.reconcile(self.config_path)

    def test_changed_service_invocation_blocks_recovery(self):
        self.started()
        with mock.patch.object(B, 'observation', return_value=dict(self.state, InvocationID='c' * 32)):
            with self.assertRaisesRegex(ValueError, 'invocation changed'):
                B.reconcile(self.config_path)

    def test_incomplete_recovery_of_existing_journal_cannot_be_reinitialized(self):
        for key in ('recover_from', 'recover_cached_only', 'preseal_only', 'reuse_preseal'):
            for target in ('plan', 'config'):
                with self.subTest(key=key, target=target):
                    config, plan = copy.deepcopy(self.config), copy.deepcopy(self.plan)
                    (plan if target == 'plan' else config)[key] = True
                    with self.assertRaisesRegex(ValueError, 'existing journal requires journal recovery'):
                        B.incomplete_new_candidate(config, plan)

    def test_admitted_or_accepted_work_cannot_be_abandoned(self):
        proofs = self.owner / 'proofs'
        for name in ('node.6.0', 'execution/worker-0.session', 'execution/worker-0-start.json',
                     'execution/worker-0-startup/authorization.json',
                     'execution/worker-0-startup/started.json', 'execution/launches/some.intent',
                     'execution/artifacts/n-' + 'a' * 64 + '.proof', 'result.json'):
            with self.subTest(name=name):
                path = proofs / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'presence must prohibit abandonment')
                with self.assertRaisesRegex(ValueError, 'admitted or accepted work'):
                    B.incomplete_new_candidate(self.config, self.plan)
                path.unlink()

    def test_valid_initialization_uses_existing_journal_path(self):
        started = self.started()
        value = B.read(self.gate / 'intent.json')
        marker = dict(schema_version=1, owner_pid=started['pid'], coordinator_pid=99,
                      plan_sha256=value['plan_sha256'], proofs=value['proofs'])
        (self.gate / 'initialized.json').write_text(json.dumps(marker))
        receipt = B.reconcile(self.config_path)
        self.assertFalse(receipt['abandoned_incomplete_new_candidate'])
        self.assertEqual(receipt['initialized'], marker)

    def test_changed_initialization_marker_cannot_be_treated_as_empty(self):
        self.started()
        (self.gate / 'initialized.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'initialization marker differs'):
            B.reconcile(self.config_path)

    def test_symlinked_lock_is_rejected(self):
        (self.gate / 'lock').unlink()
        (self.gate / 'lock').symlink_to(self.gate / 'intent.json')
        with self.assertRaises(OSError):
            B.reconcile(self.config_path)

    def test_changed_revocation_is_rejected(self):
        (self.gate / 'revoked.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'revocation changed'):
            B.reconcile(self.config_path)

    def test_partial_wallet_store_is_preserved(self):
        path = self.owner / 'proofs/execution/artifacts/w-partial.proof'
        path.parent.mkdir(parents=True)
        path.write_bytes(b'incomplete pre-dispatch store')
        receipt = B.reconcile(self.config_path)
        self.assertTrue(receipt['abandoned_incomplete_new_candidate'])
        self.assertEqual(path.read_bytes(), b'incomplete pre-dispatch store')


if __name__ == '__main__':
    unittest.main()
