#!/usr/bin/env python3
"""Admission protocol tests; fake fixtures do not qualify cryptographic proving."""
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

C = importlib.import_module('block_v2_controller_bootstrap')
S = importlib.import_module('block-v2-typed-shared-gpu-run')


class ControllerBootstrap(unittest.TestCase):
    def test_controller_cpuset_preserves_inherited_affinity_and_rejects_empty(self):
        with mock.patch.object(C.os, 'sched_getaffinity', return_value={7, 1, 3, 5}):
            self.assertEqual(C.controller_cpu_property(), '--property=AllowedCPUs=1,3,5,7')
        with mock.patch.object(C.os, 'sched_getaffinity', return_value=set()):
            with self.assertRaises(ValueError): C.controller_cpu_property()

    def test_calibration_recovery_cannot_issue_a_new_workflow(self):
        self.args.pool_calibration = self.root / 'calibration.json'
        self.args.evidence = self.root / 'forbidden-recovery'
        with self.assertRaises(ValueError):
            C.create(self.args, self.script, {}, recovered={'intent': self.value})
        self.assertFalse(self.args.evidence.exists())
        original = dict(self.value, arguments=C.arguments(self.args))
        self.args.recover_controller = self.root / 'old'
        with mock.patch.object(C, 'reconcile', return_value={'intent': original, 'recovery_owner': None}):
            with self.assertRaises(ValueError):
                C.recover(self.args, S.argument_parser())

    def test_calibration_controller_uses_the_bounded_pool_limits(self):
        self.args.pool_calibration = self.root / 'calibration.json'
        with mock.patch.object(C, 'create', return_value=(self.path, self.value)), \
                mock.patch.object(C.G, 'lock_fleet', return_value=[]), \
                mock.patch.object(C.os, 'sched_getaffinity', return_value={1, 3, 5, 7}), \
                mock.patch.object(C.G, 'systemctl', side_effect=lambda *a: '[]' if a[0] == 'list-units' else ''), \
                mock.patch.object(C.subprocess, 'run', return_value=mock.Mock(returncode=0)) as launch, \
                mock.patch.object(C.B, 'quiescent'):
            C.launch(self.args, self.script, {}, lambda directory: '--property=LimitCORE=0')
        command = launch.call_args.args[0]
        self.assertIn('--property=AllowedCPUs=1,3,5,7', command)
        for argument in ['--slice=lattica-v2-multi-coordinator.slice', '--property=MemoryMax=1G',
                         '--property=RuntimeMaxSec=180', '--property=CPUQuota=400%', '--setenv=RAYON_NUM_THREADS=4']:
            self.assertIn(argument, command)

    def test_calibration_dispatch_clock_is_pinned_before_launch(self):
        self.args.pool_calibration = self.root / 'calibration.json'
        self.args.evidence = self.root / 'calibration-run'
        path, value = C.create(self.args, self.script, {str(self.script): C.G.digest(self.script)})
        workflow, window = value['pool_workflow'], value['pool_scheduling']
        self.assertEqual(workflow['boot_id'], window['boot_id'])
        self.assertLessEqual(workflow['started_monotonic_ms'], window['issued_monotonic_ms'])
        self.assertEqual(window['dispatch_deadline_monotonic_ms'] - window['issued_monotonic_ms'], 150000)
        self.assertEqual(workflow['deadline_monotonic_ms'] - workflow['started_monotonic_ms'], 600000)
        self.assertEqual(C.intent(path)[1]['pool_scheduling'], window)

    def test_bounded_controller_and_owner_share_one_admitted_budget(self):
        self.args.pool_timing_approval = ['GPU-a=/timing.json']
        with mock.patch.object(C, 'create', return_value=(self.path, self.value)), \
                mock.patch.object(C.G, 'lock_fleet', return_value=[]), \
                mock.patch.object(C.G, 'systemctl', side_effect=lambda *a: '[]' if a[0] == 'list-units' else '') as systemctl, \
                mock.patch.object(C.subprocess, 'run', return_value=mock.Mock(returncode=0)) as launch, \
                mock.patch.object(C.B, 'quiescent'):
            C.launch(self.args, self.script, {}, lambda directory: '--property=LimitCORE=0')
        command = launch.call_args.args[0]
        for argument in ['--slice=lattica-v2-multi-coordinator.slice', '--property=MemoryMax=1G',
                         '--property=RuntimeMaxSec=180', '--property=CPUQuota=400%', '--setenv=RAYON_NUM_THREADS=4']:
            self.assertIn(argument, command)
        self.assertNotIn('--property=MemoryMax=4G', command)
        calls = [call.args for call in systemctl.call_args_list]
        self.assertIn(('set-property', '--runtime', 'lattica-v2-multi.slice',
                      'MemoryMax=4G', 'MemorySwapMax=0', 'CPUQuota=400%'), calls)
        self.assertIn(('set-property', '--runtime', 'lattica-v2-multi-coordinator.slice',
                      'MemoryMax=1G', 'MemorySwapMax=0', 'CPUQuota=400%'), calls)

    def test_bounded_dispatch_clock_is_pinned_before_controller_entry(self):
        self.args.evidence = self.root / 'bounded'
        self.args.pool_timing_approval = ['GPU-a=/timing.json']
        self.args.pool_requests = self.root / 'requests'
        path, value = C.create(self.args, self.script, {str(self.script): C.G.digest(self.script)})
        workflow, window = value['pool_workflow'], value['pool_scheduling']
        self.assertEqual(workflow['boot_id'], window['boot_id'])
        self.assertLessEqual(workflow['started_monotonic_ms'], window['issued_monotonic_ms'])
        self.assertEqual(window['dispatch_deadline_monotonic_ms'] - window['issued_monotonic_ms'], 150000)
        self.assertEqual(workflow['deadline_monotonic_ms'] - workflow['started_monotonic_ms'], 600000)
        self.assertEqual(C.intent(path)[1]['pool_scheduling'], window)

    def test_recovery_and_launch_keep_the_recorded_proving_policy(self):
        required = {'LATTICA_PROVING_POLICY': 'gpu-required', 'LATTICA_PROVING_REPORT': '1'}
        self.args.evidence = self.root / 'recovered'
        with mock.patch.dict(os.environ, {'LATTICA_PROVING_POLICY': 'compatible', 'LATTICA_PROVING_REPORT': '0'}):
            path, value = C.create(self.args, self.script, {str(self.script): C.G.digest(self.script)},
                                   recovered={'intent': {'proving_environment': required}})
            self.assertEqual(value['proving_environment'], required)
            with mock.patch.object(C, 'create', return_value=(path, value)), \
                    mock.patch.object(C.subprocess, 'run', return_value=mock.Mock(returncode=0)) as launch, \
                    mock.patch.object(C.B, 'quiescent'):
                C.launch(self.args, self.script, {}, lambda directory: '--property=LimitCORE=0')
        command = launch.call_args.args[0]
        for name, setting in required.items():
            self.assertLess(command.index(f'--setenv={name}={setting}'), command.index(value['executable']))

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.script = self.root / 'controller.py'
        self.script.write_text('# synthetic controller identity\n')
        self.binary = self.root / 'probe'
        self.binary.write_bytes(b'synthetic probe identity')
        self.args = S.argument_parser().parse_args(['--gpu-binary', str(self.binary),
            '--cpu-binary', str(self.binary), '--fixture', str(self.root), '--count', '4',
            '--gpu-uuid', 'GPU-a', '--gpu-uuid', 'GPU-b', '--evidence', str(self.root / 'run')])
        self.fd_count = len(C._lifetime_fds)
        self.path, self.value = C.create(self.args, self.script,
            {str(p): C.G.digest(p) for p in (self.script, self.binary)})
        self.gate = self.path.parent
        self.dead = dict(LoadState='not-found', ActiveState='inactive', SubState='dead', MainPID=0,
            ControlPID=0, Job='', InvocationID='', ControlGroup='')
        self.observation = mock.patch.object(C, 'observation', return_value=self.dead)
        self.observation.start()

    def tearDown(self):
        self.observation.stop()
        for fd in C._lifetime_fds[self.fd_count:]:
            os.close(fd)
        del C._lifetime_fds[self.fd_count:]
        self.temporary.cleanup()

    def release(self):
        while len(C._lifetime_fds) > self.fd_count:
            os.close(C._lifetime_fds.pop())

    def enter(self):
        state = dict(self.dead, ActiveState='active', SubState='running', MainPID=os.getpid(),
            InvocationID='b' * 32, ControlGroup='/' + self.value['unit'])
        original_bytes, original_text = Path.read_bytes, Path.read_text
        def read_bytes(path, *args, **kwargs):
            if path == Path('/proc/self/cmdline'):
                return b'\0'.join(os.fsencode(arg) for arg in self.value['command']) + b'\0'
            return original_bytes(path, *args, **kwargs)
        def read_text(path, *args, **kwargs):
            if path == Path('/proc/self/cgroup'):
                return '0::' + state['ControlGroup']
            return original_text(path, *args, **kwargs)
        with mock.patch.object(C, 'observation', return_value=state), \
                mock.patch.object(C.B, 'group_path', return_value=self.gate), \
                mock.patch.object(Path, 'read_bytes', read_bytes), \
                mock.patch.object(Path, 'read_text', read_text), \
                mock.patch.dict(os.environ, INVOCATION_ID=state['InvocationID']):
            args, control = C.enter(self.path, S.argument_parser(), self.script)
        return args, control, state

    def owner(self, control):
        directory = self.gate.parent / 'owner'
        directory.mkdir(mode=0o700)
        gate = directory / 'coordinator-startup'
        plan = dict(startup_fenced=True, coordinator_bootstrap_guard=str(gate), recover_from=None, workers=[])
        plan_path = self.gate.parent / 'fleet-plan.json'
        plan_path.write_text(json.dumps(plan))
        config = dict(owner_directory=str(directory), owner_unit='lattica-v2-multi-owner-' + 'a' * 64 + '.service',
            coordinator_bootstrap_guard=str(gate), fleet_plan=str(plan_path), controller_admission=control)
        path = self.gate.parent / 'config.json'
        path.write_text(json.dumps(config))
        C.B.create(path, self.script)
        return path, config

    def stopped_controller(self):
        self.release()
        # Simulate a prior boot, so the real current test PID cannot be confused
        # with a stopped controller. No OS process is stopped by these tests.
        path = self.gate / 'started.json'
        if path.exists():
            data = C.read(path)
            data['boot'] = 'prior-boot'
            path.write_text(json.dumps(data))

    def test_argument_round_trip_preserves_paths_flags_recovery_and_gpu_order(self):
        self.args.recover_owner = self.root / 'prior/owner'
        self.args.reuse_preseal = [self.root / 'prefix/proofs']
        self.args.allow_worker_failover = True
        restored = S.argument_parser().parse_args(C.arguments(self.args))
        self.assertEqual(vars(restored), vars(self.args))

    def test_live_launcher_is_not_revoked(self):
        with self.assertRaises(BlockingIOError):
            C.reconcile(self.gate.parent)
        self.assertFalse((self.gate / 'revoked.json').exists())

    def test_pending_or_live_controller_is_not_revoked(self):
        self.release()
        for changes in [dict(Job='17/start'), dict(MainPID=123, ActiveState='active'), dict(ControlPID=123)]:
            with self.subTest(changes=changes), mock.patch.object(C, 'observation', return_value=self.dead | changes):
                with self.assertRaisesRegex(ValueError, 'not quiescent'):
                    C.reconcile(self.gate.parent)
                self.assertFalse((self.gate / 'revoked.json').exists())

    def test_entry_before_preparation_is_fenced_after_reconciliation(self):
        self.release()
        receipt = C.reconcile(self.gate.parent)
        self.assertTrue(receipt['future_controller_entry_fenced'])
        self.assertTrue(receipt['future_owner_entry_fenced'])
        self.assertIsNone(receipt['recovery_owner'])
        with self.assertRaisesRegex(ValueError, 'revoked or already consumed'):
            C.enter(self.path, S.argument_parser(), self.script)
        self.assertEqual(C.reconcile(self.gate.parent), receipt)

    def test_changed_binary_fails_before_revocation(self):
        self.release()
        self.binary.write_bytes(b'changed image')
        with self.assertRaisesRegex(ValueError, 'input changed'):
            C.reconcile(self.gate.parent)
        self.assertFalse((self.gate / 'revoked.json').exists())

    def test_entry_records_exact_service_and_holds_lock_until_os_exit(self):
        args, control, state = self.enter()
        self.assertEqual(args.count, 4)
        self.assertEqual(control['unit'], self.value['unit'])
        self.assertEqual(C.read(self.gate / 'started.json')['invocation'], state['InvocationID'])
        with self.assertRaises(BlockingIOError):
            C.lock(self.gate, 'lock')
        self.release()
        with self.assertRaisesRegex(ValueError, 'already consumed'):
            C.enter(self.path, S.argument_parser(), self.script)

    def test_incomplete_config_is_retained_without_authorizing_an_owner(self):
        self.enter()
        partial = self.gate.parent / 'config.json'
        partial.write_text('{partial')
        self.stopped_controller()
        receipt = C.reconcile(self.gate.parent)
        self.assertIsNone(receipt['owner_admission'])
        self.assertEqual(partial.read_text(), '{partial')

    def test_an_owner_cannot_enter_before_the_atomic_handoff(self):
        _, control, _ = self.enter()
        path, config = self.owner(control)
        with self.assertRaises(FileNotFoundError):
            C.B.enter(path)
        self.assertFalse((C.B.gate_path(config) / 'started.json').exists())

    def test_owner_requires_the_same_live_controller_after_handoff(self):
        _, control, state = self.enter()
        path, config = self.owner(control)
        C.authorize(control, path)
        with mock.patch.object(C, 'observation', return_value=state):
            C.require_owner_authorized(path, config)
        with self.assertRaisesRegex(ValueError, 'no longer'):
            C.require_owner_authorized(path, config)
        with self.assertRaises(FileExistsError):
            C.authorize(control, path)

    def test_handoff_recovery_routes_to_owner_and_fences_delayed_owner_entry(self):
        _, control, _ = self.enter()
        path, config = self.owner(control)
        C.authorize(control, path)
        self.stopped_controller()
        with mock.patch.object(C.B, 'observation', return_value=self.dead):
            receipt = C.reconcile(self.gate.parent)
            self.assertEqual(receipt['recovery_owner'], str(self.gate.parent / 'owner'))
            self.assertTrue(receipt['owner_bootstrap']['abandoned_incomplete_new_candidate'])
            self.assertEqual(C.reconcile(self.gate.parent), receipt)
        with self.assertRaisesRegex(ValueError, 'exact controller handoff'):
            C.require_owner_authorized(path, config)

    def test_changed_handoff_cannot_silently_be_retried_as_preparation(self):
        _, control, _ = self.enter()
        path, _ = self.owner(control)
        C.authorize(control, path)
        self.stopped_controller()
        path.write_text(path.read_text() + '\n')
        with self.assertRaisesRegex(ValueError, 'handoff differs'):
            C.reconcile(self.gate.parent)

    def test_revoked_controller_cannot_publish_an_owner_handoff(self):
        _, control, _ = self.enter()
        path, _ = self.owner(control)
        C.publish(self.gate / 'revoked.json', dict(schema_version=1, intent_sha256=C.G.digest(self.path)))
        with self.assertRaisesRegex(ValueError, 'handoff differs'):
            C.authorize(control, path)
        self.assertFalse((self.gate / 'owner-admission.json').exists())

    def test_preparation_retry_preserves_an_earlier_accepted_journal_argument(self):
        self.release()
        value = C.read(self.path)
        value['arguments'] += ['--recover-owner', str(self.root / 'prior/owner')]
        self.path.write_text(json.dumps(value))
        args = S.argument_parser().parse_args(['--recover-controller', str(self.gate.parent),
                                             '--evidence', str(self.root / 'new')])
        restored, receipt = C.recover(args, S.argument_parser())
        self.assertEqual(restored.recover_owner, self.root / 'prior/owner')
        self.assertEqual(restored.evidence, self.root / 'new')
        self.assertEqual(restored.gpu_uuid, ['GPU-a', 'GPU-b'])
        self.assertIsNone(receipt['owner_admission'])

    def test_completed_owner_can_explicitly_request_the_existing_cpu_only_recovery(self):
        _, control, _ = self.enter()
        path, _ = self.owner(control)
        C.authorize(control, path)
        self.stopped_controller()
        args = S.argument_parser().parse_args(['--recover-controller', str(self.gate.parent),
            '--evidence', str(self.root / 'cached'), '--recover-cached-only'])
        with mock.patch.object(C.B, 'observation', return_value=self.dead):
            restored, receipt = C.recover(args, S.argument_parser())
        self.assertTrue(restored.recover_cached_only)
        self.assertEqual(restored.recover_owner, self.gate.parent / 'owner')
        self.assertEqual(restored.count, 4)
        self.assertIsNotNone(receipt['owner_admission'])


if __name__ == '__main__':
    unittest.main()
