#!/usr/bin/env python3
"""Supervision lifecycle tests; local subprocesses only, no GPU work."""
import copy
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

S = importlib.import_module('block_v2_supervisor')
C = importlib.import_module('block-v2-typed-shared-gpu-run')
sleep = time.sleep


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


class SupervisorTests(unittest.TestCase):
    def fixture(self, root, restarts=2):
        script = root/'fake-controller.py'
        script.write_text("import pathlib,sys\np=pathlib.Path(sys.argv[sys.argv.index('--evidence')+1]);p.mkdir()\n(p/'child.txt').write_text('started')\nraise SystemExit(1)\n")
        args = C.argument_parser().parse_args(['--supervise', '--evidence', str(root/'trial'),
            '--gpu-binary', str(script), '--cpu-binary', str(script), '--fixture', str(root/'fixture'),
            '--count', '4', '--host-config', str(root/'host.json'), '--host-journal', str(root/'journal'),
            '--arrival-store', str(root/'intake'), '--arrival-selection', 'selection',
            '--supervisor-max-restarts', str(restarts), '--supervisor-restart-delay', '0'])
        path, value = S.create(args, script, {str(script): S.G.digest(script)})
        identity = dict(pid=os.getpid(), start_ticks=S.B.birth(os.getpid()), boot=S.B.boot(), invocation='a'*32)
        return script, path, value, identity

    def run_engine(self, path, script, identity, decisions, current=True):
        with patch.object(S, 'entry_identity', return_value=identity), \
                patch.object(S, 'candidate_current', return_value=current) as candidate, \
                patch.object(S, 'controller_state', side_effect=decisions) as observe, \
                patch.object(S.time, 'sleep', side_effect=lambda seconds: sleep(min(seconds, .001))):
            S.run_request(path, script, C.argument_parser(), C)
        return candidate, observe

    def test_supervisor_options_are_not_forwarded_to_child_controllers(self):
        with tempfile.TemporaryDirectory() as directory:
            _, _, value, _ = self.fixture(Path(directory))
            self.assertFalse(any(arg.startswith('--supervis') for arg in value['arguments']))
            self.assertIn('--host-config', value['arguments'])

    def test_request_rejects_changed_script_and_restart_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            script, path, value, _ = self.fixture(Path(directory))
            self.assertEqual(S.request(path, script), value)
            bad = dict(value, max_restarts=9)
            write(path, bad)
            with self.assertRaises(ValueError):
                S.request(path, script)
            write(path, value)
            script.write_text('changed')
            with self.assertRaises(ValueError):
                S.request(path, script)

    def test_unsealed_and_external_recovery_requests_are_rejected(self):
        args = C.argument_parser().parse_args([])
        with self.assertRaises(ValueError):
            S.validate_options(args)
        with tempfile.TemporaryDirectory() as directory:
            _, _, value, _ = self.fixture(Path(directory))
            args = C.argument_parser().parse_args(value['arguments'])
            for option, bad in [('preseal', True), ('recover_owner', Path('/previous')),
                                ('supervisor_max_restarts', -1), ('supervisor_restart_delay', 61)]:
                changed = copy.copy(args)
                setattr(changed, option, bad)
                with self.subTest(option=option), self.assertRaises(ValueError):
                    S.validate_options(changed)

    def test_attempt_commands_preserve_initial_inputs_and_use_recovery_only_after_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            _, _, value, _ = self.fixture(Path(directory))
            initial = S.attempt_command(value, 1, None)
            self.assertIn('--host-config', initial['command'])
            self.assertNotIn('--recover-controller', initial['command'])
            retry = S.attempt_command(value, 2, Path(initial['directory']), cached=True)
            self.assertEqual(retry['command'][2:], ['--recover-controller', initial['directory'],
                '--evidence', retry['directory'], '--recover-cached-only'])
            with self.assertRaises(ValueError):
                S.attempt_command(value, 4, Path(retry['directory']))

    def test_fatal_attempt_automatically_uses_durable_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            script, path, value, identity = self.fixture(Path(directory))
            self.run_engine(path, script, identity, [dict(action='recover', cached_only=False),
                                                       dict(action='succeeded', result={'native_blocks_applied': 1})])
            result = S.read(path.parent/'result.json')
            self.assertEqual(result['status'], 'succeeded')
            self.assertEqual(result['retries'], 1)
            intent = S.read(path.parent/'attempt-002.intent.json')
            self.assertEqual(intent['previous'], str(path.parent/'attempt-001'))
            self.assertTrue((path.parent/'attempt-001/child.txt').is_file())
            self.assertTrue((path.parent/'attempt-002/child.txt').is_file())

    def test_monitor_timeout_waits_for_same_attempt_without_relaunch(self):
        with tempfile.TemporaryDirectory() as directory:
            script, path, _, identity = self.fixture(Path(directory))
            _, observed = self.run_engine(path, script, identity, [
                subprocess.TimeoutExpired(['systemctl', 'show'], 1), dict(action='wait'), dict(action='succeeded')])
            self.assertEqual(observed.call_count, 3)
            self.assertEqual(len(list(path.parent.glob('attempt-*.intent.json'))), 1)
            self.assertTrue((path.parent/'attempt-001.observation-errors.jsonl').is_file())

    def test_restart_budget_is_durable_and_exhaustion_returns_terminal_result(self):
        with tempfile.TemporaryDirectory() as directory:
            script, path, _, identity = self.fixture(Path(directory), restarts=1)
            self.run_engine(path, script, identity, [dict(action='recover'), dict(action='recover')])
            result = S.read(path.parent/'result.json')
            self.assertEqual(result['status'], 'restart_budget_exhausted')
            self.assertEqual(len(result['attempts']), 2)
            identity['invocation'] = 'b'*32
            candidate, observed = self.run_engine(path, script, identity, [])
            candidate.assert_not_called()
            observed.assert_not_called()
            self.assertEqual(len(list(path.parent.glob('attempt-*.intent.json'))), 2)

    def test_stale_candidate_does_not_launch_or_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            script, path, _, identity = self.fixture(Path(directory))
            _, observed = self.run_engine(path, script, identity, [], current=False)
            observed.assert_not_called()
            self.assertEqual(S.read(path.parent/'result.json')['status'], 'stale_candidate')
            self.assertEqual(len(list(path.parent.glob('attempt-*.intent.json'))), 0)

    def test_resume_adopts_existing_attempt_before_checking_a_now_advanced_head(self):
        with tempfile.TemporaryDirectory() as directory:
            script, path, _, identity = self.fixture(Path(directory))
            with self.assertRaisesRegex(RuntimeError, 'observer crash'):
                self.run_engine(path, script, identity, [RuntimeError('observer crash')])
            identity['invocation'] = 'b'*32
            candidate, _ = self.run_engine(path, script, identity, [dict(action='succeeded')], current=False)
            candidate.assert_not_called()
            self.assertEqual(S.read(path.parent/'result.json')['status'], 'succeeded')
            self.assertEqual(len(list(path.parent.glob('attempt-*.intent.json'))), 1)

    def test_resume_rejects_changed_attempt_before_launching(self):
        with tempfile.TemporaryDirectory() as directory:
            script, path, _, identity = self.fixture(Path(directory))
            with self.assertRaises(RuntimeError):
                self.run_engine(path, script, identity, [RuntimeError('crash')])
            target = path.parent/'attempt-001.intent.json'
            changed = S.read(target)
            changed['command'].append('--other-input')
            write(target, changed)
            identity['invocation'] = 'b'*32
            with self.assertRaisesRegex(ValueError, 'command changed'):
                self.run_engine(path, script, identity, [])

    def state_fixture(self, root):
        gate = root/'controller-startup'
        write(gate/'intent.json', {})
        unit = 'lattica-v2-controller-'+'a'*64+'.service'
        stopped = dict(ActiveState='failed', SubState='failed', MainPID=0, ControlPID=0, Job='', ControlGroup='')
        shared = SimpleNamespace(quiescent_fleet=Mock(), validate_execution=Mock())
        return gate, unit, stopped, shared

    def test_live_launcher_is_a_wait_even_when_no_result_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gate, _, _, shared = self.state_fixture(root)
            write(gate/'launcher-started.json', dict(pid=os.getpid(), start_ticks=S.B.birth(os.getpid()), boot=S.B.boot()))
            with patch.object(S.Controller, 'observation') as observed:
                result = S.controller_state(root, shared)
            self.assertEqual(result['action'], 'wait')
            observed.assert_not_called()

    def test_live_controller_and_live_fleet_never_authorize_recovery(self):
        for live_fleet in (False, True):
            with self.subTest(live_fleet=live_fleet), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                gate, unit, stopped, shared = self.state_fixture(root)
                config = dict(pins={}, owner_unit='lattica-v2-multi-owner-'+'b'*64+'.service', workers=[])
                write(root/'config.json', config)
                live = dict(stopped, ActiveState='active', SubState='running', MainPID=123)
                with patch.object(S.Controller, 'intent', return_value=(gate, {'unit': unit})), \
                        patch.object(S.Controller, 'observation', return_value=stopped if live_fleet else live), \
                        patch.object(S.Controller, 'check_pins'), patch.object(S.B, 'quiescent'), \
                        patch.object(S, 'observe', return_value=live), patch.object(S.Controller, 'reconcile') as reconcile:
                    result = S.controller_state(root, shared)
                self.assertEqual(result['action'], 'wait')
                reconcile.assert_not_called()
                shared.quiescent_fleet.assert_not_called()

    def test_stale_completed_attempt_does_not_enter_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gate, unit, stopped, shared = self.state_fixture(root)
            write(root/'summary.json', {'status': 'failed', 'native_head_change': {'detected': True}})
            with patch.object(S.Controller, 'intent', return_value=(gate, {'unit': unit})), \
                    patch.object(S.Controller, 'observation', return_value=stopped), \
                    patch.object(S.B, 'quiescent'), patch.object(S.Controller, 'reconcile', return_value={}):
                result = S.controller_state(root, shared)
            self.assertEqual(result['action'], 'stale')

    def test_pending_service_job_is_not_terminal(self):
        self.assertFalse(S.terminal(dict(ActiveState='inactive', MainPID=0, ControlPID=0, Job='123')))
        self.assertFalse(S.terminal(dict(ActiveState='deactivating', MainPID=0, ControlPID=0, Job='')))
        self.assertTrue(S.terminal(dict(ActiveState='inactive', MainPID=0, ControlPID=0, Job='')))


if __name__ == '__main__':
    unittest.main()
