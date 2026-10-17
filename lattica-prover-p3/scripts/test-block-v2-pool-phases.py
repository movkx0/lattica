#!/usr/bin/env python3
"""Controller receipt/fencing tests; fixtures do not qualify GPU proving."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import block_v2_pool_phases as P


class PhaseTests(unittest.TestCase):
    def test_workflow_cleanup_covers_reopened_journals_and_the_final_fixture(self):
        previous, current = (self.directory / name for name in ['old-phase', 'new-phase'])
        prefix, final = (self.directory / name for name in ['prefix-fixture', 'final-fixture'])
        files = {}
        for root in [previous / 'owner', current / 'owner', prefix, final]:
            root.mkdir(mode=0o700, parents=True)
            path = root / 'public-proof'
            files[path] = str(root).encode()
            path.write_bytes(files[path])
        events = []
        def advise(fd, *_): events.append(('advice', os.readlink(f'/proc/self/fd/{fd}')))
        with patch.object(P, 'reconcile', side_effect=lambda path: events.append(('stopped', path))):
            with patch.object(P.S.PublicCache.os, 'posix_fadvise', side_effect=advise):
                receipt = P.retire_workflow_inputs([previous, current], [prefix, final],
                    time.monotonic_ns() // 1_000_000 + 30000)
        self.assertEqual(events[:2], [('stopped', previous), ('stopped', current)])
        self.assertEqual(events[-2:], [('stopped', previous), ('stopped', current)])
        self.assertEqual({Path(path) for event, path in events if event == 'advice'}, set(files))
        self.assertEqual({path: path.read_bytes() for path in files}, files)
        self.assertFalse(receipt['physical_release_measured'])

    def test_one_live_reader_prevents_retirement_of_all_workflow_inputs(self):
        previous, current = self.directory / 'old', self.directory / 'current'
        with patch.object(P, 'reconcile', side_effect=[None, ValueError('reader active')]):
            with patch.object(P.S.PublicCache, 'release') as release:
                with self.assertRaisesRegex(ValueError, 'reader active'):
                    P.retire_workflow_inputs([previous, current], [self.directory], 100)
                release.assert_not_called()

    def test_workflow_retirement_preserves_the_private_directory_contract(self):
        phase = self.directory / 'phase'; (phase / 'owner').mkdir(parents=True, mode=0o700)
        fixture = self.directory / 'caller-fixture'; fixture.mkdir(mode=0o755)
        path = fixture / 'public-proof'; path.write_bytes(b'public proof')
        with patch.object(P, 'reconcile'), patch.object(P.S.PublicCache, 'release', return_value={}) as release:
            result = P.retire_workflow_inputs([phase], [fixture], 100)
            release.assert_called_once_with(phase / 'owner', 100)
        self.assertEqual(result['skipped_nonprivate_fixtures'], [str(fixture)])
        self.assertEqual(path.read_bytes(), b'public proof')

    def test_workflow_retirement_rejects_aliases_bounds_and_advice_failures(self):
        phase = self.directory / 'phase'
        fixture = self.directory / 'fixture'; fixture.mkdir(mode=0o700)
        alias = self.directory / 'alias'; alias.symlink_to(fixture, target_is_directory=True)
        with patch.object(P, 'reconcile'), patch.object(P.S.PublicCache, 'release') as release:
            for phases, fixtures, message in [([], [fixture], 'bound'),
                    ([self.directory / str(i) for i in range(P.MAX_PHASES + 1)], [fixture], 'bound'),
                    ([phase], [fixture, alias, self.directory], 'bound'),
                    ([phase], [alias], 'nonsymlink')]:
                with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                    P.retire_workflow_inputs(phases, fixtures, 100)
            release.assert_not_called()
        with patch.object(P, 'reconcile'), patch.object(P.S.PublicCache, 'release', side_effect=OSError('advice failed')):
            with self.assertRaisesRegex(OSError, 'advice failed'):
                P.retire_workflow_inputs([phase], [fixture], 100)

    def test_failed_phase_stops_readers_before_retirement_and_keeps_the_original_failure(self):
        configuration = self.directory / 'host.json'; configuration.write_text('{}')
        config = {'host_config': str(configuration), 'owned_public_gpu': True}
        class FailedProcess:
            returncode = 1
            def poll(self): return self.returncode
        for cleanup_fails in [False, True]:
            output = self.directory / ('failed-cleanup' if cleanup_fails else 'cleaned')
            events = []
            def launch(*args, **kwargs):
                phase = output / 'phase-000'; phase.mkdir(mode=0o700)
                (phase / 'config.json').write_text('{}')
                return FailedProcess()
            def retire(directories, fixtures, deadline):
                self.assertEqual(events, ['stopped'])
                self.assertEqual(directories, [output / 'phase-000'])
                self.assertEqual(fixtures, [self.directory])
                events.append('retired')
                if cleanup_fails: raise OSError('retirement failed')
                return {'cleanup_only': True}
            with self.subTest(cleanup_fails=cleanup_fails), \
                    patch.object(P.T, 'workflow', return_value=(self.workflow, {})), \
                    patch.object(P.T, 'workflow_clock', return_value=(self.workflow['boot_id'], 10)), \
                    patch.object(P, 'command', return_value=['unused']), \
                    patch.object(P.subprocess, 'Popen', side_effect=launch), \
                    patch.object(P, 'stop_owned_services', side_effect=lambda _: events.append('stopped')), \
                    patch.object(P, 'retire_workflow_inputs', side_effect=retire):
                with self.assertRaisesRegex(RuntimeError, 'no automatic retry'):
                    P.run(config, self.directory, self.directory / 'clock.json', output)
            self.assertEqual(events, ['stopped', 'retired'])
            summary = json.loads((output / 'summary.json').read_text())
            self.assertEqual(summary['status'], 'failed')
            self.assertIn('no automatic retry', summary['error'])
            self.assertEqual(summary['pool_workflow'], self.workflow)
            if cleanup_fails: self.assertIn('retirement failed', summary['input_retirement_failure'])

    def native_binding(self):
        journal = self.directory / 'native-journal'
        journal.mkdir()
        configuration = self.directory / 'native-config.json'
        configuration.write_text(json.dumps({'library': '/pinned/native.so', 'registry': '/pinned/registry'}))
        config_sha256 = hashlib.sha256(configuration.read_bytes()).hexdigest()
        semantic = hashlib.sha256(b'independently verified native semantic configuration').digest()
        manifest = self.directory / 'manifest.json'
        manifest.write_text(json.dumps({'host_configuration_sha256': semantic.hex()}))
        files = {'preparation_sha256': manifest,
                 'complete_body_sha256': self.directory / 'complete-body.bin',
                 'head_token': journal / 'HEAD.json'}
        binding = {'expected': {'structural_expected': 1}, 'configuration_sha256': list(semantic)}
        for field, path in files.items():
            if not path.exists(): path.write_bytes(field.encode())
            binding[field] = list(hashlib.sha256(path.read_bytes()).digest())
        (self.directory / 'expected.json').write_text(json.dumps(binding['expected']))
        config = {'host_config': str(configuration), 'host_journal': str(journal)}
        self.assertNotEqual(config_sha256, semantic.hex())
        return config, binding, config_sha256, files

    def test_binding_pins_are_checked_without_another_native_verifier(self):
        config, binding, pin, files = self.native_binding()
        P.check_binding(config, self.directory, binding, pin)
        files['head_token'].write_bytes(b'another published head')
        with self.assertRaisesRegex(ValueError, 'head changed'):
            P.check_binding(config, self.directory, binding, pin)

    def test_configuration_file_change_rejects_even_with_unchanged_semantic_binding(self):
        config, binding, pin, _ = self.native_binding()
        Path(config['host_config']).write_text('{"library":"/substituted/native.so"}')
        with self.assertRaisesRegex(ValueError, 'configuration file changed'):
            P.check_binding(config, self.directory, binding, pin)

    def test_preparation_must_match_verified_semantic_configuration(self):
        config, binding, pin, files = self.native_binding()
        files['preparation_sha256'].write_text(json.dumps({'host_configuration_sha256': 'ab' * 32}))
        binding['preparation_sha256'] = list(hashlib.sha256(files['preparation_sha256'].read_bytes()).digest())
        with self.assertRaisesRegex(ValueError, 'verified host configuration'):
            P.check_binding(config, self.directory, binding, pin)

    def test_semantic_digest_must_be_a_nonzero_byte_array(self):
        config, binding, pin, _ = self.native_binding()
        for invalid in [None, 'ab' * 32, [0] * 32, [1] * 31, [True] * 32]:
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, 'verified host configuration'):
                P.check_binding(config, self.directory, binding | {'configuration_sha256': invalid}, pin)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.result = self.directory / 'owner/proofs/candidate-000000'
        self.result.mkdir(parents=True)
        self.workflow = {'schema_version': 1, 'boot_id': '01234567-89ab-cdef-0123-456789abcdef',
                         'started_monotonic_ms': 10, 'deadline_monotonic_ms': 600010}
        self.binding = {'structural_native_binding': 1}
        self.summary = {'status': 'succeeded', 'pool_service': True, 'pool_workflow': self.workflow,
                        'pool_result': {'workers_drained': True, 'partial_candidate': True, 'completed_requests': 0}}
        self.partial = {'status': 'partial', 'pool_workflow': self.workflow, 'native_host': self.binding,
                        'deadline_ms': 600000, 'candidate_journaled': True, 'workers_drained': True,
                        'started_ms': 10, 'stopped_ms': 150000,
                        'worker_failures': [], 'fresh_proofs': 1, 'native_applied': False}
        self.records = [{'job': '01' * 32, 'proof_bytes': 32}]

    def write(self, complete=False):
        (self.directory / 'summary.json').write_text(json.dumps(self.summary))
        (self.result / 'execution-jobs.json').write_text(json.dumps(self.records))
        (self.result / ('result.json' if complete else 'phase.json')).write_text(json.dumps(self.partial))

    def test_partial_phase_requires_progress_original_binding_and_drained_workers(self):
        self.write()
        complete, jobs, result = P.phase_result(self.directory, self.workflow, self.binding, set())
        self.assertFalse(complete)
        self.assertEqual(jobs, {'01' * 32})
        self.assertEqual(result, self.result)
        for field, value in [('deadline_ms', 600001), ('candidate_journaled', False),
                             ('workers_drained', False), ('fresh_proofs', 2), ('fresh_proofs', True),
                             ('stopped_ms', 600000), ('started_ms', -1),
                             ('native_applied', True), ('worker_failures', [{'worker': 2}]),
                             ('native_host', {'another_candidate': 1})]:
            original = copy.deepcopy(self.partial)
            self.partial[field] = value
            self.write()
            with self.assertRaises(ValueError): P.phase_result(self.directory, self.workflow, self.binding, set())
            self.partial = original

    def test_duplicate_or_empty_progress_cannot_trigger_another_phase(self):
        self.write()
        with self.assertRaises(ValueError): P.phase_result(self.directory, self.workflow, self.binding, {'01' * 32})
        for records in [[], self.records * 2, [{'job': 'invalid', 'proof_bytes': 32}],
                        [{'job': '01' * 32, 'proof_bytes': 2 ** 21 + 1}]]:
            self.records = records
            self.write()
            with self.assertRaises(ValueError): P.phase_result(self.directory, self.workflow, self.binding, set())

    def test_live_handoff_requires_an_open_two_request_prefix_service(self):
        self.summary['status'] = 'running'
        ready = self.directory / 'owner/proofs/pool-ready.json'
        ready.write_text(json.dumps({'max_requests': 2, 'preseal_only': True, 'pool_workflow': self.workflow}))
        self.partial.update(status='preseal_verified', preseal_only=True, completed_ms=100,
                            reused_proofs=0, stable_nodes=[{'job': [1] * 32}])
        self.write(complete=True)
        with patch.object(P.S, 'pin_preseal'):
            self.assertTrue(P.phase_result(self.directory, self.workflow, self.binding, set(), prefix=True, live=True)[0])
            with self.assertRaises(ValueError):
                P.phase_result(self.directory, self.workflow, self.binding, set(), prefix=False, live=True)
            (self.directory / 'owner/proofs/pool-stopped.json').write_text('{}')
            with self.assertRaises(ValueError):
                P.phase_result(self.directory, self.workflow, self.binding, set(), prefix=True, live=True)

    def test_final_result_still_requires_independent_audit_and_exact_reuse_count(self):
        self.summary['pool_result'] = {'workers_drained': True, 'completed_requests': 1}
        self.partial = {'status': 'proved_cpu_audit_pending', 'root_file': 'node.6.0',
                        'native_host': self.binding, 'native_applied': False, 'worker_failures': [],
                        'started_ms': 150000, 'completed_ms': 250000,
                        'fresh_proofs': 1, 'reused_proofs': 1}
        (self.result / 'node.6.0').write_bytes(b'structural receipt fixture, not a proof')
        self.write(complete=True)
        self.assertTrue(P.phase_result(self.directory, self.workflow, self.binding, {'02' * 32})[0])
        self.partial['reused_proofs'] = 0
        self.write(complete=True)
        with self.assertRaises(ValueError): P.phase_result(self.directory, self.workflow, self.binding, {'02' * 32})

    def test_complete_cached_result_can_have_zero_new_proofs_without_another_phase(self):
        self.records = []
        self.summary['pool_result'] = {'workers_drained': True, 'completed_requests': 1}
        self.partial = {'status': 'proved_cpu_audit_pending', 'root_file': 'node.6.0',
                        'native_host': self.binding, 'native_applied': False, 'worker_failures': [],
                        'fresh_proofs': 0, 'reused_proofs': 1, 'started_ms': 150000, 'completed_ms': 150010}
        (self.result / 'node.6.0').write_bytes(b'structural cached result, not a proof')
        self.write(complete=True)
        complete, jobs, _ = P.phase_result(self.directory, self.workflow, self.binding, {'02' * 32})
        self.assertTrue(complete)
        self.assertEqual(jobs, set())

    def test_replacement_command_preserves_workflow_and_uses_original_owner(self):
        config = {'gpu_uuids': ['GPU-test'], 'pool_timing_approvals': {'GPU-test': '/approval.json'},
                  'gpu_binary': '/gpu', 'cpu_binary': '/cpu', 'host_config': '/native', 'host_journal': '/journal',
                  'count': 64, 'workload': '/workload', 'scratch': '/scratch', 'resource_assignment': '/allocation'}
        command = P.command(config, '/fixture', '/requests', '/workflow', '/output', Path('/prior'))
        self.assertEqual(command[command.index('--recover-owner') + 1], '/prior/owner')
        self.assertEqual(command[command.index('--pool-runtime-seconds') + 1], '180')
        self.assertEqual(command[command.index('--pool-workflow') + 1], '/workflow')
        self.assertNotIn('--resource-assignment', command)
        config['pool_timing_approvals'] = {}
        with self.assertRaises(ValueError): P.command(config, '/fixture', '/requests', '/workflow', '/output', None)

    def test_reconciliation_checks_exact_supervisor_units_before_replacement(self):
        (self.directory / 'config.json').write_text(json.dumps({'owner_unit': 'owner'}))
        (self.directory / 'summary.json').write_text(json.dumps({'attempts': [{'unit': 'worker'}]}))
        with patch.object(P.S.Controller, 'reconcile') as controller, patch.object(P.S, 'quiescent_fleet') as workers:
            P.reconcile(self.directory)
            controller.assert_called_once_with(self.directory)
            workers.assert_called_once_with('owner', [{'unit': 'worker'}])
            workers.side_effect = ValueError('worker still alive')
            with self.assertRaisesRegex(ValueError, 'still alive'): P.reconcile(self.directory)

    def test_owned_profile_reaches_maintained_parser_on_initial_and_recovered_phases(self):
        config = {'gpu_uuids': ['GPU-test'], 'pool_timing_approvals': {'GPU-test': '/approval.json'},
                  'gpu_binary': '/gpu', 'cpu_binary': '/cpu', 'host_config': '/native', 'host_journal': '/journal',
                  'count': 64, 'workload': str(P.S.Owned.WORKLOAD), 'scratch': '/scratch', 'owned_public_gpu': True}
        for previous in [None, Path('/previous')]:
            with self.subTest(previous=previous):
                command = P.command(config, '/fixture', '/requests', '/workflow', '/output', previous)
                args = P.S.argument_parser().parse_args(command[2:])
                self.assertTrue(P.S.Owned.check_mode(args))
                self.assertEqual(args.pool_runtime_seconds, 180)
                self.assertEqual(str(args.pool_workflow), '/workflow')
                self.assertEqual(P.S.T.resource_profile(args.workload, 'paired', 'owned')['typed_ram_admission'], 'owned')
        config['owned_public_gpu'] = False
        args = P.S.argument_parser().parse_args(P.command(config, '/fixture', '/requests', '/workflow', '/output', None)[2:])
        self.assertFalse(P.S.Owned.check_mode(args))

    def test_owned_option_requires_boolean_configuration(self):
        for value in ['false', 'true', 0, 1, None]:
            config = {'gpu_uuids': ['GPU-test'], 'pool_timing_approvals': {'GPU-test': '/approval.json'},
                      'owned_public_gpu': value}
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'must be a boolean'):
                P.command(config, '/fixture', '/requests', '/workflow', '/output', None)

    def test_bounded_request_selects_owner_snapshot_and_rejects_changed_launch_pins(self):
        fixture = self.directory / 'native-fixture'
        owner = self.directory / 'owner'
        expected = self.directory / 'expected.json'
        launch = {'fixture': str(fixture), 'owner_directory': str(owner),
                  'expected': str(expected), 'native_host': self.binding, 'pool_workflow': self.workflow}
        config = self.directory / 'config.json'
        config.write_text(json.dumps(launch))
        request = P.prepared_request(self.directory, fixture, self.binding, self.workflow)
        # The Rust owner is invoked with its private copy and the pinned expected
        # file, not the source fixture originally supplied to the controller.
        self.assertEqual(request['fixture'], str(owner / 'input'))
        self.assertEqual(request['expected'], str(expected))
        self.assertNotEqual(request['fixture'], str(fixture))
        self.assertEqual(request['deadline_ms'], self.workflow['deadline_monotonic_ms'] - self.workflow['started_monotonic_ms'])
        for field, value in [('fixture', '/another'), ('owner_directory', '/another'),
                             ('expected', '/another.json'), ('native_host', {'changed': 1}),
                             ('pool_workflow', self.workflow | {'started_monotonic_ms': 11})]:
            config.write_text(json.dumps(launch | {field: value}))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'verified owner snapshot'):
                P.prepared_request(self.directory, fixture, self.binding, self.workflow)
        config.write_text(json.dumps(launch))
        with self.assertRaisesRegex(ValueError, 'verified owner snapshot'):
            P.prepared_request(self.directory, fixture, self.binding | {'changed': 1}, self.workflow)

    def test_unreserved_handoff_is_rejected_before_candidate_preparation(self):
        output = self.directory / 'unreserved-handoff'
        callback = {'command': ['/pinned/callback'], 'pins': {'/pinned/callback': '01' * 32}}
        with self.assertRaisesRegex(ValueError, 'continuation reserve'):
            P.run({}, self.directory, '/missing-clock', output, handoff=callback)
        self.assertFalse(output.exists())

    def handoff_scenario(self, failure=None):
        """Exercise controller transitions with synthetic receipts and no proofs/services."""
        config, binding, _, files = self.native_binding()
        binding['scope'] = 'prefix'
        config.update(preseal_only=True, arrival_store='/structural-intake')
        output = self.directory / 'deferral-run'
        events, launches, callbacks = [], [], []
        clock_now = [100]
        original_handoff = P.Handoff.run
        final_binding = {k: v for k, v in binding.items() if k != 'scope'}
        seal = {'schema_version': 1, 'pool_workflow': self.workflow,
                'sealed_monotonic_ms': 100, 'deadline_monotonic_ms': 180100}

        def write(path, value):
            path.write_text(json.dumps(value))

        def command(config, fixture, requests, workflow, phase, previous):
            self.assertEqual(P.read(workflow), self.workflow)
            if previous is not None:
                self.assertIn(('reconciled', previous), events)
                self.assertEqual(previous, output / 'phase-000')
            launches.append((phase, previous))
            return ['structural-launch', str(phase)]

        def launch(argv, **kwargs):
            phase = Path(argv[1]); number = len(launches) - 1
            inbox = output / f'requests-{number:03}'
            proofs = phase / 'owner/proofs'
            candidate = proofs / 'candidate-000000'
            candidate.mkdir(parents=True)
            fleet = phase / 'fleet.json'
            write(fleet, {'pool_scheduling': {'dispatch_deadline_monotonic_ms': 50100 if number == 0 else 150100}})
            write(phase / 'config.json', config | {'pool_prefix_handoff': True,
                'pool_workflow': self.workflow, 'fleet_plan': str(fleet), 'native_host': binding,
                'fixture': str(self.directory), 'owner_directory': str(phase / 'owner'),
                'expected': str(phase / 'expected.json')})
            write(phase / 'native-host.json', binding)
            write(proofs / 'pool-ready.json', {'max_requests': 2, 'preseal_only': True, 'pool_workflow': self.workflow})
            receipt = {'status': 'preseal_verified', 'preseal_only': True, 'native_host': binding,
                'pool_workflow': self.workflow, 'native_applied': False, 'worker_failures': [],
                'fresh_proofs': 1 if number == 0 else 0, 'reused_proofs': number,
                'started_ms': 10, 'completed_ms': 90, 'root_file': None, 'stable_nodes': [{'job': [1] * 32}]}
            write(candidate / 'result.json', receipt)
            write(candidate / 'execution-jobs.json', self.records if number == 0 else [])
            summary = {'status': 'running', 'pool_service': True, 'pool_workflow': self.workflow}
            write(phase / 'summary.json', summary)

            class Process:
                returncode = None
                drain_polls = 0
                def poll(process):
                    if process.returncode is not None:
                        return process.returncode
                    stopping = (inbox / 'stop').exists()
                    final = (inbox / '000001.json').exists()
                    if stopping and process.drain_polls == 0:
                        process.drain_polls += 1
                        return None
                    if stopping or final:
                        stopped = {'schema_version': 1, 'workers_drained': True,
                                   'completed_requests': 1 if stopping else 2, 'stopped_ms': 95}
                        if stopping:
                            events.append(('stop', phase))
                            if failure == 'drain': stopped['workers_drained'] = False
                            if failure == 'natural-stop': stopped['reason'] = 'dispatch_window_closed'
                            if failure == 'workflow-expiry': clock_now[0] = self.workflow['deadline_monotonic_ms']
                            if failure == 'head': files['head_token'].write_bytes(b'changed head')
                            if failure == 'seal': write(proofs / 'prefix-transition-intent.json', {})
                            if failure == 'prefix': write(candidate / 'result.json', receipt | {'changed': True})
                            if failure == 'workflow':
                                launch_config = P.read(phase / 'config.json')
                                launch_config['pool_workflow'] = self.workflow | {'started_monotonic_ms': 11}
                                write(phase / 'config.json', launch_config)
                        else:
                            final_candidate = proofs / 'candidate-000001'; final_candidate.mkdir()
                            write(final_candidate / 'execution-jobs.json', [{'job': '02' * 32, 'proof_bytes': 32}])
                            write(final_candidate / 'result.json', {'status': 'proved_cpu_audit_pending',
                                'root_file': 'node.6.0', 'native_host': final_binding, 'native_applied': False,
                                'worker_failures': [], 'fresh_proofs': 1, 'reused_proofs': 1,
                                'started_ms': 90, 'completed_ms': 99})
                            (final_candidate / 'node.6.0').write_bytes(b'structural fixture, not a proof')
                        write(proofs / 'pool-stopped.json', stopped)
                        write(phase / 'summary.json', summary | {'status': 'succeeded', 'pool_result': stopped})
                        process.returncode = 0
                    return process.returncode
                def terminate(process): process.returncode = 1
                def wait(process, timeout): return process.returncode
                def kill(process): process.returncode = 1
            return Process()

        def handoff(phase, cache, callback):
            callbacks.append(phase)
            if phase.name == 'phase-000':
                if failure == 'callback':
                    (phase / 'handoff').mkdir()
                    raise ValueError('bounded native handoff failed; no automatic retry')
                return original_handoff(phase, cache, callback)
            return {'fixture': str(self.directory), 'native_host': final_binding, 'pool_seal': seal,
                    'arrival_selection': 'ab' * 32}

        def reconcile(phase):
            if failure == 'reconciliation': raise ValueError('worker still live')
            events.append(('reconciled', phase))

        with (patch.object(P.T, 'workflow', return_value=(self.workflow, {})),
              patch.object(P.T, 'workflow_clock', side_effect=lambda: (self.workflow['boot_id'], clock_now[0])),
              patch.object(P, 'command', side_effect=command), patch.object(P.subprocess, 'Popen', side_effect=launch),
              patch.object(P.Handoff, 'run', side_effect=handoff), patch.object(P.S, 'pin_preseal'),
              patch.object(P, 'reconcile', side_effect=reconcile), patch.object(P, 'stop_owned_services'),
              patch.object(P.time, 'sleep')):
            callback = {'command': ['/pinned/callback'], 'pins': {'/pinned/callback': '01' * 32},
                        'continuation_reserve_ms': 75_000}
            if failure:
                messages = {'callback': 'bounded native handoff failed', 'drain': 'successful drained supervision',
                    'reconciliation': 'worker still live', 'natural-stop': 'planned successful worker drain',
                    'head': 'head changed', 'seal': 'started handoff', 'prefix': 'input changed',
                    'workflow': 'input changed', 'workflow-expiry': 'original deadline expired'}
                with self.assertRaisesRegex(ValueError, messages[failure]):
                    P.run(config, self.directory, '/clock', output, handoff=callback)
            else:
                P.run(config, self.directory, '/clock', output, handoff=callback)
        summary = P.read(output / 'summary.json')
        self.assertEqual(summary['pool_workflow'], self.workflow)
        self.assertEqual(len(callbacks), len(launches))
        if failure:
            self.assertEqual(summary['status'], 'failed')
            self.assertEqual(len(launches), 1)
            self.assertFalse((output / 'requests-000/000001.json').exists())
        else:
            self.assertEqual(len(launches), 2)
            self.assertEqual(summary['status'], 'proved_cpu_audit_pending')
            self.assertFalse(summary['native_applied'])
            self.assertEqual(summary['pool_seal'], seal)
            self.assertEqual(summary['accepted_proofs'], 2)
            self.assertEqual([p['fresh_proofs'] for p in summary['phases']], [1, 0, 1])
            self.assertIn('handoff_deferral', summary['phases'][0])
            self.assertFalse((output / 'phase-000/handoff').exists())
            self.assertFalse((output / 'requests-000/000001.json').exists())
            self.assertEqual(P.read(output / 'requests-000/000000.json')['deadline_ms'], 600000)
            self.assertEqual(P.read(output / 'requests-001/000000.json')['deadline_ms'], 600000)

    def test_planned_deferral_drains_once_and_reuses_completed_prefix_under_original_clock(self):
        self.handoff_scenario()

    def test_failed_handoff_cannot_be_deferred_or_retried(self):
        self.handoff_scenario('callback')

    def test_deferral_cannot_replace_undrained_workers(self):
        self.handoff_scenario('drain')

    def test_deferral_requires_reconciliation_before_replacement(self):
        self.handoff_scenario('reconciliation')

    def test_deferral_cannot_treat_natural_expiry_as_requested_drain(self):
        self.handoff_scenario('natural-stop')

    def test_deferral_rejects_a_changed_native_head(self):
        self.handoff_scenario('head')

    def test_deferral_rejects_a_started_native_seal(self):
        self.handoff_scenario('seal')

    def test_deferral_rejects_changed_prefix_bytes(self):
        self.handoff_scenario('prefix')

    def test_deferral_cannot_replace_the_original_workflow(self):
        self.handoff_scenario('workflow')

    def test_deferral_cannot_continue_after_original_workflow_expiry(self):
        self.handoff_scenario('workflow-expiry')


if __name__ == '__main__':
    unittest.main()
