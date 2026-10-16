#!/usr/bin/env python3
"""Structural handoff fence tests; no native or GPU proof qualification."""
import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import block_v2_pool_handoff as H


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.proofs = self.root / 'proofs'
        self.proofs.mkdir()
        self.workflow = {'schema_version': 1, 'boot_id': '01234567-89ab-cdef-0123-456789abcdef',
                         'started_monotonic_ms': 100, 'deadline_monotonic_ms': 600100}
        self.prefix = {'scope': 'prefix', 'schema_version': 1, 'head_token': [1] * 32, 'generation': 2,
                       'configuration_sha256': [2] * 32, 'expected': {'schema_version': 1, 'count': 3,
                       'profile': [3] * 32, 'chain': [4] * 32, 'root': [1] * 4,
                       'block_height': 8, 'authorized_issuance': {'2': 7}}}
        self.final = copy.deepcopy(self.prefix)
        self.final.pop('scope')
        self.final['expected'].update(count=4, root=[2] * 4, authorized_issuance={'2': 7, '3': 9})
        self.seal = {'schema_version': 1, 'pool_workflow': self.workflow, 'sealed_monotonic_ms': 200,
                     'deadline_monotonic_ms': 180200}
        self.config = {'owner_directory': str(self.root), 'native_host': self.prefix,
                       'pool_workflow': self.workflow, 'preseal_only': True, 'pool_prefix_handoff': True}
        self.request = {'schema_version': 1, 'fixture': str(self.root / 'final'),
                        'expected': str(self.root / 'final/expected.json'), 'native_host': self.final,
                        'deadline_ms': 600000, 'arrival_selection': 'ab' * 32, 'pool_seal': self.seal}
        self.record = {'schema_version': 1, 'original': self.prefix, 'workflow': self.workflow,
                       'prefix_root': [1] * 32, 'final_root': [2] * 32, 'request': self.request,
                       'prepared_ms': 150}

    def write(self, name, record=None):
        (self.proofs / name).write_text(json.dumps(self.record if record is None else record))

    def clock(self, now=300):
        return patch.object(H.T, 'workflow_clock', return_value=(self.workflow['boot_id'], now))

    def admission_fixture(self, remaining=16000, now=300):
        phase = self.root / 'phase'
        phase.mkdir()
        fleet = phase / 'fleet.json'
        fleet.write_text(json.dumps({'pool_scheduling': {'dispatch_deadline_monotonic_ms': now + remaining}}))
        config = {'pool_prefix_handoff': True, 'arrival_store': '/intake', 'owner_unit': 'unused.service',
                  'pool_workflow': self.workflow, 'fleet_plan': str(fleet)}
        (phase / 'config.json').write_text(json.dumps(config))
        (self.proofs / 'result.json').write_text('{}')
        callback = {'command': ['/pinned/callback'], 'pins': {'/pinned/callback': '01' * 32}}
        return phase, callback

    def test_short_phase_defers_before_creating_a_service_or_calling_callback(self):
        phase, callback = self.admission_fixture()
        with self.clock(), patch.object(H.subprocess, 'run') as run:
            with self.assertRaises(H.HandoffWindowUnavailable) as caught:
                H.run(phase, self.proofs, callback)
            run.assert_not_called()
        self.assertEqual(caught.exception.window['pool_workflow'], self.workflow)
        self.assertEqual(caught.exception.window['phase_deadline_monotonic_ms'], 16300)
        self.assertFalse((phase / 'handoff').exists())

    def test_insufficient_original_workflow_is_terminal_even_with_a_fresh_phase(self):
        now = self.workflow['deadline_monotonic_ms'] - H.MIN_HANDOFF_MS + 1
        phase, callback = self.admission_fixture(150000, now)
        with self.clock(now), patch.object(H.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'original workflow') as caught:
                H.run(phase, self.proofs, callback)
            self.assertNotIsInstance(caught.exception, H.HandoffWindowUnavailable)
            run.assert_not_called()
        self.assertFalse((phase / 'handoff').exists())

    def test_expired_phase_cannot_be_reclassified_as_planned_deferral(self):
        phase, callback = self.admission_fixture(0)
        with self.clock(), self.assertRaisesRegex(ValueError, 'expired') as caught:
            H.run(phase, self.proofs, callback)
        self.assertNotIsInstance(caught.exception, H.HandoffWindowUnavailable)
        self.assertFalse((phase / 'handoff').exists())

    def test_admitted_failure_is_terminal_and_keeps_original_service_cap(self):
        phase, callback = self.admission_fixture(H.MIN_HANDOFF_MS)
        supervisor = H.importlib.import_module('block-v2-typed-shared-gpu-run')
        with (self.clock(), patch.object(supervisor.G, 'systemctl', return_value='not-found'),
              patch.object(H.subprocess, 'run', return_value=H.subprocess.CompletedProcess([], 1)) as run):
            with self.assertRaisesRegex(ValueError, 'no automatic retry'):
                H.run(phase, self.proofs, callback)
            self.assertIn('--property=RuntimeMaxSec=30', run.call_args.args[0])
            run.assert_called_once()
            with self.clock(301), self.assertRaisesRegex(ValueError, 'already started') as caught:
                H.run(phase, self.proofs, callback)
            self.assertNotIsInstance(caught.exception, H.HandoffWindowUnavailable)
            run.assert_called_once()
        self.assertEqual(H.read(phase / 'config.json')['pool_workflow'], self.workflow)

    def cache_fixture(self):
        self.proofs.chmod(0o700)
        payload = b'explicit non-cryptographic public proof stub'
        (self.proofs / 'node.1.0').write_bytes(payload)
        node = {'level': 1, 'index': 0, 'bytes': len(payload), 'job': [1] * 32, 'artifact_digest': [2] * 32}
        receipt = {'status': 'preseal_verified', 'preseal_only': True, 'native_host': self.prefix,
                   'stable_nodes': [node]}
        (self.proofs / 'result.json').write_text(json.dumps(receipt))
        audit = {'status': 'passed', 'cpu_prefix_audited': True, 'cpu_audited_roots': 0,
                 'count': 3, 'nodes': [copy.deepcopy(node)]}
        return receipt, audit

    def test_completed_prefix_retirement_uses_only_exact_audited_outputs(self):
        receipt, audit = self.cache_fixture()
        pins = H.prefix_cache_pins(self.proofs, receipt)
        self.assertEqual(set(pins), {'result.json', 'node.1.0'})
        with patch.object(H.PublicCache, 'release_pinned', return_value={'files': 2}) as release:
            self.assertEqual(H.retire_audited_prefix(self.proofs, receipt, audit, pins, 12345), {'files': 2})
            release.assert_called_once_with(self.proofs, pins, 12345)

    def test_changed_incomplete_or_oversized_prefix_cannot_retire_files(self):
        receipt, audit = self.cache_fixture()
        for field, value in [('status', 'partial'), ('preseal_only', False), ('stable_nodes', []),
                             ('stable_nodes', receipt['stable_nodes'] * 63)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                H.prefix_cache_pins(self.proofs, dict(receipt, **{field: value}))
        for key, value in [('level', 6), ('index', 32), ('bytes', (2 << 20) + 1), ('job', [0] * 32)]:
            changed = copy.deepcopy(receipt); changed['stable_nodes'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): H.prefix_cache_pins(self.proofs, changed)
        pins = H.prefix_cache_pins(self.proofs, receipt)
        for key, value in [('status', 'failed'), ('cpu_prefix_audited', False), ('cpu_audited_roots', 1),
                           ('count', 4), ('nodes', [])]:
            with patch.object(H.PublicCache, 'release_pinned') as release:
                with self.subTest(key=key), self.assertRaises(ValueError):
                    H.retire_audited_prefix(self.proofs, receipt, dict(audit, **{key: value}), pins, 12345)
                release.assert_not_called()
        with self.assertRaisesRegex(ValueError, 'inventory'):
            H.retire_audited_prefix(self.proofs, receipt, audit, {}, 12345)

    def test_output_mutation_after_audit_does_not_grant_retirement_receipt(self):
        receipt, audit = self.cache_fixture()
        pins = H.prefix_cache_pins(self.proofs, receipt)
        path = self.proofs / 'node.1.0'; original = path.read_bytes()
        path.write_bytes(b'x' + original[1:])
        with patch.object(H.PublicCache.os, 'posix_fadvise') as advice:
            with self.assertRaisesRegex(ValueError, 'bytes changed'):
                H.retire_audited_prefix(self.proofs, receipt, audit, pins,
                                       time.monotonic_ns() // 1_000_000 + 30000)
            advice.assert_not_called()

    def test_extension_preserves_all_prefix_policies_and_only_allows_sealed_growth(self):
        H.check_extension(self.prefix, self.final)
        for key in ['head_token', 'generation', 'configuration_sha256', 'schema_version']:
            value = copy.deepcopy(self.final)
            value[key] = None
            with self.subTest(key=key), self.assertRaises(ValueError): H.check_extension(self.prefix, value)
        for key, changed in [('count', 2), ('count', H.Capacity.MAX_TRANSACTIONS + 1), ('count', True), ('block_height', 9),
                             ('chain', [9] * 32), ('profile', [9] * 32), ('authorized_issuance', {}),
                             ('authorized_issuance', {'2': 8})]:
            value = copy.deepcopy(self.final)
            value['expected'][key] = changed
            with self.subTest(key=key), self.assertRaises(ValueError): H.check_extension(self.prefix, value)
        with self.assertRaises(ValueError): H.check_extension(self.prefix, self.prefix)
        with self.assertRaises(ValueError): H.check_extension(self.final, self.final)

    def test_no_transition_keeps_original_plan_and_intent_without_receipt_fails_closed(self):
        self.assertIs(H.effective_config(self.config), self.config)
        self.write('prefix-transition-intent.json')
        with self.assertRaises(FileNotFoundError): H.effective_config(self.config)
        self.write('prefix-transition.json')
        with self.clock():
            result = H.effective_config(self.config)
        self.assertFalse(result['preseal_only'])
        self.assertFalse(result['pool_prefix_handoff'])
        self.assertEqual(result['native_host'], self.final)
        self.assertEqual(result['count'], 4)
        self.assertEqual(result['pool_seal'], self.seal)
        self.assertTrue(self.config['preseal_only'])

    def test_ambiguous_receipt_changed_scope_and_expired_seal_do_not_grant_authority(self):
        self.write('prefix-transition-intent.json')
        self.write('prefix-transition.json')
        for key, value in [('final_root', [0] * 32), ('schema_version', 2), ('original', self.final)]:
            altered = copy.deepcopy(self.record)
            altered[key] = value
            self.write('prefix-transition.json', altered)
            with self.clock(), self.assertRaises(ValueError): H.effective_config(self.config)
        self.write('prefix-transition.json')
        with self.clock(180200), self.assertRaises(ValueError): H.effective_config(self.config)
        with self.clock(), self.assertRaises(ValueError):
            H.effective_config(dict(self.config, pool_prefix_handoff=False))


if __name__ == '__main__':
    unittest.main()
