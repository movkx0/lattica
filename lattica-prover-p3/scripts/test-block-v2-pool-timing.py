#!/usr/bin/env python3
"""Host binding and artifact substitution tests; no GPU timing is fabricated."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import block_v2_pool_timing as T


class TimingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / 'worker'
        self.binary.write_bytes(b'structural test executable')
        self.record = self.root / 'record.bin'
        self.record.write_bytes(b'structural record; Rust must decode and bind actual calibration')
        self.device = {'uuid': 'GPU-test', 'nvidia': {'uuid': 'GPU-test', 'name': 'test',
            'total_bytes': 16 << 30, 'pci': '0:1', 'driver': 'driver-a'}, 'opencl': {'driver': 'runtime-a'}}
        self.budget = {'unit': 'worker-a.service', 'startup_guard': '/tmp/a',
            'native_host': {'generation': 1}, 'host': {'worker_bytes': 3 << 30, 'scratch_path': '/tmp/a', 'scratch_device': 1},
            'gpu': {'uuid': 'GPU-test', 'managed_bytes': 7 << 30, 'available_bytes': 13 << 30},
            'cpu': {'rayon_threads': 4}}
        self.profile = {'schema_version': 1, 'shape': [64, 6], 'cache_entries': 2}
        self.environment = {'LATTICA_PROVING_POLICY': 'gpu-required', 'LATTICA_PROVING_REPORT': '1',
            'LATTICA_V2_WORKER_BUDGET': '/tmp/a', 'LATTICA_V2_ACCOUNTING_UNIT': 'worker-a.service',
            'LATTICA_SPILL_DIR': '/tmp/a', 'LATTICA_V2_GPU_RANDOMNESS': '1'}
        binding = T.binding(self.binary, self.device, self.budget, self.profile, self.environment)
        self.approval = {'schema_version': 1, 'approved_for_pool_import': True,
            'binding': binding, 'identity': T.fingerprints(binding), 'executable': [3] * 32,
            'records': [{'path': str(self.record), 'sha256': T.digest(self.record),
                         'content_identity': [7] * 32, 'evidence': [8] * 32}]}
        self.path = self.root / 'approval.json'
        self.output = self.root / 'staged.json'

    def stage(self):
        self.path.write_text(json.dumps(self.approval))
        return T.stage(self.path, self.output, self.binary, self.device, self.budget, self.profile, self.environment)

    def test_observed_binding_pins_input_output_and_record(self):
        pins = self.stage()
        self.assertEqual(set(pins), {str(self.path), str(self.output), str(self.record)})
        self.assertEqual(json.loads(self.output.read_text())['identity'], T.fingerprints(self.approval['binding']))
        self.assertNotIn('sha256', json.loads(self.output.read_text())['records'][0])

    def test_new_process_paths_and_head_do_not_rewrite_measurement_identity(self):
        self.budget.update(unit='worker-b.service', startup_guard='/tmp/b', native_host={'generation': 2})
        self.budget['host']['scratch_path'] = '/tmp/b'
        self.budget['gpu']['available_bytes'] = 12 << 30
        self.environment.update(LATTICA_V2_WORKER_BUDGET='/tmp/b', LATTICA_V2_ACCOUNTING_UNIT='worker-b.service', LATTICA_SPILL_DIR='/tmp/b')
        self.stage()

    def test_inventory_occupancy_is_not_an_effective_setting(self):
        self.budget['detected_host'] = {'available_bytes': 40 << 30,
                                      'ancestors': [{'memory_current': 123, 'path': '/old'}]}
        self.budget['detected_gpu'] = {'nvidia': {'free_bytes': 13 << 30}}
        original = copy.deepcopy(self.budget)
        binding = T.binding(self.binary, self.device, self.budget, self.profile, self.environment)
        self.assertEqual(self.budget, original)
        self.assertEqual(binding, self.approval['binding'])
        self.budget['detected_host']['available_bytes'] = 39 << 30
        self.budget['detected_gpu']['nvidia']['free_bytes'] = 12 << 30
        self.stage()

    def test_budget_geometry_cache_and_backend_changes_are_rejected(self):
        original = copy.deepcopy((self.budget, self.profile, self.environment))
        changes = [lambda: self.budget['host'].update(worker_bytes=4 << 30),
                   lambda: self.budget['host'].update(scratch_device=2),
                   lambda: self.budget['gpu'].update(managed_bytes=8 << 30),
                   lambda: self.budget['cpu'].update(rayon_threads=3),
                   lambda: self.profile.update(cache_entries=1),
                   lambda: self.profile.update(shape=[32, 6]),
                   lambda: self.environment.update(LATTICA_V2_GPU_RANDOMNESS='0'),
                   lambda: self.environment.update(LATTICA_PROVING_POLICY='compatible'),
                   lambda: self.environment.update(LATTICA_PROVING_REPORT='0')]
        for change in changes:
            self.budget, self.profile, self.environment = copy.deepcopy(original)
            change()
            with self.assertRaises(ValueError): self.stage()

    def test_different_binary_driver_runtime_or_device_is_rejected(self):
        self.binary.write_bytes(b'another executable')
        with self.assertRaises(ValueError): self.stage()
        self.binary.write_bytes(b'structural test executable')
        original = copy.deepcopy(self.device)
        for section, key, value in [('nvidia', 'driver', 'driver-b'), ('opencl', 'driver', 'runtime-b'),
                                    ('nvidia', 'name', 'other'), ('nvidia', 'uuid', 'GPU-other')]:
            self.device = copy.deepcopy(original); self.device[section][key] = value
            with self.assertRaises(ValueError): self.stage()

    def test_unapproved_and_zero_fingerprint_inputs_are_rejected(self):
        original = copy.deepcopy(self.approval)
        for key, value in [('approved_for_pool_import', False), ('schema_version', 2), ('schema_version', True), ('executable', [0] * 32)]:
            self.approval = copy.deepcopy(original); self.approval[key] = value
            with self.assertRaises(ValueError): self.stage()
        self.approval = original; self.approval['identity'][0][0] ^= 1
        with self.assertRaises(ValueError): self.stage()

    def test_record_mutation_duplication_and_missing_evidence_are_rejected(self):
        self.record.write_bytes(b'changed')
        with self.assertRaises(ValueError): self.stage()
        self.record.write_bytes(b'structural record; Rust must decode and bind actual calibration')
        self.approval['records'] *= 2
        with self.assertRaises(ValueError): self.stage()
        self.approval['records'] = self.approval['records'][:1]
        self.approval['records'][0]['evidence'] = [0] * 32
        with self.assertRaises(ValueError): self.stage()

    def test_every_assigned_worker_requires_a_unique_approval(self):
        self.path.write_text('{}')
        self.assertEqual(T.approvals([f'GPU-test={self.path}'], ['GPU-test']), {'GPU-test': self.path})
        for values, uuids in [([f'GPU-test={self.path}'] * 2, ['GPU-test']),
                              ([f'GPU-test={self.path}'], ['GPU-test', 'GPU-second']),
                              ([f'GPU-other={self.path}'], ['GPU-test'])]:
            with self.assertRaises(ValueError): T.approvals(values, uuids)

    def test_symlink_oversize_and_relative_record_inputs_are_rejected(self):
        link = self.root / 'link.bin'; link.symlink_to(self.record)
        for path in [str(link), 'record.bin']:
            self.approval['records'][0]['path'] = path
            with self.assertRaises((ValueError, FileNotFoundError)): self.stage()
        self.approval['records'][0]['path'] = str(self.record)
        self.record.write_bytes(b'x' * 4097)
        with self.assertRaises(ValueError): self.stage()

    def test_record_count_and_unknown_manifest_fields_are_rejected(self):
        self.approval['records'] *= 65
        with self.assertRaises(ValueError): self.stage()
        self.approval['records'] = []
        with self.assertRaises(ValueError): self.stage()
        self.approval['extra'] = 'not admitted'
        with self.assertRaises(ValueError): self.stage()

    def test_existing_output_is_never_overwritten(self):
        self.output.write_bytes(b'preserved')
        with self.assertRaises(FileExistsError): self.stage()
        self.assertEqual(self.output.read_bytes(), b'preserved')

    def test_duplicate_manifest_fields_are_rejected(self):
        self.path.write_text('{"schema_version":1,"schema_version":2}')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            T.stage(self.path, self.output, self.binary, self.device, self.budget, self.profile, self.environment)


class WorkflowTests(unittest.TestCase):
    BOOT = '01234567-89ab-cdef-0123-456789abcdef'

    def original(self):
        return {'schema_version': 1, 'boot_id': self.BOOT,
                'started_monotonic_ms': 10, 'deadline_monotonic_ms': 10 + T.WORKFLOW_MS}

    def test_deadline_and_clock_cannot_be_extended_or_rebased(self):
        original = self.original()
        for now in [10, 180010, 599999]:
            self.assertEqual(T.validate_workflow(original, self.BOOT, now), original)
        for now in [9, original['deadline_monotonic_ms'], original['deadline_monotonic_ms'] + 1]:
            with self.assertRaises(ValueError): T.validate_workflow(original, self.BOOT, now)
        for field, value in [('schema_version', True), ('boot_id', '0' * 36),
                             ('deadline_monotonic_ms', 11 + T.WORKFLOW_MS),
                             ('started_monotonic_ms', -1), ('deadline_monotonic_ms', 1 << 64),
                             ('started_monotonic_ms', True)]:
            changed = dict(original, **{field: value})
            with self.assertRaises(ValueError): T.validate_workflow(changed, self.BOOT, 20)
        with self.assertRaises(ValueError): T.validate_workflow(dict(original, extra=1), self.BOOT, 20)

    def test_recovery_uses_the_exact_original_workflow(self):
        from unittest.mock import patch
        original = self.original()
        previous = {'pool_scheduling': {'old': 'expired service window'}, 'pool_requests': '/old',
                    'pool_workflow': original}
        with patch.object(T, 'workflow_clock', return_value=(self.BOOT, 180010)):
            value, pins = T.workflow(previous=previous)
            self.assertEqual(value, original)
            self.assertIsNot(value, original)
            self.assertEqual(pins, {})
            for field in ['pool_scheduling', 'pool_requests', 'pool_workflow']:
                with self.assertRaises(ValueError): T.workflow(previous={k: v for k, v in previous.items() if k != field})
        with patch.object(T, 'workflow_clock', return_value=(self.BOOT, original['deadline_monotonic_ms'])):
            with self.assertRaises(ValueError): T.workflow(previous=previous)

    def test_explicit_receipt_is_pinned_and_cannot_replace_recovery_origin(self):
        from unittest.mock import patch
        original = self.original()
        previous = {'pool_scheduling': {'old': 'window'}, 'pool_requests': '/old', 'pool_workflow': original}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'workflow.json'
            path.write_text(json.dumps(original))
            with patch.object(T, 'workflow_clock', return_value=(self.BOOT, 180010)):
                value, pins = T.workflow(path, previous)
                self.assertEqual(value, original)
                self.assertEqual(pins[str(path)], T.digest(path))
                changed = dict(original, started_monotonic_ms=180010, deadline_monotonic_ms=180010 + T.WORKFLOW_MS)
                path.write_text(json.dumps(changed))
                with self.assertRaises(ValueError): T.workflow(path, previous)
                path.write_text(json.dumps(original)[:-1] + ',"schema_version":1}')
                with self.assertRaises(ValueError): T.workflow(path, previous)


if __name__ == '__main__':
    unittest.main()
