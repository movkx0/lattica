#!/usr/bin/env python3
"""Request and supervision boundaries; no fabricated proof or timing approval."""
import copy
import hashlib
import importlib
import json
from pathlib import Path
import tempfile
import unittest

import block_v2_pool_calibration as C
import block_v2_pool_timing as T

S = importlib.import_module('block-v2-typed-shared-gpu-run')


class CalibrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / 'request.json'
        self.proof = self.root / 'seed.bin'
        self.proof.write_bytes(b'structural seed: Rust must independently verify cryptographic validity')
        self.value = {'schema_version': 1, 'jobs': ['01' * 32], 'seeds': [
            {'job': '02' * 32, 'path': str(self.proof), 'sha256': T.digest(self.proof)}]}

    def load(self):
        self.path.write_text(json.dumps(self.value))
        return C.load(self.path)

    def test_request_pins_exact_seed_and_separates_fresh_jobs(self):
        request, pins = self.load()
        self.assertEqual(request['jobs'], [[1] * 32])
        self.assertEqual(request['seeds'], [{'job': [2] * 32, 'path': str(self.proof)}])
        self.assertEqual(pins[str(self.proof)], T.digest(self.proof))
        self.assertEqual(pins[str(self.path)], T.digest(self.path))
        self.assertNotIn('identity', request)
        self.assertNotIn('approved_for_pool_import', request)

    def test_inventory_bounds_and_unknown_fields_reject(self):
        original = copy.deepcopy(self.value)
        for field, value in [('schema_version', True), ('jobs', []), ('jobs', ['01' * 32] * 17),
                             ('seeds', self.value['seeds'] * 128), ('approval', True), ('identity', [[1] * 32] * 5)]:
            with self.subTest(field=field):
                self.value = copy.deepcopy(original)
                self.value[field] = value
                with self.assertRaises(ValueError):
                    self.load()

    def test_duplicate_missing_nonhex_or_seeded_fresh_jobs_reject(self):
        for jobs in [['01' * 32] * 2, ['02' * 32], [True], ['ab'], ['GG' * 32]]:
            with self.subTest(jobs=jobs):
                self.value['jobs'] = jobs
                with self.assertRaises(ValueError):
                    self.load()

    def test_changed_duplicate_unbounded_and_relative_seeds_reject(self):
        original = copy.deepcopy(self.value)
        cases = [lambda v: v['seeds'][0].update(sha256='0' * 64),
                 lambda v: v['seeds'].append(copy.deepcopy(v['seeds'][0])),
                 lambda v: v['seeds'][0].update(path='relative.bin'),
                 lambda v: v['seeds'][0].update(path='/' + 'x' * 4096)]
        for change in cases:
            self.value = copy.deepcopy(original)
            change(self.value)
            with self.assertRaises(ValueError):
                self.load()

    def test_symlinked_and_oversized_inputs_reject(self):
        self.path.symlink_to(self.proof)
        with self.assertRaises(ValueError):
            C.load(self.path)
        self.path.unlink()
        linked = self.root / 'linked.bin'
        linked.symlink_to(self.proof)
        self.value['seeds'][0]['path'] = str(linked)
        with self.assertRaises(ValueError):
            self.load()
        self.path.write_bytes(b' ' * (T.MAX_JSON_BYTES + 1))
        with self.assertRaises(ValueError):
            C.load(self.path)

    def test_calibration_cannot_enable_pool_recovery_application_or_automatic_retry(self):
        args = S.argument_parser().parse_args(['--pool-calibration', str(self.path), '--gpu-uuid', 'GPU-test'])
        self.assertTrue(C.check_mode(args))
        for field in ['pool_requests', 'pool_timing_approval', 'preseal', 'reuse_preseal',
                      'recover_owner', 'recover_cached_only', 'allow_worker_failover', 'arrival_store',
                      'arrival_selection', 'supervise', 'recover_controller']:
            changed = copy.deepcopy(args)
            setattr(changed, field, True)
            with self.subTest(field=field), self.assertRaises(ValueError):
                C.check_mode(changed)
        for uuids in [[], ['GPU-a', 'GPU-b']]:
            changed = copy.deepcopy(args)
            changed.gpu_uuid = uuids
            with self.assertRaises(ValueError):
                C.check_mode(changed)
        args.pool_runtime_seconds = 181
        with self.assertRaises(ValueError):
            C.check_mode(args)

    def test_host_identity_is_computed_for_the_actual_image_and_settings(self):
        self.load()
        binary = self.root / 'worker'
        binary.write_bytes(b'structural executable')
        device = {'uuid': 'GPU-test', 'nvidia': {'uuid': 'GPU-test', 'name': 'test',
            'total_bytes': 16 << 30, 'pci': '0:1', 'driver': 'driver'}, 'opencl': {'driver': 'opencl'}}
        budget = {'host': {'worker_bytes': 3 << 30}, 'gpu': {'uuid': 'GPU-test'}, 'unit': 'first'}
        environment = {'LATTICA_PROVING_POLICY': 'gpu-required', 'LATTICA_PROVING_REPORT': '1'}
        request, report, pins = C.stage(self.path, binary, device, budget, {}, environment)
        self.assertEqual(request['identity'], T.fingerprints(report['binding']))
        self.assertFalse(report['approved_for_pool_import'])
        self.assertEqual(report['source_pins'], pins)
        budget['unit'] = 'next'
        self.assertEqual(C.stage(self.path, binary, device, budget, {}, environment)[0]['identity'], request['identity'])
        binary.write_bytes(b'another executable')
        self.assertNotEqual(C.stage(self.path, binary, device, budget, {}, environment)[0]['identity'], request['identity'])

    def receipt(self, block_capacity=64):
        request, _ = self.load()
        request['identity'] = [[3] * 32] * 5
        workflow = {'schema_version': 1, 'boot_id': 'x' * 36,
                    'started_monotonic_ms': 1000, 'deadline_monotonic_ms': 601000}
        window = {'dispatch_deadline_monotonic_ms': 151000}
        (self.root / 'node.1.0').write_bytes(b'structural proof bytes')
        (self.root / 'timing-000.bin').write_bytes(b'structural record; needs Rust decode and independent host audit')
        receipt = {'schema_version': 1, 'status': 'calibrated_cpu_audit_pending',
            'approved_for_pool_import': False, 'scheduled_throughput_admitted': False, 'native_applied': False,
            'workers_drained': True, 'workspace_released': True, 'independent_complete_audit_pending': True,
            'bootstrap_ms': 180000, 'pool_workflow': workflow, 'native_host': None, 'gpu_uuid': 'GPU-test',
            'identity': request['identity'], 'executable': [4] * 32, 'fresh_proofs': 1, 'seed_proofs': 1,
            'fresh_recursive_dag': False, 'existing_recursive_proofs_imported': True,
            'started_ms': 10, 'completed_ms': 100, 'stopped_ms': 110,
            'dispatch_deadline_ms': 150000, 'observations': [{'job': [1] * 32, 'mode': 3, 'warm': False,
                'issued_ms': 15, 'accepted_ms': 99, 'elapsed_ms': 84, 'estimate_ms': 180000,
                'proof_bytes': len(b'structural proof bytes'), 'estimate_source': 'Bootstrap', 'file': 'node.1.0'}],
            'records': [{'path': str(self.root / 'timing-000.bin'), 'content_identity': [5] * 32}]}
        def check(value):
            C.validate_result(value, request, workflow, window, None, 'GPU-test', self.root,
                              block_capacity=block_capacity)
        return receipt, check

    def test_receipt_names_are_bounded_by_the_selected_capacity(self):
        receipt, check128 = self.receipt(128)
        _, check64 = self.receipt(64)
        for name in ('node.7.0', 'node.0.127'):
            (self.root / name).write_bytes(b'structural proof bytes')
            changed = copy.deepcopy(receipt)
            changed['observations'][0]['file'] = name
            check128(changed)
            with self.assertRaises(ValueError):
                check64(changed)
        for name in ('node.7.1', 'node.0.128', 'node.8.0', 'node.1.00'):
            changed = copy.deepcopy(receipt)
            changed['observations'][0]['file'] = name
            with self.subTest(name=name), self.assertRaises(ValueError):
                check128(changed)

    def test_receipt_validation_never_grants_timing_approval_or_application(self):
        receipt, check = self.receipt()
        check(receipt)
        for field in ['approved_for_pool_import', 'scheduled_throughput_admitted', 'native_applied']:
            changed = copy.deepcopy(receipt)
            changed[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                check(changed)

    def test_expired_or_extended_work_and_shutdown_are_rejected(self):
        receipt, check = self.receipt()
        for field, value in [('started_ms', True), ('completed_ms', 150000),
                             ('stopped_ms', 180000), ('dispatch_deadline_ms', 150002)]:
            changed = copy.deepcopy(receipt)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                check(changed)

    def test_imported_or_reduced_bootstrap_samples_are_rejected(self):
        receipt, check = self.receipt()
        for field, value in [('job', [8] * 32), ('warm', True), ('estimate_ms', 1),
                             ('estimate_source', 'Calibration'), ('file', '../seed.bin'), ('proof_bytes', 1)]:
            changed = copy.deepcopy(receipt)
            changed['observations'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                check(changed)

    def test_record_substitution_and_incomplete_drain_are_rejected(self):
        receipt, check = self.receipt()
        for field, value in [('workers_drained', False), ('records', []), ('fresh_proofs', True), ('gpu_uuid', 'other')]:
            changed = copy.deepcopy(receipt)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                check(changed)
        receipt['records'][0]['path'] = str(self.proof)
        with self.assertRaises(ValueError):
            check(receipt)

    def test_resident_mode_controls_warm_samples(self):
        receipt, _ = self.receipt()
        request, _ = self.load()
        request['identity'] = receipt['identity']
        request['jobs'].append([6] * 32)
        receipt.update(fresh_proofs=2, completed_ms=110, stopped_ms=120)
        second = copy.deepcopy(receipt['observations'][0])
        second.update(job=[6] * 32, issued_ms=100, accepted_ms=105, elapsed_ms=5,
                      file='node.1.1', mode=3, warm=True, estimate_source='ColdLive', estimate_ms=100)
        (self.root / 'node.1.1').write_bytes(b'structural proof bytes')
        receipt['observations'].append(second)
        def check():
            C.validate_result(receipt, request, receipt['pool_workflow'],
                {'dispatch_deadline_monotonic_ms': 151000}, None, 'GPU-test', self.root)
        check()
        second['mode'] = 4
        with self.assertRaises(ValueError):
            check()
        second.update(warm=False, estimate_source='Bootstrap', estimate_ms=180000)
        check()

    def test_partial_calibration_cannot_claim_a_fresh_full_dag(self):
        receipt, check = self.receipt()
        receipt['fresh_recursive_dag'] = True
        with self.assertRaises(ValueError):
            check(receipt)


if __name__ == '__main__':
    unittest.main()
