#!/usr/bin/env python3
"""Scope and lineage fixtures; these tests do not qualify GPU proof validity."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import block_v2_pool_phases as P


class PrefixContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.result = self.directory / 'owner/proofs/candidate-000000'
        self.result.mkdir(parents=True)
        self.workflow = {'schema_version': 1, 'boot_id': '01234567-89ab-cdef-0123-456789abcdef',
                         'started_monotonic_ms': 10, 'deadline_monotonic_ms': 600010}
        self.binding = {'scope': 'prefix', 'structural_native_binding': 1}
        self.summary = {'status': 'succeeded', 'pool_service': True, 'pool_workflow': self.workflow,
                        'pool_result': {'workers_drained': True, 'completed_requests': 1}}
        self.receipt = {'schema_version': 1, 'status': 'preseal_verified', 'preseal_only': True,
                        'pool_workflow': self.workflow, 'native_host': self.binding,
                        'native_applied': False, 'worker_failures': [], 'fresh_proofs': 1,
                        'reused_proofs': 0, 'started_ms': 10, 'completed_ms': 10000,
                        'stable_nodes': [{'job': [1] * 32, 'level': 1, 'index': 0, 'bytes': 32,
                                          'artifact_digest': [2] * 32}]}
        (self.result / 'node.1.0').write_bytes(b'x' * 32)
        self.records = [{'job': '01' * 32, 'proof_bytes': 32}]

    def write(self):
        (self.directory / 'summary.json').write_text(json.dumps(self.summary))
        (self.result / 'result.json').write_text(json.dumps(self.receipt))
        (self.result / 'execution-jobs.json').write_text(json.dumps(self.records))

    def check(self):
        return P.phase_result(self.directory, self.workflow, self.binding, set(), prefix=True)

    def test_prefix_requires_unclaimed_native_intake_and_exact_bounded_mode(self):
        P.S.check_pool_scope(True, True, [], '/intake', None)
        P.S.check_pool_scope(True, False, ['/cache'], '/intake', 'selection')
        P.S.check_pool_scope(True, False, [], None, None)
        for args in [(False, True, [], '/intake', None), (True, True, [], None, None),
                     (True, True, ['/cache'], '/intake', None),
                     (True, True, [], '/intake', 'sealed'),
                     (True, False, ['/cache'], '/intake', None),
                     (True, False, [], None, 'selection'),
                     (False, False, ['/cache'], '/intake', 'selection')]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                P.S.check_pool_scope(*args)

    def test_prefix_completion_exports_exact_accepted_nodes_without_root(self):
        self.write()
        complete, jobs, directory = self.check()
        self.assertTrue(complete)
        self.assertEqual(jobs, {'01' * 32})
        self.assertEqual(directory, self.result)
        with self.assertRaises(ValueError):
            P.phase_result(self.directory, self.workflow, self.binding, set())
        (self.result / 'node.6.0').write_bytes(b'an unexpected root')
        with self.assertRaisesRegex(ValueError, 'cannot contain a root'):
            self.check()

    def test_prefix_manifest_cannot_change_scope_workflow_inventory_or_original_deadline(self):
        original = copy.deepcopy(self.receipt)
        for field, value in [('preseal_only', False), ('pool_workflow', {}),
                             ('root_file', 'node.6.0'), ('completed_ms', 600000),
                             ('reused_proofs', 1), ('native_applied', True),
                             ('status', 'proved_cpu_audit_pending'), ('stable_nodes', [])]:
            self.receipt = copy.deepcopy(original)
            self.receipt[field] = value
            self.write()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check()
        for field, value in [('job', [3] * 32), ('job', [True] * 32),
                             ('level', 6), ('bytes', 33), ('level', 0)]:
            self.receipt = copy.deepcopy(original)
            self.receipt['stable_nodes'][0][field] = value
            self.write()
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.check()

    def test_recovered_prefix_counts_exact_original_jobs_and_rejects_duplicate_completion(self):
        self.records = []
        self.receipt.update(fresh_proofs=0, reused_proofs=1)
        self.write()
        complete, jobs, _ = P.phase_result(self.directory, self.workflow, self.binding, {'01' * 32}, prefix=True)
        self.assertTrue(complete)
        self.assertEqual(jobs, set())
        self.records = [{'job': '01' * 32, 'proof_bytes': 32}]
        self.receipt['fresh_proofs'] = 1
        self.write()
        with self.assertRaises(ValueError):
            P.phase_result(self.directory, self.workflow, self.binding, {'01' * 32}, prefix=True)

    def test_import_provenance_cannot_reset_workflow_or_hide_duplicate_jobs(self):
        self.write()
        P.S.check_prefix_workflows([self.result], self.workflow)
        with self.assertRaisesRegex(ValueError, 'original workflow'):
            P.S.check_prefix_workflows([self.result], self.workflow | {'started_monotonic_ms': 11})
        path = self.result.parent / 'execution-reused.json'
        records = [{'job': '01' * 32, 'cpu_reverified': True}]
        path.write_text(json.dumps(records))
        self.assertEqual(P.imported_jobs(self.directory, True), {'01' * 32})
        for invalid in [[], records * 2, [{'job': '01' * 32, 'cpu_reverified': False}]]:
            path.write_text(json.dumps(invalid))
            with self.assertRaises(ValueError):
                P.imported_jobs(self.directory, True)

    def test_phase_commands_preserve_intake_scope_and_cache_across_restarts(self):
        config = {'gpu_uuids': ['GPU-test'], 'pool_timing_approvals': {'GPU-test': '/approval.json'},
                  'gpu_binary': '/gpu', 'cpu_binary': '/cpu', 'host_config': '/native', 'host_journal': '/journal',
                  'count': 60, 'workload': '/workload', 'scratch': '/scratch',
                  'preseal_only': True, 'arrival_store': '/intake'}
        for previous in [None, Path('/previous')]:
            config['pool_prefix_handoff'] = True
            args = P.S.argument_parser().parse_args(P.command(config, '/fixture', '/requests', '/workflow', '/output', previous)[2:])
            self.assertTrue(args.preseal)
            self.assertTrue(args.pool_prefix_handoff)
            self.assertEqual(args.pool_workflow, Path('/workflow'))
            self.assertEqual(args.recover_owner, None if previous is None else Path('/previous/owner'))
            self.assertEqual(args.arrival_store, Path('/intake'))
            self.assertIsNone(args.arrival_selection)
            self.assertEqual(args.pool_runtime_seconds, 180)
        config.update(preseal_only=False, pool_prefix_handoff=False, count=64, arrival_selection='a' * 64, reuse_preseal=['/cache'])
        args = P.S.argument_parser().parse_args(P.command(config, '/fixture', '/requests', '/workflow', '/output', Path('/previous'))[2:])
        self.assertFalse(args.preseal)
        self.assertEqual(args.reuse_preseal, [Path('/cache')])
        self.assertEqual(args.arrival_selection, 'a' * 64)


if __name__ == '__main__':
    unittest.main()
