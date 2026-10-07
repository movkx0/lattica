#!/usr/bin/env python3
"""Control-plane and accounting tests; mocked data is not proving evidence."""
import copy
import importlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from block_v2_pool_qualification import compare, research_profile

C = importlib.import_module('block-v2-pool-campaign')


class PoolContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        allocation = {'wallet_threads': 4, 'wallet_bytes': 4 << 30, 'coordinator_threads': 2,
                      'coordinator_bytes': 2 << 30, 'weights': {'GPU-a': 1, 'GPU-b': 1}}
        self.profile = self.root / 'workload.json'
        self.profile.write_text(json.dumps({'pool_allocation': allocation}))
        self.config = {'schema_version': 1, 'count': 4, 'max_roots': 2, 'min_roots': 2,
                       'min_duration_seconds': 0, 'max_wall_seconds': 7200,
                       'candidate_timeout_seconds': 1800, 'cycle_seconds': 0,
                       'wallet': {'participants': 4, 'threads': 4, 'ram_bytes': 4 << 30},
                       'mode': 'exploratory', 'arrival_mode': 'saturated', 'workload': str(self.profile),
                       'host_config': str(self.profile), 'cpu_binary': str(self.profile),
                       'gpu_binary': str(self.profile), 'library': str(self.profile)}

    def test_wallet_budget_and_qualification_cannot_be_bypassed(self):
        C.validate(self.config)
        for update in ({'wallet': {'participants': 4, 'threads': 8, 'ram_bytes': 4 << 30}},
                       {'mode': 'qualifying'}, {'count': 512}, {'max_roots': True},
                       {'arrival_mode': 'fixed_rate', 'arrival_interval_ms': 0}):
            with self.assertRaises((ValueError, KeyError)):
                C.validate(self.config | update)

    def test_only_applied_users_count_and_startup_failure_remains_visible(self):
        events = C.Events(self.root, self.config, '0' * 64)
        ids = [str(i) * 64 for i in range(1, 5)]
        for tid, kind in zip(ids, C.KINDS):
            events.emit('submitted', transaction_id=tid, transaction_kind=kind)
            events.emit('wallet_proof_ready', transaction_id=tid)
            events.emit('admitted', transaction_id=tid)
        events.emit('sealed', block_id='5' * 64, transaction_ids=ids)
        events.emit('root_verified', block_id='5' * 64, cpu_audited=True, expected_statement_verified=True,
                    level=6, proof_bytes='100', proof_sha256='6' * 64, profile_sha256='7' * 64)
        events.emit('failed', reason='test: native commit rejected')
        report = events.close()
        self.assertEqual(report['unique_user_transactions_retained_at_end'], 0)
        self.assertEqual(report['issuance_transactions'], 0)
        self.assertEqual(report['failures'], 1)
        self.assertEqual(len((self.root / 'events.jsonl').read_text().splitlines()), 16)

    def test_atomic_request_publication(self):
        target = self.root / 'request.json'
        C.publish(target, {'schema_version': 1, 'deadline_ms': 100})
        self.assertEqual(json.loads(target.read_text())['deadline_ms'], 100)
        self.assertFalse(list(self.root.glob('*.tmp-*')))

    def test_comparison_requires_five_alternating_pairs_and_delivery(self):
        def run(rate):
            return {'status': 'succeeded', 'post_seal_deadline_misses': 0, 'resource_failures': 0,
                    'comparison_contract': {'count': 64, 'resources': 'fixed'},
                    'accounting': {'status': 'complete', 'failures': 0, 'user_transactions_per_minute': rate}}
        pairs = [{'order': ['control', 'candidate'] if i % 2 == 0 else ['candidate', 'control'],
                  'match_id': f'pair-{i}', 'control': run(1), 'candidate': run(1.1)} for i in range(5)]
        for i, pair in enumerate(pairs):
            for j, name in enumerate(pair['order']):
                start = (2 * i + j) * 100 + 1
                pair[name]['capture'] = {'run_id': f'run-{start}', 'boot_id': 'same-boot',
                    'started_monotonic_ns': start, 'finished_monotonic_ns': start + 90}
        self.assertTrue(compare(pairs)['eligible_for_performance_promotion'])
        for capture_change in ({'run_id': 'run-1'}, {'started_monotonic_ns': 1}, {'boot_id': 'different'}):
            bad = copy.deepcopy(pairs)
            bad[4]['candidate']['capture'].update(capture_change)
            with self.assertRaises(ValueError):
                compare(bad)
        bad = copy.deepcopy(pairs)
        bad[4]['match_id'] = bad[0]['match_id']
        with self.assertRaises(ValueError):
            compare(bad)
        with self.assertRaises(ValueError):
            compare(pairs[:4])
        pairs[1]['candidate']['post_seal_deadline_misses'] = 1
        self.assertFalse(compare(pairs)['eligible_for_performance_promotion'])
        pairs[1]['candidate']['comparison_contract']['count'] = 32
        with self.assertRaises(ValueError):
            compare(pairs)

    def test_cleanup_observes_worker_units_and_continues_after_failed_stop(self):
        supervisor = importlib.import_module('block_v2_supervisor')
        bootstrap = importlib.import_module('block_v2_coordinator_bootstrap')
        owner, worker = 'lattica-v2-multi-owner-' + 'a' * 64 + '.service', 'lattica-v2-multi-persistent-' + 'b' * 64 + '.service'
        owned = {'owner_unit': owner, 'workers': [{'budget': {'unit': worker}}]}
        absent = {'LoadState': 'not-found', 'ActiveState': 'inactive', 'MainPID': 0,
                  'ControlPID': 0, 'Job': '', 'ControlGroup': ''}
        with (patch.object(supervisor, 'observe', return_value=absent) as observe,
              patch.object(bootstrap, 'observation', side_effect=AssertionError('coordinator-only observer')),
              patch.object(C.subprocess, 'run') as stop):
            C.reconcile_services(owned)
            self.assertEqual([c.args[0] for c in observe.call_args_list], [owner, owner, worker, worker])
            stop.assert_not_called()
        with (patch.object(supervisor, 'observe', return_value=dict(absent, LoadState='loaded')),
              patch.object(C.subprocess, 'run', side_effect=[RuntimeError('owner stop failed'), None]) as stop):
            with self.assertRaisesRegex(RuntimeError, 'owner stop failed'):
                C.reconcile_services(owned)
            self.assertEqual(stop.call_count, 2)

    def test_research_proposal_is_separate_and_never_activates_execution(self):
        proposed = research_profile(512, 180, 4)
        self.assertEqual(proposed['proposal']['tree_depth'], 9)
        self.assertEqual(proposed['accepted_count_range'], [1, 512])
        self.assertIn(513, proposed['boundary_counts'])
        self.assertFalse(proposed['execution_enabled'])
        self.assertFalse(proposed['ceiling_is_measured_throughput'])
        for values in ((4096, 180, 4), (512, 0, 4), (512, 180, 512)):
            with self.assertRaises(ValueError):
                research_profile(*values)


if __name__ == '__main__':
    unittest.main()
