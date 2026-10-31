"""Prefix evidence is distinct from proof acceptance; mutations must fail closed."""
import copy
import json
import unittest
from identity_preprocessing_receipts import reconcile, FIELDS, PEAKS


def fixture():
    events = []
    source = [9] * 32
    def binding(kind, ordinal):
        return dict(kind=kind, ordinal=ordinal, source_fingerprint=source.copy(),
                    compiled_source_fingerprint=[4] * 32)
    for node, step in [(4, 11), (5, 15), (7, 21)]:
        for output, kind, ordinal in [('Compiled', 'GroupCompile', step - 2), ('Outer', 'OuterProve', step)]:
            events.append(('owned_dispatch_verification', dict(stage='inventory', identity=dict(
                route={'Crypto': dict(family='Shake', output={output: node})},
                binding=binding(kind, ordinal)))))
    totals = dict.fromkeys(FIELDS, 0)
    for batch, jobs, steps in [(0, [0, 1], [11, 15]), (1, [3], [21])]:
        measured = dict(batches=1, programs=len(jobs), elapsed_ns=1000, analysis_ns=100,
                        hash_wall_ns=500, hash_device_ns=400, fields=100,
                        uploaded_bytes=256, downloaded_bytes=128,
                        reserved_host_peak_bytes=1 << 30, reserved_managed_peak_bytes=1 << 20)
        for key in FIELDS:
            totals[key] = max(totals[key], measured[key]) if key in PEAKS else totals[key] + measured[key]
        events.append(('owned_identity_report', dict(schema='lattica-proving-stages-v1',
            entry_point='block_v2_identity_prefix_batch', policy='gpu_required',
            capabilities=dict(scope='operation', profile='block_v2_cubic', max_log_fri_arity=1,
                              stages=[dict(stage='preprocessing', backend='open_cl')]),
            elapsed_ns=1000, succeeded=True, stage_coverage_complete=True,
            completion_rejected=False, observation_errors=0, components=[],
            observations=[dict(stage='preprocessing', backend='open_cl', calls=4, completed_calls=4,
                               device_calls=4, inclusive_ns=0, device_ns=450)])))
        for index, (job, step) in enumerate(zip(jobs, steps)):
            epoch = dict(startup={}, retirement={}, independent_verification_complete=True,
                         cpu_verification_ns=10, identity_prefix_use=dict(batch=batch, job=job))
            if index == 0:
                epoch['identity_prefix'] = dict(batch=batch, jobs=jobs + [None] * (16 - len(jobs)),
                    startup=dict(elapsed_ns=10, succeeded=True, retained_tree_host_bytes=8 << 30),
                    retirement=dict(managed_live_bytes=0, host_tree_live_bytes=0,
                                    managed_peak_bytes=1 << 20, lease_released=True), totals=measured)
            events.append(('owned_outer_epoch', dict(schema='ringct-owned-outer-epoch-v2',
                ordinal=step, binding=binding('OuterProve', step), epoch=epoch)))
    return events, totals


def render(events):
    return '\n'.join(prefix + ' ' + json.dumps(value) for prefix, value in events)


class IdentityReceiptTests(unittest.TestCase):
    def test_pairs_odd_tail_and_separate_fresh_work_are_reconciled(self):
        events, totals = fixture()
        content, audit = reconcile(render(events), totals)
        self.assertEqual(audit['tokens_consumed'], 3)
        self.assertEqual(audit['max_streams'], 2)
        self.assertNotIn('identity_prefix', content)
        self.assertNotIn('owned_identity_report', content)

    def test_wrong_source_reuse_missing_leaf_and_unretired_epoch_fail(self):
        mutations = [
            lambda e: e[-1][1]['binding']['source_fingerprint'].__setitem__(0, 8),
            lambda e: e[-1][1]['epoch']['identity_prefix_use'].update(job=0),
            lambda e: e.pop(),
            lambda e: e[7][1]['epoch']['identity_prefix']['retirement'].update(lease_released=False),
            lambda e: e[7][1]['epoch']['identity_prefix']['jobs'].__setitem__(1, 0),
            lambda e: e[6][1]['observations'][0].update(backend='cpu'),
            lambda e: e[6][1].update(stage_coverage_complete=False),
            lambda e: e[6][1].update(observation_errors=False),
            lambda e: e[6][1]['capabilities'].update(max_log_fri_arity=True),
            lambda e: e[7][1]['epoch']['identity_prefix']['totals'].update(hash_device_ns=451),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                events, totals = fixture()
                mutation(events)
                with self.assertRaises(ValueError):
                    reconcile(render(events), totals)

    def test_serial_cannot_claim_prefix_work_or_accept_modified_snapshot(self):
        events, totals = fixture()
        with self.assertRaises(ValueError):
            reconcile(render(events), None)
        for key in FIELDS:
            changed = copy.deepcopy(totals)
            changed[key] += 1
            with self.assertRaises(ValueError):
                reconcile(render(events), changed)
            changed[key] = float(totals[key])
            with self.assertRaises(ValueError):
                reconcile(render(events), changed)


if __name__ == '__main__':
    unittest.main()
