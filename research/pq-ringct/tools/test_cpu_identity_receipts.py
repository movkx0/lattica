"""CPU receipt mutations and retirement audits; synthetic records are not proofs."""
import copy
import unittest
import cpu_identity_receipts as audit
from test_identity_preprocessing_receipts import fixture as legacy_fixture, render


def operation(entry='block_v2_cpu_identity', cpu=True, elapsed=10):
    backend = 'cpu' if cpu else 'open_cl'
    return dict(schema='lattica-proving-stages-v1', entry_point=entry,
        policy='cpu_required' if cpu else 'gpu_required',
        capabilities=dict(scope='operation', profile='block_v2_cubic', max_log_fri_arity=1,
                          stages=[dict(stage='preprocessing', backend=backend)]),
        elapsed_ns=elapsed, succeeded=True, stage_coverage_complete=True, completion_rejected=False,
        observation_errors=0, components=[], observations=[dict(stage='preprocessing', backend=backend,
            calls=1, completed_calls=1, device_calls=0 if cpu else 1, inclusive_ns=elapsed, device_ns=0 if cpu else 1)])


def add_finalizations(events):
    result = []; totals = dict.fromkeys(audit.FIELDS, 0)
    for prefix, value in events:
        result.append((prefix, value))
        if prefix == 'proving_stage_report' and value.get('entry_point') == 'block_v2_preprocessing':
            result.append((prefix, operation()))
            totals['finalizations'] += 1; totals['finalization_ns'] += 10
    return result, totals


def fixture():
    original, _ = legacy_fixture(2, True, 16)
    events = []; totals = dict.fromkeys(audit.FIELDS, 0)
    for index, (prefix, value) in enumerate(original):
        if prefix == 'owned_identity_report':
            epoch = next(v['epoch']['identity_prefix'] for p, v in original[index + 1:] if p == 'owned_outer_epoch' and 'identity_prefix' in v['epoch'])
            jobs = [j for j in epoch['jobs'] if j is not None]; count = len(jobs)
            footprint = epoch['footprint']; footprint.update(managed_bytes=0, max_allocation_bytes=0)
            measured = dict.fromkeys(audit.FIELDS, 0)
            measured.update(batches=1, programs=count, elapsed_ns=110, analysis_ns=100, hash_wall_ns=9,
                            worker_elapsed_ns=count * 8, fields=count * 40, reserved_host_peak_bytes=footprint['host_bytes'])
            epoch['totals'] = measured
            for name in audit.FIELDS: totals[name] = max(totals[name], measured[name]) if name in audit.PEAKS else totals[name] + measured[name]
            value = dict(schema='identity-cpu-prefix-v1', batch=epoch['batch'], streams=count,
                         requested_workers=2, effective_workers=count, peak_active_workers=count,
                         analysis_ns=100, hash_wall_ns=9, worker_elapsed_ns=count * 8, fields=count * 40,
                         footprint=copy.deepcopy(footprint), analysis=operation('block_v2_identity_source_analysis', False, 101),
                         cpu=operation('block_v2_cpu_identity_prefixes'),
                         workers=[dict(job=j, fields=40, elapsed_ns=8) for j in jobs])
            prefix = 'owned_identity_cpu_report'
        if prefix == 'owned_outer_epoch':
            events += [('proving_stage_report', dict(entry_point='block_v2_preprocessing')),
                       ('proving_stage_report', operation()),
                       ('proving_stage_report', dict(entry_point='block_v2_registered_program'))]
            totals['finalizations'] += 1; totals['finalization_ns'] += 10
        events.append((prefix, value))
    return events, totals


class CpuIdentityTests(unittest.TestCase):
    def test_parallel_prefixes_and_tail_are_distinct_from_gpu_proofs(self):
        events, totals = fixture(); normalized, result = audit.reconcile(render(events), totals)
        self.assertEqual(result['tokens_consumed'], 3)
        self.assertEqual(result['max_streams'], 2)
        self.assertNotIn('cpu_identity', normalized)

    def test_prefix_receipt_mutations_fail_closed(self):
        for key, value in [('schema', 'old'), ('effective_workers', 1), ('peak_active_workers', 0),
                           ('worker_elapsed_ns', 1), ('fields', 1), ('requested_workers', 17)]:
            events, totals = fixture()
            next(v for p, v in events if p == 'owned_identity_cpu_report')[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): audit.reconcile(render(events), totals)

    def test_cpu_policy_missing_finalization_and_reuse_fail_closed(self):
        for mutation in ('policy', 'device', 'missing', 'reused', 'retirement', 'program'):
            events, totals = fixture()
            cpu_index = next(i for i, (p, v) in enumerate(events) if v.get('entry_point') == 'block_v2_cpu_identity')
            if mutation == 'policy': events[cpu_index][1]['policy'] = 'gpu_required'
            elif mutation == 'device': events[cpu_index][1]['observations'][0]['device_calls'] = 1
            elif mutation == 'missing': events.pop(cpu_index)
            elif mutation == 'reused': events.insert(cpu_index, copy.deepcopy(events[cpu_index]))
            else:
                epoch = next(v['epoch'] for p, v in events if p == 'owned_outer_epoch')
                if mutation == 'retirement': epoch['identity_prefix']['retirement']['lease_released'] = False
                else: epoch['identity_prefix_use']['job'] = 99
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): audit.reconcile(render(events), totals)
