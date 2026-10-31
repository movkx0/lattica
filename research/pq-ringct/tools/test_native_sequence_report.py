"""Regression checks for receipt coverage and partial-workflow overclaims."""
import copy
import json
from pathlib import Path
import unittest

import native_sequence_report as audit


def fixture(shape):
    native, setup, proof = json.loads(Path(__file__).with_name('fixtures')
        .joinpath('native-sequence-stage-reports.json').read_text())
    natives = audit.SHAPES[shape][2]
    groups = natives - 1
    events = [('preissued', dict(shape=shape, native_proofs_expected=natives,
        recursive_proofs_expected=groups, all_source_bounds_complete=True,
        original_phase_owners_live=True, native_dispatch_started=False,
        host_bytes=32 * audit.GIB, device_bytes=8 * audit.GIB))]
    if groups == 2:
        events.append(('handoff_refusal', dict(shape=shape, previous_index=0, refused_next_index=2,
                complete_owners_returned=True, ledger_snapshot_unchanged=True,
                proof_dispatch_attempted=False)))
    for _ in range(natives):
        events.append(('receipt', copy.deepcopy(native)))
    for _ in range(groups):
        events.extend([('receipt', copy.deepcopy(setup)), ('receipt', copy.deepcopy(proof))])
    for ordinal in range(groups):
        events.append(('group', dict(shape=shape, ordinal=ordinal, active_rows=100, padded_rows=128,
            compiler_ns=10, setup_ns=setup['elapsed_ns'], proving_ns=proof['elapsed_ns'],
            cpu_verification_ns=10, independent_cpu_verified=True, mutation_rejections=2)))
    component = sum(value['elapsed_ns'] for name, value in events if name == 'receipt') + 1000
    events.extend([('complete', dict(shape=shape, native_proofs=natives, recursive_proofs=groups,
        mutation_rejections=groups * 2, source_preissue_ns=10, component_including_mutations_ns=component,
        fresh_gpu_required=True, compiler_backend='cpu', public_endpoint_preprocessing='cpu',
        original_startup_pcs_reused=True, native_successor_and_attachment_snapshots_unchanged=True,
        skipped_predecessor_handoff_refusals=groups - 1, second_outer_dispatched=groups == 2,
        request_aggregate_proofs=0, complete_ringct_workflow=False)),
        ('terminal', dict(shape=shape, original_quota_released=True, complete_ringct_workflow=False))])
    return events


def encode(events):
    lines = []
    for name, value in events:
        if name == 'receipt':
            lines.append('proving_stage_report ' + json.dumps(value))
        else:
            lines.append('ringct_native_sequence_' + name + ' ' + ' '.join(
                key + '=' + (str(item).lower() if type(item) is bool else str(item))
                for key, item in value.items()))
    return '\n'.join(lines + ['test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 462 filtered out; finished in 45.00s'])


class SequenceAuditTests(unittest.TestCase):
    def rejects(self, shape, transform):
        events = fixture(shape)
        transform(events)
        with self.assertRaises(ValueError):
            audit.audit_log(encode(events), shape)

    def test_pair_and_odd_tail(self):
        for shape, count in [('pair', 4), ('pair-and-tail', 7)]:
            with self.subTest(shape=shape):
                self.assertEqual(audit.audit_log(encode(fixture(shape)), shape)['stage_receipts'], count)

    def test_missing_duplicate_and_reordered_receipts(self):
        self.rejects('pair', lambda e: e.pop(1))
        self.rejects('pair', lambda e: e.insert(1, e[1]))
        self.rejects('pair', lambda e: e.__setitem__(slice(1, 4), list(reversed(e[1:4]))))

    def test_cpu_and_missing_completed_calls(self):
        self.rejects('pair', lambda e: e[1][1].update(policy='cpu_allowed'))
        self.rejects('pair', lambda e: e[1][1]['observations'][0].update(device_calls=0))
        self.rejects('pair', lambda e: e[1][1]['observations'][0].update(completed_calls=0))

    def test_device_event_time_must_be_recorded(self):
        self.rejects('pair', lambda e: e[1][1]['observations'][0].pop('device_ns'))
        for value in (0, -1, True, None, '100', 1 << 128):
            with self.subTest(value=value):
                self.rejects('pair', lambda e: e[1][1]['observations'][0].update(device_ns=value))

    def test_inclusive_time_is_nonnegative_without_inventing_wall_time(self):
        events = fixture('pair')
        events[1][1]['observations'][0]['inclusive_ns'] = 0
        audit.audit_log(encode(events), 'pair')
        self.rejects('pair', lambda e: e[1][1]['observations'][0].pop('inclusive_ns'))
        for value in (-1, True, None, '100', 1 << 128):
            with self.subTest(value=value):
                self.rejects('pair', lambda e: e[1][1]['observations'][0].update(inclusive_ns=value))

    def test_shortened_stage_contract(self):
        def shorten(events):
            receipt = events[1][1]
            receipt['capabilities']['stages'] = [s for s in receipt['capabilities']['stages'] if s['stage'] != 'grinding']
            receipt['observations'] = [s for s in receipt['observations'] if s['stage'] != 'grinding']
        self.rejects('pair', shorten)

    def test_provenance_refusal_and_cleanup(self):
        self.rejects('pair-and-tail', lambda e: e[1][1].update(ledger_snapshot_unchanged=False))
        self.rejects('pair', lambda e: e[-1][1].update(original_quota_released=False))
        self.rejects('pair', lambda e: e[0][1].update(host_bytes=33 * audit.GIB))

    def test_wrong_shape_and_coverage(self):
        with self.assertRaises(ValueError):
            audit.audit_log(encode(fixture('pair')), 'pair-and-tail')
        self.rejects('pair-and-tail', lambda e: e[-3][1].update(ordinal=0))
        self.rejects('pair', lambda e: e[-3][1].update(padded_rows=129))

    def test_disallowed_full_workflow_claim(self):
        self.rejects('pair', lambda e: e[-2][1].update(complete_ringct_workflow=True))
        self.rejects('pair', lambda e: e[-2][1].update(request_aggregate_proofs=1))

    def test_timing_must_match_receipts_and_enclose_stages(self):
        self.rejects('pair', lambda e: e[-3][1].update(setup_ns=1))
        self.rejects('pair', lambda e: e[-2][1].update(component_including_mutations_ns=1))

    def test_duplicate_json_and_marker_fields(self):
        with self.assertRaises(ValueError):
            audit.decode('{"succeeded":true,"succeeded":false}')
        with self.assertRaises(ValueError):
            audit.fields('shape=pair shape=pair-and-tail')

    def test_boolean_integer_aliases_refuse(self):
        self.rejects('pair', lambda e: e[-2][1].update(recursive_proofs=True))
        self.rejects('pair', lambda e: e[-1][1].update(original_quota_released=1))


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads(Path(__file__).with_name('fixtures')
            .joinpath('native-sequence-guard-binding.json').read_text())

    def check_build(self):
        calls = []
        audit.check_build(self.fixture['build'], self.fixture['run'],
            lambda build: calls.append(build), lambda path: self.fixture['build']['raw_log_sha256'])
        self.assertEqual(calls, [self.fixture['build']])

    def check_service(self):
        run = self.fixture['run']
        root = Path(self.fixture['root'])
        audit.check_service(run, root, root / '.tools/pq-opencl-opt/runs' / (run['label'] + '.json'),
            run['command'], run['environment'], run['memory_max_bytes'] // audit.GIB,
            run['memory_high_bytes'] // audit.GIB)

    def test_exact_build_and_service_binding(self):
        self.check_build()
        self.check_service()

    def test_failed_build_terminal_propagates(self):
        def failed(build):
            raise ValueError('build did not retire')
        with self.assertRaises(ValueError):
            audit.check_build(self.fixture['build'], self.fixture['run'], failed, lambda path: '')

    def test_build_log_features_and_chronology(self):
        with self.assertRaises(ValueError):
            audit.check_build(self.fixture['build'], self.fixture['run'], lambda build: None, lambda path: 'wrong')
        original = copy.deepcopy(self.fixture)
        for field, value in [('command', ['cargo', 'build']),
            ('finished_utc', self.fixture['run']['finished_utc']),
            ('input_sha256', {'changed': '1' * 64})]:
            self.fixture = copy.deepcopy(original)
            self.fixture['build'][field] = value
            with self.assertRaises(ValueError):
                self.check_build()

    def test_service_swap_and_execution_binding(self):
        original = copy.deepcopy(self.fixture)
        for source, target in [('--property=MemorySwapMax=0', '--property=MemorySwapMax=1024'),
                               ('--test-threads=1', '--test-threads=2'), ('-i', '--ignore-environment-wrong')]:
            self.fixture = copy.deepcopy(original)
            service = self.fixture['run']['service_command']
            service[service.index(source)] = target
            with self.assertRaises(ValueError):
                self.check_service()

    def test_service_duplicate_property(self):
        service = self.fixture['run']['service_command']
        service.insert(4, '--property=MemorySwapMax=0')
        with self.assertRaises(ValueError):
            self.check_service()


if __name__ == '__main__':
    unittest.main()
