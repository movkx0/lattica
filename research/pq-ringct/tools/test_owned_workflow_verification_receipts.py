"""Synthetic strict receipt predicates, never proof or closure qualification."""
import copy
import json
import unittest

from opencl_private_spend_validate import collect_gpu_receipts
from owned_workflow_case_receipts import validate
from test_owned_workflow_case_receipts import fixture, render, FAMILIES


def enrich(events, report):
    """Attach synthetic exact identities to the existing transport fixture."""
    events, report = copy.deepcopy(events), copy.deepcopy(report)
    groups, prelude, index = [], [], 0
    entry_family = {'ringct_owned_native_' + suffix: family for family, suffix in (
        ('Source', 'graph_source'), ('Uniform', 'uniform'), ('Sparse', 'sparse'),
        ('Transcript', 'transcript'), ('Affine', 'affine'), ('Ntt', 'ntt'), ('Mul', 'mul'),
        ('GBound', 'g_bound'), ('Permutation', 'permutation'), ('LinearMap', 'linear_map'))}
    native_entries = {entry for _, entry in FAMILIES}
    while index < len(events):
        prefix, value = events[index]
        entry = value.get('entry_point')
        if entry in native_entries:
            records = events[index:index + 3]
            if entry in entry_family:
                family = entry_family[entry]
                route = {'Native': {'family': family, 'ordinal': 0}}
                kind, ordinal = family + 'Native', 0
                source_kind = ('source-kind-index' if family == 'Source' else 'auxiliary-request'
                    if family in ('Uniform', 'Sparse', 'Transcript') else 'algebra-batch')
            else:
                family = 'Aes' if entry.endswith('_aes') else 'Shake'
                route = {'Crypto': {'family': family, 'request': 0, 'step': 1, 'output': {'Native': 0}}}
                kind, ordinal, source_kind = 'Native', 1, 'crypto-request'
            first, covered, member, source = 0, 1, 0, 0
        elif prefix == 'owned_group_report':
            records = events[index:index + 2]
            route = {'Crypto': {'family': 'Shake', 'request': 0, 'step': 2, 'output': {'Compiled': 0}}}
            kind, ordinal, source_kind = 'GroupCompile', 2, 'crypto-request'
            first, covered, member, source = 0, 1, 0, 0
        elif prefix == 'owned_final_compile_report':
            records = events[index:index + 3]
            stage = records[-1][1]
            ordinal, merge = stage['ordinal'], stage['report']['merge']
            route = {'Final': {'step': ordinal, 'output': {'Compiled': merge}}}
            kind, source_kind = 'FinalCompile', 'ordered-merge'
            first, covered = stage['report']['first'], stage['report']['count']
            member, source = None, merge
        elif entry == 'block_v2_preprocessing':
            records = events[index:index + 4]
            if index + 4 < len(events) and events[index + 4][0] == 'owned_final_stage':
                records.append(events[index + 4])
                stage = records[-1][1]
                ordinal, merge = stage['ordinal'], stage['report']['merge']
                route = {'Final': {'step': ordinal, 'output': {'Outer': merge}}}
                kind, source_kind = 'FinalOuter', 'ordered-merge'
                first, covered = stage['report']['first'], stage['report']['count']
                member, source = None, merge
            else:
                route = {'Crypto': {'family': 'Shake', 'request': 0, 'step': 3, 'output': {'Outer': 0}}}
                kind, ordinal, source_kind = 'OuterProve', 3, 'crypto-request'
                first, covered, member, source = 0, 1, 0, 0
        elif prefix == 'owned_final_stage' and value['stage'] == 'verify':
            records = [events[index]]
            ordinal = value['ordinal']
            route = {'Final': {'step': ordinal, 'output': 'Verified'}}
            kind, source_kind = 'FinalVerify', 'ordered-merge'
            first, covered, member, source = 0, report['transactions'], None, None
        else:
            assert not groups, 'synthetic fixture group recognition failed'
            prelude.append(events[index])
            index += 1
            continue
        identity = {'closed_ordinal': len(groups), 'expected_steps': 0,
            'transactions': report['transactions'], 'route': route,
            'binding': {'kind': kind, 'ordinal': ordinal,
                'source_fingerprint': [len(groups) + 1] * 32,
                'compiled_source_fingerprint': report['final_qualification']['compiled_source_fingerprint']},
            'workflow_source_fingerprint': [31] * 32, 'member': member,
            'member_first': first, 'member_count': covered,
            'source_kind': source_kind, 'source_ordinal': source}
        for name, record in records:
            if name.endswith('_epoch'):
                record['ordinal'] = ordinal
                if 'independent_verification_complete' in record['epoch']:
                    record['schema'] = record['schema'][:-2] + 'v2'
                    record['binding'] = copy.deepcopy(identity['binding'])
                    if name == 'owned_outer_epoch':
                        record['epoch']['cpu_verification_ns'] = (
                            records[-1][1]['report']['cpu_verification_ns'] if kind == 'FinalOuter' else 500)
        groups.append((identity, records))
        index += len(records)
    report['completed_phases'] = len(groups)
    def receipt(stage, identity):
        return ['owned_dispatch_verification', {'schema': 'ringct-owned-dispatch-verification-v1',
            'stage': stage, 'session_id': report['owned_observations']['session_id'],
            'identity': copy.deepcopy(identity)}]
    for identity, _ in groups:
        identity['expected_steps'] = len(groups)
    result = prelude + [receipt('inventory', identity) for identity, _ in groups]
    for identity, records in groups:
        result.append(receipt('attempt', identity))
        result.extend(records)
        result.append(receipt('complete', identity))
    return result, report


def graph_route_fixture(events, report, route_name, family=None):
    """Exercise graph wire shapes; this is not a valid source-closure model."""
    events, report = copy.deepcopy(events), copy.deepcopy(report)
    prelude, groups, active = [], [], None
    for prefix, value in events:
        if prefix == 'owned_dispatch_verification':
            if value['stage'] == 'attempt':
                active = (value['identity'], [])
            elif value['stage'] == 'complete':
                groups.append(active)
                active = None
        elif active is not None:
            active[1].append([prefix, value])
        else:
            prelude.append([prefix, value])
    selected = next(i for i, (identity, _) in enumerate(groups)
                    if 'Crypto' in identity['route'] and 'Outer' in identity['route']['Crypto']['output'])
    original, records = groups[selected]
    compile_identity, outer_identity = copy.deepcopy(original), copy.deepcopy(original)
    base_route = {'ordinal': 0}
    if family is not None:
        base_route['family'] = family
    if route_name == 'Parent':
        base_route['level'] = 2
    compile_identity['route'] = {route_name: dict(base_route, phase='Compile')}
    outer_identity['route'] = {route_name: dict(base_route, phase='Outer')}
    kind = {'Fixed': 'SourceCompile', 'Direct': 'GraphLeafCompile', 'Parent': 'GraphParentCompile',
            'Leaf': 'SourceNativeCompile' if family == 'Source' else 'AlgebraCompile'}[route_name]
    source_kind = {'Fixed': 'fixed-source', 'Direct': 'graph-leaf', 'Parent': 'parent-route',
                   'Leaf': 'source-kind-index' if family == 'Source' else 'algebra-batch'}[route_name]
    for identity in (compile_identity, outer_identity):
        identity['source_kind'] = source_kind
        identity['source_ordinal'] = None if route_name == 'Parent' else 0
    compile_identity['binding'].update(kind=kind, ordinal=0, source_fingerprint=[99] * 32)
    outer_identity['binding'].update(kind='GraphOuter', ordinal=int(route_name in ('Parent', 'Direct')))
    for prefix, value in records:
        if prefix == 'owned_outer_epoch':
            value.update(binding=copy.deepcopy(outer_identity['binding']),
                         ordinal=outer_identity['binding']['ordinal'])
    groups[selected:selected + 1] = [(compile_identity, []), (outer_identity, records)]
    report['completed_phases'] = len(groups)
    for ordinal, (identity, _) in enumerate(groups):
        identity.update(closed_ordinal=ordinal, expected_steps=len(groups))
    def receipt(stage, identity):
        return ['owned_dispatch_verification', {'schema': 'ringct-owned-dispatch-verification-v1',
            'stage': stage, 'session_id': report['owned_observations']['session_id'],
            'identity': copy.deepcopy(identity)}]
    events = prelude + [receipt('inventory', identity) for identity, _ in groups]
    for identity, records in groups:
        events.append(receipt('attempt', identity))
        events.extend(records)
        events.append(receipt('complete', identity))
    return events, report


class ExactVerificationReceiptTests(unittest.TestCase):
    def fixture(self, count=3):
        return enrich(*fixture(count))

    def audit(self, events, report):
        return validate(render(events), report, collect_gpu_receipts,
                        verification_mode='exact-dispatch-v1')['cpu_verification']

    @staticmethod
    def dispatch_index(events, stage):
        return next(i for i, (prefix, value) in enumerate(events)
                    if prefix == 'owned_dispatch_verification' and value['stage'] == stage)

    def test_n3_n4_all_proof_timings_and_identity_coverage(self):
        for count in (3, 4):
            events, report = self.fixture(count)
            audit = self.audit(events, report)
            self.assertEqual(audit['coverage'], 'exact-dispatch-v1')
            self.assertEqual(audit['completed_steps'], report['completed_phases'])
            self.assertTrue(audit['exact_dispatch_identity_coverage_complete'])
            self.assertTrue(audit['source_member_request_identity_authenticated'])
            self.assertEqual(audit['recursive_proofs_with_cpu_timing'], count)
            self.assertEqual(audit['recursive_proofs_without_cpu_timing'], 0)
            self.assertEqual(audit['native_cpu_verification_ns'], 12 * 300)
            self.assertEqual(audit['recursive_cpu_verification_ns'], 500 + 100 * (count - 1))
            self.assertEqual(audit['complete_cpu_verification_ns'], 12 * 300 + 500 + 200 * (count - 1) + 1000)
            self.assertTrue(audit['final_outer_timing_counted_once'])
            self.assertFalse(audit['inventory_used_as_completion'])
            self.assertEqual(audit['artifact_mutation_qualification_scope'], 'final-aggregate')

    def test_inventory_never_qualifies_completion(self):
        events, report = self.fixture()
        events = events[:self.dispatch_index(events, 'attempt')]
        with self.assertRaises(ValueError):
            self.audit(events, report)

    def test_all_graph_route_shapes_and_empty_compile_completions(self):
        shapes = [('Fixed', None), ('Parent', None)]
        shapes += [('Leaf', family) for family in ('Source', 'Affine', 'Ntt', 'Mul', 'GBound', 'Permutation', 'LinearMap')]
        shapes += [('Direct', family) for family in ('Parameters', 'Auxiliary', 'Equality')]
        for route_name, family in shapes:
            events, report = graph_route_fixture(*self.fixture(), route_name, family)
            with self.subTest(route=route_name, family=family):
                audit = self.audit(events, report)
                self.assertEqual(audit['completed_steps'], report['completed_phases'])
                key = route_name + ('.' + family if family else '') + '.outer'
                self.assertEqual(audit['by_dispatch_family'][key], {'proofs': 1, 'cpu_verification_ns': 500})
                compile_index = next(i for i, (prefix, value) in enumerate(events)
                    if prefix == 'owned_dispatch_verification' and value['stage'] == 'attempt'
                    and route_name in value['identity']['route']
                    and value['identity']['route'][route_name]['phase'] == 'Compile')
                self.assertEqual(events[compile_index + 1][1]['stage'], 'complete')
                # A copied native epoch cannot be credited to a nonproof compile.
                extra = next(copy.deepcopy(event) for event in events if event[0] == 'owned_native_epoch')
                events.insert(compile_index + 1, extra)
                with self.assertRaises(ValueError):
                    self.audit(events, report)

    def test_parent_level_and_ordinary_compile_completion_are_bound(self):
        events, report = graph_route_fixture(*self.fixture(), 'Parent')
        complete = next(value for prefix, value in events if prefix == 'owned_dispatch_verification'
            and value['stage'] == 'complete' and 'Parent' in value['identity']['route'])
        complete['identity']['route']['Parent']['level'] += 1
        with self.assertRaises(ValueError):
            self.audit(events, report)
        events, report = graph_route_fixture(*self.fixture(), 'Fixed')
        missing = next(i for i, (prefix, value) in enumerate(events) if prefix == 'owned_dispatch_verification'
            and value['stage'] == 'complete' and 'Fixed' in value['identity']['route']
            and value['identity']['route']['Fixed']['phase'] == 'Compile')
        del events[missing]
        with self.assertRaises(ValueError):
            self.audit(events, report)

    def test_each_dispatch_stage_rejects_missing_duplicate_and_reordered_records(self):
        for stage in ('inventory', 'attempt', 'complete'):
            for mutation in ('missing', 'duplicate', 'reordered'):
                events, report = self.fixture()
                i = self.dispatch_index(events, stage)
                if mutation == 'missing':
                    del events[i]
                elif mutation == 'duplicate':
                    events.insert(i, copy.deepcopy(events[i]))
                else:
                    events[i], events[i + 1] = events[i + 1], events[i]
                with self.subTest(stage=stage, mutation=mutation), self.assertRaises(ValueError):
                    self.audit(events, report)

    def test_source_member_request_and_phase_substitution_fail(self):
        mutations = (
            lambda i: i.update(closed_ordinal=1),
            lambda i: i.update(member=1, member_first=1),
            lambda i: i.update(source_ordinal=1),
            lambda i: i['binding'].update(ordinal=1),
            lambda i: i['binding'].update(source_fingerprint=[99] * 32),
            lambda i: i['binding'].update(compiled_source_fingerprint=[99] * 32),
            lambda i: i.update(workflow_source_fingerprint=[99] * 32),
            lambda i: i['route']['Native'].update(family='Uniform'),
        )
        for stage in ('inventory', 'attempt', 'complete'):
            for mutation in mutations:
                events, report = self.fixture()
                mutation(events[self.dispatch_index(events, stage)][1]['identity'])
                with self.subTest(stage=stage, mutation=mutation), self.assertRaises(ValueError):
                    self.audit(events, report)
        events, report = self.fixture()
        record = next(value for prefix, value in events if prefix == 'owned_dispatch_verification'
                      and value['stage'] == 'complete' and 'Crypto' in value['identity']['route'])
        record['identity']['route']['Crypto']['request'] += 1
        with self.assertRaises(ValueError):
            self.audit(events, report)

    def test_v2_epoch_binding_and_cpu_duration_are_required(self):
        mutations = (
            lambda r: r['binding'].update(source_fingerprint=[55] * 32),
            lambda r: r['binding'].update(ordinal=False),
            lambda r: r['binding']['source_fingerprint'].__setitem__(0, True),
            lambda r: r['epoch'].update(cpu_verification_ns=None),
            lambda r: r['epoch'].update(cpu_verification_ns=False),
            lambda r: r['epoch'].update(cpu_verification_ns=-1),
            lambda r: r['epoch'].update(independent_verification_complete=False),
            lambda r: r.update(schema=r['schema'][:-2] + 'v1'),
        )
        for prefix in ('owned_source_native_epoch', 'owned_outer_epoch'):
            for mutation in mutations:
                events, report = self.fixture()
                record = next(value for name, value in events if name == prefix)
                mutation(record)
                with self.subTest(prefix=prefix, mutation=mutation), self.assertRaises(ValueError):
                    self.audit(events, report)

    def test_final_outer_duplicate_cpu_value_must_match_but_is_counted_once(self):
        events, report = self.fixture()
        record = next(value for prefix, value in events if prefix == 'owned_outer_epoch'
                      and value['binding']['kind'] == 'FinalOuter')
        record['epoch']['cpu_verification_ns'] += 1
        with self.assertRaises(ValueError):
            self.audit(events, report)

    def test_partial_format_does_not_silently_fall_back(self):
        events, report = fixture()
        report['completed_phases'] = 19
        with self.assertRaises(ValueError):
            self.audit(events, report)
        with self.assertRaises(ValueError):
            validate(render(events), report, collect_gpu_receipts, verification_mode='unknown')

    def test_epoch_cannot_move_outside_its_attempt(self):
        events, report = self.fixture()
        i = next(i for i, (prefix, _) in enumerate(events) if prefix == 'owned_source_native_epoch')
        epoch = events.pop(i)
        events.insert(self.dispatch_index(events, 'attempt'), epoch)
        with self.assertRaises(ValueError):
            self.audit(events, report)

    def test_wrong_session_missing_final_completion_and_extra_proofs_fail(self):
        events, report = self.fixture()
        events[self.dispatch_index(events, 'complete')][1]['session_id'] = report['generation_session_id']
        with self.assertRaises(ValueError):
            self.audit(events, report)
        events, report = self.fixture()
        with self.assertRaises(ValueError):
            self.audit(events[:-1], report)
        events, report = self.fixture()
        record = next(copy.deepcopy(event) for event in events if event[0] == 'owned_native_epoch')
        events.append(record)
        with self.assertRaises(ValueError):
            self.audit(events, report)

    def test_extra_v2_epoch_under_unknown_prefix_fails(self):
        events, report = self.fixture()
        epoch = next(copy.deepcopy(value) for prefix, value in events if prefix == 'owned_outer_epoch')
        events.append(['unrelated_prefix', epoch])
        with self.assertRaises(ValueError):
            self.audit(events, report)

    def test_mislabelled_future_receipt_versions_fail(self):
        for schema in ('ringct-owned-dispatch-verification-v2',
                       'ringct-owned-final-stage-v2', 'ringct-owned-outer-epoch-v3'):
            events, report = self.fixture()
            events.append(['unrelated_prefix', {'schema': schema}])
            with self.subTest(schema=schema), self.assertRaises(ValueError):
                self.audit(events, report)

    def test_unknown_prefix_duplicate_keys_and_framing_fail(self):
        events, report = self.fixture()
        content = render(events)
        invalid = (
            content.replace('owned_dispatch_verification ', 'unknown_dispatch ', 1),
            content.replace('owned_dispatch_verification ', ' owned_dispatch_verification ', 1),
            content.replace('owned_dispatch_verification ', 'owned_dispatch_verification\t', 1),
            content.replace('owned_dispatch_verification {', 'owned_dispatch_verification {"session_id": 0, ', 1),
        )
        for changed in invalid:
            with self.subTest(changed=changed[:40]), self.assertRaises(ValueError):
                validate(changed, report, collect_gpu_receipts, verification_mode='exact-dispatch-v1')


if __name__ == '__main__':
    unittest.main()
