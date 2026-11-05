"""Pure complete-case profile and corrupted-stream tests; no GPU execution."""
import copy
import json
import unittest

import full_workflow_profiling as profile


def fixture(mode='detail'):
    empty = lambda n: [dict(completed=0, failed=0, elapsed_ns=0) for _ in range(n)]
    p = dict(schema=profile.SCHEMA, clock='host_monotonic_wall', mode=mode, complete=True,
             total_ns=800, phase_order=profile.PHASES, phase_ns=[100] * 8, groups=profile.GROUPS,
             native_inputs=empty(4), preissue=empty(16), execution=empty(16),
             parent_compile=empty(11), parent_outer=empty(11), events=0)
    routes = [dict(Native=dict(family='Source', ordinal=i)) for i in range(2)]
    routes += [dict(Parent=dict(level=0, ordinal=0, phase=phase)) for phase in ('Compile', 'Outer')]
    routes += [dict(Final=dict(step=0, output='Verified'))]
    events = []
    def emit(phase, kind, work=None, ns=None, success=None, now=None):
        sequence = len(events)
        events.append(dict(schema=profile.SCHEMA, sequence=sequence,
            since_start_ns=now if now is not None else phase * 100 + 1 + len([e for e in events if e['phase'] == profile.PHASES[phase]]),
            phase=profile.PHASES[phase], event=kind, work=work, elapsed_ns=ns, success=success))
    def step(phase, work):
        emit(phase, 'begin', work)
        emit(phase, 'end', work, 1, True)
    for phase in range(8):
        emit(phase, 'phase')
        if phase == 0:
            for i in range(3):
                step(phase, {'input': i})
                p['native_inputs'][i] = dict(completed=1, failed=0, elapsed_ns=1)
        if phase in (5, 6):
            for ordinal, route in enumerate(routes):
                group, level = profile.route_group(route)
                if phase == 5 and group not in profile.PROOFS:
                    continue
                if mode == 'detail':
                    step(phase, {'preissue' if phase == 5 else 'execute': [ordinal, route]})
                rows = p['preissue' if phase == 5 else 'execution']
                rows[group]['completed'] += 1
                rows[group]['elapsed_ns'] += 1
                if phase == 6 and level is not None:
                    rows = p['parent_compile' if group == 11 else 'parent_outer']
                    rows[level]['completed'] += 1
                    rows[level]['elapsed_ns'] += 1
    emit(7, 'complete', success=True, now=801)
    p['events'] = len(events)
    report = dict(transactions=3, native_proofs=2, recursive_proofs=1,
                  completed_phases=5, complete_workflow_ns=800, workflow_profile=p)
    return report, events, routes


def stream(events):
    return '\n'.join(profile.PREFIX + json.dumps(event) for event in events)


class WorkflowProfileTests(unittest.TestCase):
    def test_complete_summary_and_detail_reconcile(self):
        for mode in ('summary', 'detail'):
            report, events, routes = fixture(mode)
            result = profile.validate_progress(stream(events), report, mode, 900, expected_routes=routes)
            self.assertTrue(result['clock_reconciled'])
            self.assertTrue(result['progress_reconciled'])
        self.assertIsNone(profile.validate_progress('', {}, 'off', 1))

    def test_disabled_missing_or_changed_modes_are_rejected(self):
        report, events, routes = fixture()
        for mode in ('off', 'unknown', 'summary'):
            with self.assertRaises(ValueError):
                profile.validate_progress(stream(events), report, mode, 900, expected_routes=routes)
        report.pop('workflow_profile')
        with self.assertRaises(ValueError):
            profile.validate_summary(report, 'detail')

    def test_wrong_clocks_counts_levels_and_failure_are_rejected(self):
        for mutate in [
            lambda p: p['phase_ns'].__setitem__(0, 101),
            lambda p: p['phase_ns'].__setitem__(0, True),
            lambda p: p.__setitem__('complete', False),
            lambda p: p['execution'][0].__setitem__('completed', 3),
            lambda p: p['preissue'][0].__setitem__('failed', 1),
            lambda p: p['parent_outer'][0].__setitem__('elapsed_ns', 2),
            lambda p: p['native_inputs'][3].__setitem__('completed', 1),
            lambda p: p.__setitem__('events', 1),
        ]:
            report, _, routes = fixture()
            mutate(report['workflow_profile'])
            with self.assertRaises(ValueError):
                profile.validate_summary(report, 'detail')

    def test_partial_duplicate_out_of_order_and_changed_route_streams_are_rejected(self):
        report, events, routes = fixture()
        variants = [events[:-1], events + [events[-1]], events[:1] + events[2:]]
        for field, value in [('sequence', True), ('since_start_ns', 1000), ('success', False), ('phase', 'retirement')]:
            changed = copy.deepcopy(events)
            changed[2][field] = value
            variants.append(changed)
        changed = copy.deepcopy(events)
        index = next(i for i, e in enumerate(changed) if e['work'] and 'execute' in e['work'])
        changed[index]['work'] = copy.deepcopy(changed[index]['work'])
        changed[index]['work']['execute'][1]['Native']['ordinal'] = 99
        variants.append(changed)
        for changed in variants:
            with self.assertRaises(ValueError):
                profile.validate_progress(stream(changed), report, 'detail', 900, expected_routes=routes)

    def test_step_summary_cannot_hide_changed_detail_durations(self):
        report, events, routes = fixture()
        events[2]['elapsed_ns'] = 2
        with self.assertRaisesRegex(ValueError, 'differs from summary'):
            profile.validate_progress(stream(events), report, 'detail', 900, expected_routes=routes)


if __name__ == '__main__':
    unittest.main()
