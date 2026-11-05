"""Bounded full-case timing validation, independent of proof acceptance."""
from owned_workflow_case_receipts import parse_record

SCHEMA = 'ringct-full-workflow-profile-v1'
ENVIRONMENT = 'LATTICA_RINGCT_FULL_WORKFLOW_PROFILE'
PREFIX = 'RINGCT_WORKFLOW_PROGRESS '
MODES = ('off', 'summary', 'detail')
PHASES = ['generation', 'startup', 'metadata', 'admission', 'preflight', 'preissue', 'execution', 'retirement']
GROUPS = ['native', 'crypto_endpoints', 'crypto_native', 'crypto_compile', 'crypto_outer',
          'fixed_compile', 'fixed_outer', 'leaf_compile', 'leaf_outer', 'direct_compile',
          'direct_outer', 'parent_compile', 'parent_outer', 'final_compile', 'final_outer', 'final_verify']
PROOFS = (0, 2, 4, 6, 8, 10, 12, 14)


def require(condition, message):
    if not condition:
        raise ValueError('full-workflow profile: ' + message)


def natural(value):
    require(type(value) is int and 0 <= value < 1 << 128, 'invalid counter')
    return value


def works(values, size):
    require(type(values) is list and len(values) == size, 'wrong work inventory')
    for row in values:
        require(type(row) is dict and set(row) == {'completed', 'failed', 'elapsed_ns'}, 'wrong work fields')
        for value in row.values():
            natural(value)
        require(row['failed'] == 0, 'failed work in completed case')
        require(row['completed'] > 0 or row['elapsed_ns'] == 0, 'time without completed work')
    return values


def total(rows, field):
    return sum(row[field] for row in rows)


def validate_summary(report, mode):
    require(mode in MODES, 'unknown mode')
    profile = report.get('workflow_profile')
    if mode == 'off':
        require(profile is None, 'unexpected profiling report')
        return None
    require(type(profile) is dict and set(profile) == {
        'schema', 'clock', 'mode', 'complete', 'total_ns', 'phase_order', 'phase_ns', 'groups',
        'native_inputs', 'preissue', 'execution', 'parent_compile', 'parent_outer', 'events'}, 'missing or unknown report fields')
    require(profile['schema'] == SCHEMA and profile['mode'] == mode
            and profile['clock'] == 'host_monotonic_wall' and profile['complete'] is True, 'wrong profile identity or completion')
    require(profile['phase_order'] == PHASES and profile['groups'] == GROUPS, 'wrong phase/group inventory')
    require(type(profile['phase_ns']) is list and len(profile['phase_ns']) == len(PHASES), 'wrong phase clock count')
    phases = [natural(value) for value in profile['phase_ns']]
    require(natural(profile['total_ns']) == report['complete_workflow_ns'] == sum(phases), 'wall clocks do not reconcile')
    require(profile['total_ns'] > 0, 'empty case timing')
    inputs = works(profile['native_inputs'], 4)
    require([row['completed'] for row in inputs] == [1] * report['transactions'] + [0] * (4 - report['transactions']), 'wrong native input inventory')
    require(total(inputs, 'elapsed_ns') <= phases[0], 'input times exceed generation phase')
    for key, phase in [('preissue', 5), ('execution', 6)]:
        rows = works(profile[key], len(GROUPS))
        require(total(rows, 'elapsed_ns') <= phases[phase], key + ' times exceed their phase')
    execution, preissue = profile['execution'], profile['preissue']
    require(total(execution, 'completed') == report['completed_phases'], 'wrong executed phase count')
    require(sum(execution[i]['completed'] for i in (0, 2)) == report['native_proofs'], 'wrong native proof count')
    require(sum(execution[i]['completed'] for i in (4, 6, 8, 10, 12, 14)) == report['recursive_proofs'], 'wrong recursive proof count')
    require(execution[15]['completed'] == 1, 'missing final verification')
    for i in range(len(GROUPS)):
        require(preissue[i]['completed'] == (execution[i]['completed'] if i in PROOFS else 0), 'preissue differs from actual proof inventory')
    for key, group in [('parent_compile', 11), ('parent_outer', 12)]:
        rows = works(profile[key], 11)
        require(all(total(rows, field) == execution[group][field] for field in ('completed', 'elapsed_ns')), 'parent level totals differ')
    events = 9 + 2 * report['transactions']
    if mode == 'detail':
        events += 2 * (total(preissue, 'completed') + report['completed_phases'])
    require(natural(profile['events']) == events, 'wrong progress event count')
    return profile


def route_group(route):
    require(type(route) is dict and len(route) == 1, 'invalid producer route')
    name, fields = next(iter(route.items()))
    require(type(fields) is dict, 'invalid producer fields')
    if name == 'Native':
        require(set(fields) == {'family', 'ordinal'} and fields['family'] in
                ('Source', 'Uniform', 'Sparse', 'Transcript', 'Affine', 'Ntt', 'Mul', 'GBound', 'Permutation', 'LinearMap'), 'invalid native route')
        natural(fields['ordinal'])
        return 0, None
    if name in ('Fixed', 'Leaf', 'Direct', 'Parent'):
        expected = {'ordinal', 'phase'} | ({'family'} if name in ('Leaf', 'Direct') else {'level'} if name == 'Parent' else set())
        require(set(fields) == expected and fields['phase'] in ('Compile', 'Outer'), 'invalid graph route')
        natural(fields['ordinal'])
        if name == 'Leaf':
            require(fields['family'] in ('Source', 'Affine', 'Ntt', 'Mul', 'GBound', 'Permutation', 'LinearMap'), 'invalid leaf family')
        if name == 'Direct':
            require(fields['family'] in ('Parameters', 'Auxiliary', 'Equality'), 'invalid direct family')
        level = natural(fields['level']) if name == 'Parent' else None
        require(level is None or level < 11, 'parent level exceeds fixed inventory')
        return {'Fixed': 5, 'Leaf': 7, 'Direct': 9, 'Parent': 11}[name] + (fields['phase'] == 'Outer'), level
    require(name in ('Crypto', 'Final'), 'unknown producer family')
    if name == 'Crypto':
        require(set(fields) == {'family', 'request', 'step', 'output'} and fields['family'] in ('Shake', 'Aes'), 'invalid crypto route')
        natural(fields['request'])
    else:
        require(set(fields) == {'step', 'output'}, 'invalid final route')
    natural(fields['step'])
    output = fields['output']
    if name == 'Final' and output == 'Verified':
        return 15, None
    require(type(output) is dict and len(output) == 1, 'invalid producer output')
    key, ordinal = next(iter(output.items()))
    natural(ordinal)
    mapping = {'Endpoint': 1, 'Native': 2, 'Compiled': 3, 'Outer': 4} if name == 'Crypto' else {'Compiled': 13, 'Outer': 14}
    require(key in mapping, 'unknown producer output')
    return mapping[key], None


def dispatch_inventory(content):
    routes = []
    prefix = 'owned_dispatch_verification '
    for line in content.splitlines():
        if line.startswith(prefix):
            value = parse_record(line[len(prefix):], prefix.rstrip())
            if value['stage'] == 'inventory':
                require(value['identity']['closed_ordinal'] == len(routes), 'reordered dispatch inventory')
                routes.append(value['identity']['route'])
    return routes


def validate_progress(content, report, mode, observation_ns, *, expected_routes=None):
    profile = validate_summary(report, mode)
    events = [parse_record(line[len(PREFIX):], PREFIX.rstrip()) for line in content.splitlines() if line.startswith(PREFIX)]
    if profile is None:
        require(not events, 'progress without selected profiling')
        return None
    require(len(events) == profile['events'], 'missing progress events')
    require(type(expected_routes) is list and len(expected_routes) == report['completed_phases'], 'missing verified dispatch inventory')
    expected_groups = [0] * len(GROUPS)
    for route in expected_routes:
        expected_groups[route_group(route)[0]] += 1
    require(expected_groups == [row['completed'] for row in profile['execution']], 'summary differs from verified dispatch inventory')
    active = None
    phase_index = -1
    last_time = 0
    next_input = next_execute = 0
    issued = {}
    last_preissue = -1
    counts = {key: [{'completed': 0, 'failed': 0, 'elapsed_ns': 0} for _ in rows]
              for key, rows in profile.items() if key in ('native_inputs', 'preissue', 'execution', 'parent_compile', 'parent_outer')}
    for sequence, event in enumerate(events):
        require(type(event) is dict and set(event) == {'schema', 'sequence', 'since_start_ns', 'phase', 'event', 'work', 'elapsed_ns', 'success'}, 'wrong event fields')
        now = natural(event['since_start_ns'])
        require(event['schema'] == SCHEMA and natural(event['sequence']) == sequence and last_time <= now <= observation_ns, 'wrong event identity or clock')
        last_time = now
        kind = event['event']
        if kind == 'phase':
            phase_index += 1
            require(active is None and phase_index < len(PHASES) and event['work'] is event['elapsed_ns'] is event['success'] is None, 'invalid phase boundary')
        require(0 <= phase_index < len(PHASES) and event['phase'] == PHASES[phase_index], 'wrong event phase')
        if kind == 'phase':
            continue
        if kind == 'complete':
            require(sequence == len(events) - 1 and phase_index == 7 and active is None and event['work'] is event['elapsed_ns'] is None
                    and event['success'] is True and now >= profile['total_ns'], 'incomplete final event')
            continue
        require(kind in ('begin', 'end') and type(event['work']) is dict and len(event['work']) == 1, 'invalid step event')
        family, work = next(iter(event['work'].items()))
        require(family in ('input', 'preissue', 'execute'), 'unknown step action')
        if family == 'input':
            ordinal, route, group, level, table = natural(work), None, natural(work), None, 'native_inputs'
            require(phase_index == 0 and group < report['transactions'], 'wrong input step')
        else:
            require(mode == 'detail' and type(work) is list and len(work) == 2, 'unexpected detailed step')
            ordinal, route = natural(work[0]), work[1]
            group, level = route_group(route)
            require(ordinal < len(expected_routes) and route == expected_routes[ordinal], 'step differs from verified dispatch inventory')
            table = 'execution' if family == 'execute' else 'preissue'
            require(phase_index == (6 if family == 'execute' else 5), 'wrong producer step phase')
        if kind == 'begin':
            require(active is None and event['elapsed_ns'] is event['success'] is None, 'overlapping or completed begin event')
            if family == 'input':
                require(ordinal == next_input, 'input order changed')
                next_input += 1
            elif family == 'preissue':
                require(ordinal > last_preissue and group in PROOFS, 'preissue order or route changed')
                issued[ordinal] = route
                last_preissue = ordinal
            else:
                require(ordinal == next_execute, 'execution order changed')
                next_execute += 1
                require((group not in PROOFS and ordinal not in issued) or issued.get(ordinal) == route, 'executed proof differs from preissue')
            active = (event['work'], now)
        else:
            require(active is not None and active[0] == event['work'] and event['success'] is True, 'unmatched or failed completion')
            ns = natural(event['elapsed_ns'])
            # The timer starts immediately before its begin event is written.
            require(ns <= profile['phase_ns'][phase_index] and ns <= now, 'step time outside phase')
            row = counts[table][group]
            row['completed'] += 1
            row['elapsed_ns'] += ns
            if family == 'execute' and level is not None:
                row = counts['parent_compile' if group == 11 else 'parent_outer'][level]
                row['completed'] += 1
                row['elapsed_ns'] += ns
            active = None
    require(events[-1]['event'] == 'complete' and active is None, 'missing terminal event')
    for key, rows in counts.items():
        if mode == 'detail' or key == 'native_inputs':
            require(rows == profile[key], 'progress differs from summary: ' + key)
    return {'schema': SCHEMA, 'mode': mode, 'events': len(events), 'clock_reconciled': True, 'progress_reconciled': True}
