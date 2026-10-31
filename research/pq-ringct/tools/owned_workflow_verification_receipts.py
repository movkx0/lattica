"""Strict exact-dispatch verification audit for binding-identified v2 epochs.

Expected inventory never earns completion or timing credit. Only completed
attempts with the exact planned identity and actual proof/row/verified epoch
sequence contribute. Artifact/mutation qualification remains final-aggregate.
"""
import copy
import json

import owned_workflow_cpu_receipts as common

PREFIX = 'owned_dispatch_verification'
SCHEMA = 'ringct-owned-dispatch-verification-v1'
IDENTITY_FIELDS = ('closed_ordinal', 'expected_steps', 'transactions', 'route', 'binding',
    'workflow_source_fingerprint', 'member', 'member_first', 'member_count', 'source_kind', 'source_ordinal')
BINDING_FIELDS = ('kind', 'ordinal', 'source_fingerprint', 'compiled_source_fingerprint')
NATIVE_FAMILIES = {'Source': 'graph_source', 'Uniform': 'uniform', 'Sparse': 'sparse',
    'Transcript': 'transcript', 'Affine': 'affine', 'Ntt': 'ntt', 'Mul': 'mul',
    'GBound': 'g_bound', 'Permutation': 'permutation', 'LinearMap': 'linear_map'}
LEAF_FAMILIES = {'Source', 'Affine', 'Ntt', 'Mul', 'GBound', 'Permutation', 'LinearMap'}


def require(condition, message):
    if not condition:
        raise ValueError('Exact verification receipts: ' + message)


def digest(value, name):
    require(type(value) is list and len(value) == 32, 'invalid digest: ' + name)
    for byte in value:
        common.integer(byte, name, 8)


def variant(value, names, name):
    require(type(value) is dict and len(value) == 1, 'invalid variant: ' + name)
    kind = next(iter(value))
    require(kind in names, 'unknown variant: ' + name)
    return kind, value[kind]


def inspect_binding(value):
    common.fields(value, BINDING_FIELDS, 'verification binding')
    common.integer(value['ordinal'], 'binding ordinal')
    require(type(value['kind']) is str, 'invalid phase kind')
    for name in ('source_fingerprint', 'compiled_source_fingerprint'):
        digest(value[name], name)
    return value


def inspect_identity(identity, report):
    common.fields(identity, IDENTITY_FIELDS, 'dispatch identity')
    for name in ('closed_ordinal', 'expected_steps', 'transactions', 'member_first', 'member_count'):
        common.integer(identity[name], name)
    require(identity['expected_steps'] == report['completed_phases']
            and identity['transactions'] == report['transactions']
            and identity['closed_ordinal'] < identity['expected_steps'], 'dispatch inventory geometry mismatch')
    for name in ('member', 'source_ordinal'):
        if identity[name] is not None:
            common.integer(identity[name], name)
    binding = inspect_binding(identity['binding'])
    digest(identity['workflow_source_fingerprint'], 'workflow source')
    require(binding['compiled_source_fingerprint'] == report['final_qualification'].get('compiled_source_fingerprint'),
            'dispatch compiled source differs from final qualified source')
    require(type(binding['kind']) is str, 'invalid phase kind')
    route, body = variant(identity['route'], ('Native', 'Leaf', 'Fixed', 'Direct', 'Crypto', 'Parent', 'Final'), 'route')
    route_fields = {'Native': ('family', 'ordinal'), 'Leaf': ('family', 'ordinal', 'phase'),
        'Fixed': ('ordinal', 'phase'), 'Direct': ('family', 'ordinal', 'phase'),
        'Crypto': ('family', 'request', 'step', 'output'), 'Parent': ('level', 'ordinal', 'phase'),
        'Final': ('step', 'output')}
    common.fields(body, route_fields[route], 'route.' + route)
    for name in ('ordinal', 'request', 'step', 'level'):
        if name in body:
            common.integer(body[name], 'route.' + name)
    if 'phase' in body:
        require(body['phase'] in ('Compile', 'Outer'), 'invalid graph phase')
    family = body.get('family')
    proof_entry = final_stage = None
    if route == 'Native':
        require(type(family) is str and family in NATIVE_FAMILIES, 'invalid native family')
        expected_kind = family + 'Native'
        proof_entry = 'ringct_owned_native_' + NATIVE_FAMILIES[family]
        source_kind = ('source-kind-index' if family == 'Source' else 'auxiliary-request'
                       if family in ('Uniform', 'Sparse', 'Transcript') else 'algebra-batch')
    elif route == 'Leaf':
        require(type(family) is str and family in LEAF_FAMILIES, 'invalid leaf family')
        expected_kind = 'GraphOuter' if body['phase'] == 'Outer' else (
            'SourceNativeCompile' if family == 'Source' else 'AlgebraCompile')
        source_kind = 'source-kind-index' if family == 'Source' else 'algebra-batch'
    elif route == 'Fixed':
        expected_kind = 'GraphOuter' if body['phase'] == 'Outer' else 'SourceCompile'
        source_kind = 'fixed-source'
    elif route == 'Direct':
        require(family in ('Parameters', 'Auxiliary', 'Equality'), 'invalid direct family')
        expected_kind = 'GraphOuter' if body['phase'] == 'Outer' else 'GraphLeafCompile'
        source_kind = 'graph-leaf'
    elif route == 'Parent':
        require(body['level'] < 32, 'invalid parent level')
        expected_kind = 'GraphOuter' if body['phase'] == 'Outer' else 'GraphParentCompile'
        source_kind = 'parent-route'
    elif route == 'Crypto':
        require(family in ('Shake', 'Aes'), 'invalid crypto family')
        output, index = variant(body['output'], ('Endpoint', 'Native', 'Compiled', 'Outer'), 'crypto output')
        common.integer(index, 'crypto output index')
        require(binding['ordinal'] == body['step'], 'crypto request local step mismatch')
        source_kind = 'crypto-request'
        if output == 'Native':
            expected_kind = 'Native'
            proof_entry = 'ringct_owned_native_' + family.lower()
        elif output == 'Outer':
            expected_kind = 'OuterProve'
            proof_entry = 'block_v2_registered_program'
        elif output == 'Endpoint':
            expected_kind = 'EndpointAttach'
            require(index == body['request'], 'crypto endpoint request mismatch')
        else:
            require(binding['kind'] in ('GroupCompile', 'ParentCompile'), 'invalid crypto compiler kind')
            expected_kind = binding['kind']
    else:
        source_kind = 'ordered-merge'
        require(binding['ordinal'] == body['step'], 'final local step mismatch')
        if body['output'] == 'Verified':
            expected_kind, final_stage = 'FinalVerify', 'verify'
            require(body['step'] == 2 * (report['transactions'] - 1), 'wrong final verification step')
            require(identity['source_ordinal'] is None, 'final verification has merge source ordinal')
        else:
            output, index = variant(body['output'], ('Compiled', 'Outer'), 'final output')
            common.integer(index, 'final merge index')
            require(index < report['transactions'] - 1 and body['step'] == 2 * index + int(output == 'Outer')
                    and identity['source_ordinal'] == index, 'final merge source mismatch')
            expected_kind = 'FinalCompile' if output == 'Compiled' else 'FinalOuter'
            final_stage = 'compile' if output == 'Compiled' else 'outer'
            if output == 'Outer':
                proof_entry = 'block_v2_registered_program'
    if route in ('Leaf', 'Fixed', 'Direct', 'Parent') and body['phase'] == 'Outer':
        proof_entry = 'block_v2_registered_program'
    require(binding['kind'] == expected_kind, 'route/phase binding mismatch')
    require(identity['source_kind'] == source_kind, 'wrong source ordinal semantics')
    if route == 'Final':
        require(identity['member'] is None and 2 <= identity['member_count'] <= report['transactions'],
                'invalid final member interval')
    else:
        member = common.integer(identity['member'], 'member')
        require(member < report['transactions'] and identity['member_first'] == member
                and identity['member_count'] == 1, 'invalid dispatch member identity')
        if route == 'Parent':
            require(identity['source_ordinal'] is None, 'parent has unrelated source ordinal')
        else:
            common.integer(identity['source_ordinal'], 'source ordinal')
    require(identity['member_first'] + identity['member_count'] <= report['transactions'],
            'member interval exceeds transaction inventory')
    return proof_entry, final_stage


def expected_records(identity, proof_entry, final_stage, native_prefixes):
    if proof_entry is not None:
        if proof_entry == 'block_v2_registered_program':
            result = [('proving_stage_report', 'block_v2_preprocessing'),
                ('proving_stage_report', proof_entry), ('owned_proof_rows', proof_entry),
                ('owned_outer_epoch', None)]
        else:
            prefix = next(prefix for prefix, entries in native_prefixes.items() if proof_entry in entries)
            result = [(prefix, proof_entry), ('owned_proof_rows', proof_entry),
                      (prefix.replace('_report', '_epoch'), None)]
        if final_stage:
            result.append(('owned_final_stage', final_stage))
        return result
    if final_stage == 'compile':
        return [('owned_final_compile_report', 'pq_graph_witness_preparation'),
                ('owned_final_compile_epoch', None), ('owned_final_stage', 'compile')]
    if final_stage == 'verify':
        return [('owned_final_stage', 'verify')]
    if identity['binding']['kind'] == 'GroupCompile':
        return [('owned_group_report', 'pq_graph_witness_preparation'), ('owned_group_epoch', None)]
    return []


def validate(content, report, native_prefixes, parse_record):
    require(type(report.get('final_qualification')) is dict, 'missing final qualification identity')
    phases = common.integer(report.get('completed_phases'), 'completed_phases')
    require(phases > 0, 'empty completed dispatch')
    session = report['owned_observations']['session_id']
    native_epochs = {prefix.replace('_report', '_epoch') for prefix in native_prefixes}
    verification_epochs = native_epochs | {'owned_outer_epoch'}
    phase_prefixes = set(native_prefixes) | verification_epochs | {
        'proving_stage_report', 'owned_proof_rows', 'owned_group_report', 'owned_group_epoch',
        'owned_final_compile_report', 'owned_final_compile_epoch', 'owned_final_stage'}
    inventory, routes, normalized, families = [], set(), [], {}
    current = None
    completed = 0
    proof_sequence = 0
    proof_cpu_ns = native_cpu_ns = outer_cpu_ns = 0
    final_outer_cpu_ns = 0
    workflow_source = None
    for line in content.splitlines():
        stripped = line.lstrip()
        prefix = stripped.split(None, 1)[0] if stripped else ''
        payload = stripped[len(prefix) + 1:]
        if prefix not in phase_prefixes and prefix != PREFIX:
            unknown = stripped if stripped.startswith('{') else payload
            if unknown.lstrip().startswith('{'):
                schema = parse_record(unknown, prefix).get('schema')
                reserved = type(schema) is str and (
                    schema.startswith('ringct-owned-dispatch-verification-v')
                    or schema.startswith('ringct-owned-final-stage-v')
                    or (schema.startswith('ringct-owned-') and '-epoch-v' in schema))
                require(not reserved, 'dispatch or verification receipt under unknown prefix')
            normalized.append(line)
            continue
        require(line == stripped and stripped.startswith(prefix + ' ') and payload.startswith('{'),
                'invalid receipt framing: ' + prefix)
        value = parse_record(payload, prefix)
        if prefix == PREFIX:
            common.fields(value, ('schema', 'stage', 'session_id', 'identity'), 'dispatch receipt')
            require(value['schema'] == SCHEMA and type(value['stage']) is str
                    and value['stage'] in ('inventory', 'attempt', 'complete'), 'wrong dispatch schema or stage')
            require(common.integer(value['session_id'], 'dispatch session') == session, 'wrong dispatch session')
            identity = value['identity']
            proof_entry, final_stage = inspect_identity(identity, report)
            stage = value['stage']
            if stage == 'inventory':
                require(current is None and completed == 0 and identity['closed_ordinal'] == len(inventory)
                        and len(inventory) < phases, 'duplicate, reordered or late inventory')
                route_key = json.dumps(identity['route'], sort_keys=True, separators=(',', ':'))
                require(route_key not in routes, 'duplicate source producer route')
                routes.add(route_key)
                if workflow_source is None:
                    workflow_source = identity['workflow_source_fingerprint']
                require(identity['workflow_source_fingerprint'] == workflow_source, 'inventory workflow source changed')
                inventory.append(identity)
            elif stage == 'attempt':
                require(len(inventory) == phases and current is None and completed < phases
                        and identity == inventory[completed], 'missing inventory, duplicate attempt or wrong dispatch identity')
                current = {'identity': identity, 'expected': expected_records(identity, proof_entry, final_stage, native_prefixes),
                    'seen': 0, 'entry': proof_entry, 'final_stage': final_stage, 'cpu_ns': None}
            else:
                require(current is not None and identity == current['identity']
                        and identity == inventory[completed], 'missing attempt or misbound completion')
                require(current['seen'] == len(current['expected']), 'completed dispatch missing actual receipts')
                entry = current['entry']
                if entry is not None:
                    require(current['cpu_ns'] is not None, 'completed proof has unavailable CPU verification time')
                    cpu = current['cpu_ns']
                    proof_cpu_ns = common.add(proof_cpu_ns, cpu)
                    if entry == 'block_v2_registered_program':
                        outer_cpu_ns = common.add(outer_cpu_ns, cpu)
                    else:
                        native_cpu_ns = common.add(native_cpu_ns, cpu)
                    route_name, body = next(iter(identity['route'].items()))
                    family = route_name + ('.' + body['family'] if 'family' in body else '')
                    key = family + ('.native' if entry != 'block_v2_registered_program' else '.outer')
                    totals = families.setdefault(key, {'proofs': 0, 'cpu_verification_ns': 0})
                    totals['proofs'] += 1
                    totals['cpu_verification_ns'] = common.add(totals['cpu_verification_ns'], cpu)
                completed += 1
                current = None
            continue
        # Source preparation is outside dispatch, strictly before inventory.
        if current is None:
            require(not inventory and prefix == 'proving_stage_report'
                    and value.get('entry_point') == 'pq_graph_witness_preparation',
                    'proof or phase receipt outside an actual attempt')
            normalized.append(line)
            continue
        observed = (prefix, value.get('stage') if prefix == 'owned_final_stage' else value.get('entry_point'))
        require(current['seen'] < len(current['expected'])
                and observed == current['expected'][current['seen']],
                'extra, missing, reordered or wrong-family receipt inside dispatch')
        current['seen'] += 1
        identity = current['identity']
        if prefix == 'owned_proof_rows':
            require(value.get('session_id') == session and common.integer(value.get('sequence'), 'row sequence')
                    == proof_sequence, 'dispatch proof row session/sequence mismatch')
            proof_sequence += 1
        elif prefix in verification_epochs:
            common.fields(value, ('schema', 'ordinal', 'binding', 'epoch'), 'v2 verification epoch')
            inspect_binding(value['binding'])
            require(value['binding'] == identity['binding']
                    and common.integer(value['ordinal'], 'epoch ordinal') == identity['binding']['ordinal'],
                    'verification epoch from wrong source or local phase')
            expected_schema = ('ringct-owned-outer-epoch-v2' if prefix == 'owned_outer_epoch'
                else 'ringct-owned-native-epoch-v2' if prefix == 'owned_native_epoch'
                else 'ringct-owned-source-native-epoch-v2')
            require(value['schema'] == expected_schema, 'strict audit requires binding-identified v2 epoch')
            epoch = value['epoch']
            require(type(epoch) is dict and epoch.get('independent_verification_complete') is True,
                    'independent verification did not complete')
            current['cpu_ns'] = common.integer(epoch.get('cpu_verification_ns'), 'CPU verification duration', 128)
            # Reuse the v1 lifetime/row/final-stage checks on a transport-only
            # projection. No success flag, observed timing, proof or count is
            # synthesized; strict identity/timing is checked above and below.
            legacy = copy.deepcopy(value)
            del legacy['binding']
            legacy['schema'] = expected_schema[:-2] + 'v1'
            if prefix == 'owned_outer_epoch':
                del legacy['epoch']['cpu_verification_ns']
            normalized.append(prefix + ' ' + json.dumps(legacy))
            continue
        elif prefix in ('owned_group_epoch', 'owned_final_compile_epoch'):
            require(common.integer(value.get('ordinal'), 'preparation ordinal') == identity['binding']['ordinal'],
                    'preparation epoch local phase mismatch')
        elif prefix == 'owned_final_stage':
            require(value.get('ordinal') == identity['binding']['ordinal'], 'final stage local phase mismatch')
            stage_report = value.get('report')
            require(type(stage_report) is dict and (stage_report.get('first'), stage_report.get('count'))
                    == (identity['member_first'], identity['member_count']), 'final stage member coverage mismatch')
            if current['final_stage'] == 'outer':
                require(current['cpu_ns'] == stage_report.get('cpu_verification_ns'), 'final outer CPU timing mismatch')
                final_outer_cpu_ns = common.add(final_outer_cpu_ns, current['cpu_ns'])
        normalized.append(line)
    require(len(inventory) == phases and completed == phases and current is None,
            'inventory alone or incomplete terminal dispatch')
    partial = common.validate('\n'.join(normalized), report, native_prefixes, parse_record)
    require(proof_sequence == report['native_proofs'] + report['recursive_proofs'], 'actual proof coverage mismatch')
    final_times = partial['final_stage_cpu_verification_ns']
    require(final_times['outer'] == final_outer_cpu_ns, 'final CPU proof timing counted inconsistently')
    total = common.add(common.add(proof_cpu_ns, final_times['compile']), final_times['verify'])
    require(total <= report['proving_and_verification_ns'], 'CPU verification exceeds execution duration')
    return {'schema': 'ringct-owned-exact-verification-receipts-v1',
        'coverage': 'exact-dispatch-v1', 'inventory_steps': phases, 'completed_steps': completed,
        'proof_epoch_coverage_complete': True, 'exact_dispatch_identity_coverage_complete': True,
        'source_member_request_identity_authenticated': True,
        'native_cpu_verification_ns': native_cpu_ns, 'recursive_cpu_verification_ns': outer_cpu_ns,
        'proof_producer_cpu_verification_ns': proof_cpu_ns,
        'final_stage_cpu_verification_ns': final_times,
        'complete_cpu_verification_ns': total, 'known_cpu_verification_ns': total,
        'recursive_proofs_with_cpu_timing': report['recursive_proofs'],
        'recursive_proofs_without_cpu_timing': 0, 'by_dispatch_family': families,
        'inventory_used_as_completion': False, 'final_outer_timing_counted_once': True,
        'artifact_mutation_qualification_scope': 'final-aggregate'}
