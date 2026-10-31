"""Reconcile one fresh owned N3/N4 receipt stream with its fixed snapshots.

This is an audit, not a runner, admission mechanism, artifact verifier or cache
coverage estimator. The caller separately authenticates the binary, requested
case, environment, artifact and terminal process/resource evidence.
"""
import json
import owned_workflow_row_receipts
import owned_workflow_cpu_receipts
import owned_workflow_verification_receipts
import math
import re


NATIVE_ENTRIES = tuple('ringct_owned_native_' + family for family in (
    'graph_source', 'uniform', 'sparse', 'transcript', 'affine', 'ntt', 'mul',
    'g_bound', 'permutation', 'linear_map', 'aes', 'shake'))
NATIVE_PREFIXES = {
    'owned_native_report': frozenset(NATIVE_ENTRIES[-2:]),
    'owned_source_native_report': frozenset((NATIVE_ENTRIES[0],)),
    **{'owned_' + family + '_native_report': frozenset(('ringct_owned_native_' + family,))
       for family in ('uniform', 'sparse', 'transcript', 'affine', 'ntt', 'mul',
                      'g_bound', 'permutation', 'linear_map')},
}
PREPARATION_ENTRY = 'pq_graph_witness_preparation'
SPEND_ENTRY = 'native_matrict_spend'
MACHINE_ENTRIES = ('block_v2_preprocessing', 'block_v2_registered_program')
OWNED_PREPARATION_PREFIXES = frozenset(('owned_group_report', 'owned_final_compile_report'))
GPU_PREFIXES = frozenset(NATIVE_PREFIXES) | OWNED_PREPARATION_PREFIXES | frozenset((
    'proving_stage_report', 'owned_generation_report'))
GENERATION_RECORDS = frozenset(('owned_generation_spend', 'owned_generation_terminal'))
REPORT_FIELDS = frozenset(('schema', 'entry_point', 'policy', 'capabilities', 'elapsed_ns',
    'succeeded', 'stage_coverage_complete', 'completion_rejected', 'observation_errors',
    'observations', 'components'))
OBSERVATION_FIELDS = frozenset(('stage', 'backend', 'calls', 'completed_calls',
    'device_calls', 'inclusive_ns', 'device_ns'))
GENERATION_FIELDS = frozenset(('spends', 'seconds', 'managed_peak_bytes',
    'witness_completed_calls', 'witness_device_calls', 'witness_device_ns'))
SOURCE_FIELDS = frozenset(('session_id', 'calls', 'succeeded', 'complete_reports', 'seconds',
    'witness_completed_calls', 'witness_device_calls', 'witness_device_ns',
    'native_cpu_calls', 'native_cpu_succeeded', 'failure_events'))
TOTAL_FIELDS = ('reports', 'completed_calls', 'device_calls', 'elapsed_ns', 'device_ns')
MANAGED_DEVICE_BYTES = 8 << 30


def require(condition, message):
    if not condition:
        raise ValueError(message)


def object_fields(value, fields, name):
    require(type(value) is dict and set(value) == set(fields), 'invalid fields: ' + name)
    return value


def integer(value, name, *, bits=64, positive=False):
    require(type(value) is int and (1 if positive else 0) <= value < 1 << bits,
            'invalid integer: ' + name)
    return value


def seconds(value, name):
    require(type(value) in (int, float) and 0 < value < 1 << 128 and math.isfinite(value),
            'invalid seconds: ' + name)
    return value


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def parse_record(text, prefix):
    def reject_constant(value):
        raise ValueError('nonfinite JSON constant: ' + value)
    def finite_float(value):
        parsed = float(value)
        require(math.isfinite(parsed), 'nonfinite JSON number: ' + value)
        return parsed
    try:
        value = json.loads(text, object_pairs_hook=no_duplicate_keys,
                           parse_constant=reject_constant, parse_float=finite_float)
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError('malformed receipt: ' + prefix) from error
    require(type(value) is dict, 'receipt is not an object: ' + prefix)
    return value


def raw_report(value, prefix):
    """Validate numeric presence/types before the legacy-compatible collector."""
    object_fields(value, REPORT_FIELDS, prefix)
    require(value['schema'] == 'lattica-proving-stages-v1', 'wrong proving receipt schema')
    integer(value['elapsed_ns'], prefix + '.elapsed_ns', bits=128)
    integer(value['observation_errors'], prefix + '.observation_errors')
    require(type(value['components']) is list and not value['components'],
            'owned receipt contains component or cache credit')
    capabilities = object_fields(value['capabilities'],
        ('scope', 'profile', 'max_log_fri_arity', 'stages'), prefix + '.capabilities')
    arity = integer(capabilities['max_log_fri_arity'], prefix + '.max_log_fri_arity', bits=8)
    require(arity == (0 if prefix == 'owned_generation_report' else 1),
            'wrong owned receipt FRI profile')
    require(type(capabilities['stages']) is list and capabilities['stages'],
            'missing owned receipt stage inventory')
    for stage in capabilities['stages']:
        object_fields(stage, ('stage', 'backend'), prefix + '.stage')
        require(type(stage['stage']) is str and type(stage['backend']) is str,
                'invalid stage identity')
    require(type(value['observations']) is list and value['observations'],
            'missing owned receipt observations')
    for observation in value['observations']:
        object_fields(observation, OBSERVATION_FIELDS, prefix + '.observation')
        require(type(observation['stage']) is str and type(observation['backend']) is str,
                'invalid observation identity')
        for key in ('calls', 'completed_calls', 'device_calls'):
            integer(observation[key], prefix + '.' + key)
        for key in ('inclusive_ns', 'device_ns'):
            integer(observation[key], prefix + '.' + key, bits=128)
    entry = value['entry_point']
    if prefix in NATIVE_PREFIXES:
        allowed = NATIVE_PREFIXES[prefix]
    elif prefix in OWNED_PREPARATION_PREFIXES:
        allowed = (PREPARATION_ENTRY,)
    elif prefix == 'owned_generation_report':
        allowed = (SPEND_ENTRY,)
    else:
        allowed = MACHINE_ENTRIES + (PREPARATION_ENTRY,)
    require(type(entry) is str and entry in allowed,
            'receipt prefix/entry identity mismatch: ' + prefix)
    # The shared collector checks success, GPU policy/backend, exact complete
    # stage/profile/scope inventory and completed device calls, using these
    # original entry names. Only the line prefix is normalized below.
    return entry


def digest(value, name):
    require(type(value) is list and len(value) == 32, 'invalid digest: ' + name)
    for byte in value:
        integer(byte, name, bits=8)


def generation_spend(summary, receipt, ordinal, session_id):
    object_fields(summary, ('session_id', 'ordinal', 'elapsed_ns', 'witness_completed_calls',
        'witness_device_calls', 'witness_device_ns', 'managed_bytes', 'prelude_steps',
        'accepted_attempt_steps', 'source_fingerprint', 'kernel_source_sha256'),
        'owned_generation_spend')
    require(integer(summary['session_id'], 'spend.session_id', positive=True) == session_id
            and integer(summary['ordinal'], 'spend.ordinal') == ordinal,
            'generation spend session or ordinal mismatch')
    require(integer(summary['elapsed_ns'], 'spend.elapsed_ns', bits=128) == receipt['elapsed_ns'],
            'generation spend elapsed receipt mismatch')
    require(len(receipt['observations']) == 1, 'generation spend observation count')
    observation = receipt['observations'][0]
    for target, key in (('witness_completed_calls', 'completed_calls'),
                        ('witness_device_calls', 'device_calls'), ('witness_device_ns', 'device_ns')):
        require(integer(summary[target], 'spend.' + target, bits=128 if key == 'device_ns' else 64)
                == observation[key], 'generation spend stage receipt mismatch: ' + target)
    require(integer(summary['managed_bytes'], 'spend.managed_bytes', positive=True)
            <= MANAGED_DEVICE_BYTES, 'generation spend exceeds managed device allowance')
    require(integer(summary['prelude_steps'], 'spend.prelude_steps', bits=32) == 0x3f
            and integer(summary['accepted_attempt_steps'], 'spend.accepted_attempt_steps', bits=32)
            == 0x03ffffc0, 'incomplete native generation schedule')
    digest(summary['source_fingerprint'], 'spend.source_fingerprint')
    require(type(summary['kernel_source_sha256']) is str
            and re.fullmatch('[0-9a-fA-F]{64}', summary['kernel_source_sha256']) is not None,
            'invalid generation kernel source identity')


def time_covered(elapsed_ns, wrapper_seconds, calls, name):
    # Diagnostics measures an OUTER wrapper interval, not the sum of receipt
    # intervals. Permit only binary-float summation/serialization rounding at
    # the lower bound; never force equality or invent the wrapper overhead.
    tolerance = max(1e-9, (calls + 2) * math.ulp(wrapper_seconds))
    require(elapsed_ns / 1e9 <= wrapper_seconds + tolerance,
            'receipt time exceeds wrapper duration: ' + name)


def entry_totals(receipts, entry):
    return receipts['by_entry'].get(entry, dict.fromkeys(TOTAL_FIELDS, 0))


def report_totals(snapshot, observed, name):
    object_fields(snapshot, ('reports', 'elapsed_ns'), name)
    require(integer(snapshot['reports'], name + '.reports') == observed['reports']
            and integer(snapshot['elapsed_ns'], name + '.elapsed_ns', bits=128)
            == observed['elapsed_ns'], 'owned report totals mismatch: ' + name)


def witness_totals(snapshot, observed, name):
    for target, key in (('witness_completed_calls', 'completed_calls'),
                        ('witness_device_calls', 'device_calls'), ('witness_device_ns', 'device_ns')):
        require(integer(snapshot[target], name + '.' + target, bits=128 if key == 'device_ns' else 64)
                == observed[key], 'witness stage totals mismatch: ' + name + '.' + target)


def generation_numbers(value, name):
    object_fields(value, GENERATION_FIELDS, name)
    for key in ('spends', 'managed_peak_bytes', 'witness_completed_calls', 'witness_device_calls'):
        integer(value[key], name + '.' + key, positive=True)
    integer(value['witness_device_ns'], name + '.witness_device_ns', bits=128)
    seconds(value['seconds'], name + '.seconds')


def validate(content, report, collect_gpu_receipts, *, verification_mode):
    """Return fixed receipt evidence, or raise ValueError; never execute work."""
    require(verification_mode in ('existing-format-partial', 'exact-dispatch-v1'), 'unknown verification receipt mode')
    require(type(content) is str and type(report) is dict, 'invalid complete-case audit input')
    count = integer(report.get('transactions'), 'transactions')
    require(count in (3, 4), 'owned case requires exactly N3 or N4')
    native_count = integer(report.get('native_proofs'), 'native_proofs', positive=True)
    recursive_count = integer(report.get('recursive_proofs'), 'recursive_proofs', positive=True)
    generation_id = integer(report.get('generation_session_id'), 'generation_session_id', positive=True)
    generation = object_fields(report.get('generation'), GENERATION_FIELDS, 'generation')
    source = object_fields(report.get('source_preparation'), SOURCE_FIELDS, 'source_preparation')
    observed = report.get('owned_observations')
    extra = ('identity_preprocessing',) if type(observed) is dict and 'identity_preprocessing' in observed else ()
    owned = object_fields(observed, ('schema', 'session_id',
        'machine_preprocessing', 'machine_proofs', 'native_proofs', 'witness_preparation',
        'row_receipts', 'machine_rows') + extra,
        'owned_observations')
    from identity_preprocessing_receipts import reconcile
    content, identity_audit = reconcile(content, owned.get('identity_preprocessing'))
    require(owned['schema'] == 'ringct-owned-workflow-observations-v2',
            'wrong owned observation schema')
    planning_id = integer(owned['session_id'], 'owned.session_id', positive=True)
    require(integer(source['session_id'], 'source.session_id', positive=True) == planning_id
            and planning_id > generation_id, 'generation/planning context session mismatch')

    normalized, source_lines, owned_lines = [], [], []
    spend_summaries = []
    pending_spend = None
    terminal = None
    pending_outer = False
    dispatch_started = False
    final_compiles = 0
    for line in content.splitlines():
        stripped = line.lstrip()
        prefix = stripped.split(None, 1)[0] if stripped else ''
        payload = stripped[len(prefix) + 1:]
        if prefix == 'owned_proof_rows':
            continue  # Strictly paired and reconciled below.
        relevant = prefix in GPU_PREFIXES or prefix in GENERATION_RECORDS
        if not relevant:
            require(not (prefix.startswith('owned_') and prefix.endswith('_report'))
                    and not prefix.startswith('owned_generation_'), 'unknown owned receipt prefix: ' + prefix)
            unknown = stripped if stripped.startswith('{') else payload
            if unknown.lstrip().startswith('{') and 'lattica-proving-stages-v1' in unknown:
                candidate = parse_record(unknown, prefix)
                require(candidate.get('schema') != 'lattica-proving-stages-v1',
                        'unknown proving receipt prefix: ' + prefix)
            continue
        require(line == stripped and stripped.startswith(prefix + ' ') and payload.startswith('{'),
                'invalid receipt framing: ' + prefix)
        value = parse_record(payload, prefix)
        if prefix == 'owned_generation_spend':
            require(terminal is None and pending_spend is not None,
                    'extra or reordered generation spend summary')
            generation_spend(value, pending_spend, len(spend_summaries), generation_id)
            spend_summaries.append(value)
            pending_spend = None
            continue
        if prefix == 'owned_generation_terminal':
            require(terminal is None and pending_spend is None and len(spend_summaries) == count,
                    'missing, duplicate or premature generation terminal')
            terminal = value
            continue
        entry = raw_report(value, prefix)
        normalized_line = 'proving_stage_report ' + payload
        normalized.append(normalized_line)
        if prefix == 'owned_generation_report':
            require(terminal is None and pending_spend is None and len(spend_summaries) < count,
                    'extra or reordered generation receipt')
            pending_spend = value
            continue
        require(terminal is not None, 'planning receipt precedes generation retirement')
        if pending_outer:
            require(entry == MACHINE_ENTRIES[1], 'outer proof receipt missing or reordered')
        if entry == MACHINE_ENTRIES[0]:
            pending_outer = True
        elif entry == MACHINE_ENTRIES[1]:
            require(pending_outer, 'outer proof has no preceding preprocessing receipt')
            pending_outer = False
        if prefix == 'proving_stage_report' and entry == PREPARATION_ENTRY:
            require(not dispatch_started, 'source preparation appeared after owned dispatch')
            source_lines.append(normalized_line)
        else:
            dispatch_started = True
        if prefix in OWNED_PREPARATION_PREFIXES:
            owned_lines.append(normalized_line)
        final_compiles += int(prefix == 'owned_final_compile_report')
    require(terminal is not None and pending_spend is None and not pending_outer,
            'incomplete generation or outer receipt sequence')
    require(final_compiles == count - 1, 'wrong final aggregate compiler receipt count')

    # Preserve every actual entry name. Prefix normalization is the sole
    # adaptation to the existing GPU-policy/stage validator.
    receipts = collect_gpu_receipts('\n'.join(normalized), native_entry_names=NATIVE_ENTRIES)
    source_receipts = collect_gpu_receipts('\n'.join(source_lines), native_entry_names=NATIVE_ENTRIES)
    owned_receipts = collect_gpu_receipts('\n'.join(owned_lines), native_entry_names=NATIVE_ENTRIES)
    native_entries = owned['native_proofs']
    require(type(native_entries) is list and len(native_entries) == len(NATIVE_ENTRIES),
            'wrong fixed native observation inventory')
    for entry, snapshot in zip(NATIVE_ENTRIES, native_entries):
        object_fields(snapshot, ('entry_point', 'totals', 'rows'), 'native observation')
        require(snapshot['entry_point'] == entry, 'native observation identity/order mismatch')
        report_totals(snapshot['totals'], entry_totals(receipts, entry), entry)
    require(receipts['native_reports'] == native_count
            and sum(item['totals']['reports'] for item in native_entries) == native_count,
            'native receipts differ from closed graph proof count')
    for entry, key in zip(MACHINE_ENTRIES, ('machine_preprocessing', 'machine_proofs')):
        report_totals(owned[key], entry_totals(receipts, entry), key)
        require(receipts['counts'][entry] == recursive_count,
                'recursive receipts differ from closed graph proof count')

    owned_preparation = object_fields(owned['witness_preparation'],
        ('reports', 'elapsed_ns', 'witness_completed_calls', 'witness_device_calls', 'witness_device_ns'),
        'owned.witness_preparation')
    observed_owned = entry_totals(owned_receipts, PREPARATION_ENTRY)
    report_totals({key: owned_preparation[key] for key in ('reports', 'elapsed_ns')},
                  observed_owned, 'owned.witness_preparation')
    witness_totals(owned_preparation, observed_owned, 'owned.witness_preparation')
    observed_source = entry_totals(source_receipts, PREPARATION_ENTRY)
    for key in ('calls', 'succeeded', 'complete_reports'):
        require(integer(source[key], 'source.' + key, positive=True) == observed_source['reports'],
                'source preparation receipt count mismatch')
    for key in ('native_cpu_calls', 'native_cpu_succeeded', 'failure_events'):
        require(integer(source[key], 'source.' + key) == 0, 'source context contains CPU work or failures')
    witness_totals(source, observed_source, 'source_preparation')
    source_seconds = seconds(source['seconds'], 'source_preparation.seconds')
    time_covered(observed_source['elapsed_ns'], source_seconds, observed_source['reports'], 'source_preparation')
    require(receipts['preparation_reports'] == observed_source['reports'] + observed_owned['reports'],
            'unaccounted preparation receipt')

    object_fields(terminal, ('schema', 'session_id', 'operations', 'session', 'stark_proofs', 'registrations'),
                  'owned_generation_terminal')
    require(terminal['schema'] == 'ringct-native-generation-terminal-v1'
            and integer(terminal['session_id'], 'terminal.session_id', positive=True) == generation_id,
            'generation terminal identity mismatch')
    for key in ('stark_proofs', 'registrations'):
        require(integer(terminal[key], 'terminal.' + key) == 0, 'generation terminal contains proving work')
    generation_numbers(generation, 'generation')
    generation_numbers(terminal['operations'], 'terminal.operations')
    require(terminal['operations'] == generation, 'generation terminal differs from actual snapshot')
    observed_generation = entry_totals(receipts, SPEND_ENTRY)
    require(integer(generation['spends'], 'generation.spends') == count
            and receipts['private_spend_reports'] == count, 'generation receipt inventory mismatch')
    witness_totals(generation, observed_generation, 'generation')
    generation_seconds = seconds(generation['seconds'], 'generation.seconds')
    time_covered(observed_generation['elapsed_ns'], generation_seconds, count, 'generation')
    require(integer(generation['managed_peak_bytes'], 'generation.managed_peak_bytes', positive=True)
            == max(item['managed_bytes'] for item in spend_summaries),
            'generation managed peak differs from actual spend evidence')
    first = spend_summaries[0]
    require(all(item['source_fingerprint'] == first['source_fingerprint']
                and item['kernel_source_sha256'] == first['kernel_source_sha256']
                for item in spend_summaries), 'generation source identities changed within the case')
    session = object_fields(terminal['session'], ('allocations', 'commits', 'managed_peak_bytes',
        'uploaded_bytes', 'downloaded_bytes', 'queue_drained', 'context_closed',
        'managed_live_bytes', 'host_tree_live_bytes'), 'generation terminal session')
    integer(session['allocations'], 'session.allocations', positive=True)
    for key in ('commits', 'managed_live_bytes', 'host_tree_live_bytes'):
        require(integer(session[key], 'session.' + key) == 0, 'generation session is not retired')
    for key in ('uploaded_bytes', 'downloaded_bytes'):
        integer(session[key], 'session.' + key)
    require(integer(session['managed_peak_bytes'], 'session.managed_peak_bytes', positive=True)
            <= MANAGED_DEVICE_BYTES and session['queue_drained'] is True
            and session['context_closed'] is True, 'generation session cleanup or peak mismatch')

    planning_ns = integer(report.get('generation_and_planning_ns'),
                          'generation_and_planning_ns', bits=128, positive=True)
    execution_ns = integer(report.get('proving_and_verification_ns'),
                           'proving_and_verification_ns', bits=128, positive=True)
    wrapper_seconds = generation_seconds + source_seconds
    tolerance = max(1e-9, (count + source['calls'] + 4) * math.ulp(wrapper_seconds))
    require(wrapper_seconds <= planning_ns / 1e9 + tolerance,
            'generation/source wrapper durations exceed complete planning interval')
    owned_ns = sum(entry_totals(receipts, entry)['elapsed_ns']
                   for entry in NATIVE_ENTRIES + MACHINE_ENTRIES) + observed_owned['elapsed_ns']
    owned_ns += identity_audit['totals']['elapsed_ns']
    require(owned_ns <= execution_ns, 'owned receipt durations exceed complete execution interval')

    row_audit = owned_workflow_row_receipts.validate(
        content, owned, NATIVE_ENTRIES, GPU_PREFIXES, parse_record)
    verification_auditor = (owned_workflow_verification_receipts if verification_mode == 'exact-dispatch-v1'
                            else owned_workflow_cpu_receipts)
    cpu_audit = verification_auditor.validate(content, report, NATIVE_PREFIXES, parse_record)
    return {'schema': 'ringct-owned-complete-case-receipts-v2',
            'identity_preprocessing': identity_audit,
        'cpu_verification': cpu_audit,
        'proof_rows': row_audit,
            'generation_session_id': generation_id, 'planning_session_id': planning_id,
            'gpu_receipts': receipts, 'source_preparation': observed_source,
            'owned_preparation': observed_owned, 'final_compile_reports': final_compiles,
            'generation_terminal_checked': True, 'completed_stage_receipts_checked': True,
            'native_cpu_calls': 0, 'cache_counters_used_for_proof_coverage': False}
