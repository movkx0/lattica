"""Audit emitted verification epochs without inventing missing observations.

The v1 outer epoch has no dispatch/source identity or CPU duration. Matching it
to the preceding actual proof and row receipt proves stream coverage only. It
cannot authenticate which nonfinal dispatch produced the proof. This audit is
therefore explicitly partial even when every emitted success receipt matches.
Artifact/mutation qualification remains final-aggregate only.
"""

NATIVE_FIELDS = frozenset(('preissue_ns', 'preparation_ns', 'startup', 'proving_ns',
    'retirement', 'cpu_verification_ns', 'independent_verification_complete'))
OUTER_FIELDS = frozenset(('startup', 'retirement', 'independent_verification_complete'))
PREPARATION_FIELDS = frozenset(('startup', 'preparation_ns', 'retirement', 'preparation_complete'))
FINAL_FIELDS = frozenset(('merge', 'first', 'count', 'active_rows', 'padded_rows',
    'recursive_proofs', 'compile_ns', 'setup_ns', 'proving_ns', 'cpu_verification_ns', 'qualification'))
QUALIFICATION_TIMES = ('encoding_ns', 'disk_round_trip_ns', 'decoding_ns',
    'decoded_cpu_verification_ns', 'canonical_encoding_ns', 'mutation_cpu_verification_ns', 'elapsed_ns')
QUALIFICATION_FLAGS = ('artifact_round_trip', 'public_mutation_rejected', 'proof_mutation_rejected')
QUALIFICATION_SCALARS = ('decoded_positive_checks', 'packet_bytes', 'proof_bytes',
    'file_device', 'file_inode', 'height', 'public_values')
QUALIFICATION_DIGESTS = ('packet_sha3_256', 'source_fingerprint',
    'compiled_source_fingerprint', 'batch_profile', 'context')


def require(condition, message):
    if not condition:
        raise ValueError('CPU verification receipts: ' + message)


def fields(value, expected, name):
    require(type(value) is dict and set(value) == set(expected), 'invalid fields: ' + name)
    return value


def integer(value, name, bits=64):
    require(type(value) is int and 0 <= value < 1 << bits, 'invalid integer: ' + name)
    return value


def add(left, right):
    return integer(left + right, 'summed duration', 128)


def successful_epoch(value, schema, expected_fields):
    fields(value, ('schema', 'ordinal', 'epoch'), schema)
    require(value['schema'] == schema, 'wrong epoch schema')
    integer(value['ordinal'], 'local ordinal')
    epoch = fields(value['epoch'], expected_fields, 'epoch')
    startup = fields(epoch['startup'], ('elapsed_ns', 'succeeded', 'retained_tree_host_bytes'), 'startup')
    integer(startup['elapsed_ns'], 'startup.elapsed_ns', 128)
    require(startup['succeeded'] is True, 'startup did not succeed')
    require(integer(startup['retained_tree_host_bytes'], 'startup.retained_tree_host_bytes')
            <= 32 << 30, 'startup retained host bytes exceed worker allowance')
    retirement = fields(epoch['retirement'], ('managed_live_bytes', 'managed_peak_bytes',
        'host_tree_live_bytes', 'lease_released'), 'retirement')
    for key in ('managed_live_bytes', 'host_tree_live_bytes'):
        require(integer(retirement[key], 'retirement.' + key) == 0, 'epoch has live storage')
    require(integer(retirement['managed_peak_bytes'], 'retirement.managed_peak_bytes') <= 8 << 30
            and retirement['lease_released'] is True, 'epoch peak or retirement mismatch')
    return epoch


def qualification(value, completed):
    fields(value, QUALIFICATION_TIMES + QUALIFICATION_FLAGS + QUALIFICATION_SCALARS
           + QUALIFICATION_DIGESTS, 'final qualification')
    for name in QUALIFICATION_TIMES:
        integer(value[name], 'qualification.' + name, 128)
    for name in QUALIFICATION_SCALARS:
        integer(value[name], 'qualification.' + name)
    for name in QUALIFICATION_DIGESTS:
        digest = value[name]
        require(type(digest) is list and len(digest) == 32, 'invalid qualification digest')
        for byte in digest:
            integer(byte, 'qualification digest byte', 8)
    for name in QUALIFICATION_FLAGS:
        require(value[name] is completed, 'wrong final qualification stage')
    if completed:
        require(value['decoded_positive_checks'] == 3, 'missing decoded positive checks')
        # These intervals are disjoint fields within qualification. Their sum
        # may be smaller than elapsed_ns because wrapper overhead is retained.
        duration = 0
        for name in QUALIFICATION_TIMES[:-1]:
            duration = add(duration, value[name])
        require(duration <= value['elapsed_ns'], 'qualification timing exceeds its wrapper')
    else:
        require(all(value[name] == 0 for name in QUALIFICATION_TIMES + QUALIFICATION_SCALARS)
                and all(value[name] == [0] * 32 for name in QUALIFICATION_DIGESTS),
                'qualification credited before final verification')


def final_stage(value, ordinal, count):
    fields(value, ('schema', 'ordinal', 'stage', 'report'), 'final stage')
    require(value['schema'] == 'ringct-owned-final-stage-v1', 'wrong final stage schema')
    require(integer(value['ordinal'], 'final ordinal') == ordinal, 'missing, duplicate or reordered final stage')
    expected = 'verify' if ordinal == 2 * (count - 1) else ('compile' if ordinal % 2 == 0 else 'outer')
    require(value['stage'] == expected, 'wrong final stage kind')
    report = fields(value['report'], FINAL_FIELDS, 'final stage report')
    for name in FINAL_FIELDS - {'qualification'}:
        integer(report[name], 'final.' + name, 128 if name.endswith('_ns') else 64)
    merge = count - 2 if expected == 'verify' else ordinal // 2
    require(report['merge'] == merge, 'wrong final merge identity')
    require(2 <= report['count'] <= count and report['first'] + report['count'] <= count,
            'invalid final merge coverage')
    require(0 < report['active_rows'] <= report['padded_rows'] <= 1 << 20
            and report['padded_rows'] & (report['padded_rows'] - 1) == 0,
            'invalid final row geometry')
    require(report['recursive_proofs'] == int(expected == 'outer'), 'wrong final proof credit')
    for name in (('setup_ns', 'proving_ns') if expected == 'compile'
                 else ('compile_ns',) if expected == 'outer'
                 else ('compile_ns', 'setup_ns', 'proving_ns')):
        require(report[name] == 0, 'inherited timing double counted in final stage')
    qualification(report['qualification'], expected == 'verify')
    if expected == 'verify':
        require((report['first'], report['count']) == (0, count), 'final verification omits transactions')
        q = report['qualification']
        require(add(q['decoded_cpu_verification_ns'], q['mutation_cpu_verification_ns'])
                <= report['cpu_verification_ns'], 'qualification CPU time exceeds final verification')
    return report


def validate(content, report, native_prefixes, parse_record):
    """Reconcile v1 receipts; return explicit missing timing/identity coverage."""
    native_epochs = {prefix.replace('_report', '_epoch'): prefix for prefix in native_prefixes}
    preparations = {'owned_group_report': ('owned_group_epoch', 'ringct-owned-group-epoch-v1'),
        'owned_final_compile_report': ('owned_final_compile_epoch', 'ringct-owned-final-compile-epoch-v1')}
    epochs = set(native_epochs) | {'owned_outer_epoch'} | {v[0] for v in preparations.values()}
    relevant = set(native_prefixes) | set(preparations) | epochs | {
        'owned_proof_rows', 'owned_final_stage', 'proving_stage_report'}
    owned = report['owned_observations']
    session_id = integer(owned['session_id'], 'planning session')
    count = integer(report['transactions'], 'transactions')
    require(count in (3, 4), 'requires N3 or N4')
    native = {entry['entry_point']: {'proofs': 0, 'cpu_verification_ns': 0}
              for entry in owned['native_proofs']}
    pending_proof = pending_preparation = pending_setup = None
    last_outer = last_compile = final_compile = final_outer = None
    next_sequence = recursive = final_ordinal = preparation_count = 0
    final_times = dict.fromkeys(('compile', 'outer', 'verify'), 0)
    final_timed_proofs = 0
    for line in content.splitlines():
        stripped = line.lstrip()
        prefix = stripped.split(None, 1)[0] if stripped else ''
        payload = stripped[len(prefix) + 1:]
        if prefix not in relevant:
            require(not (prefix.startswith('owned_') and prefix.endswith('_epoch')),
                    'unknown epoch prefix: ' + prefix)
            unknown = stripped if stripped.startswith('{') else payload
            if unknown.lstrip().startswith('{') and ('ringct-owned-' in unknown
                    and ('-epoch-v' in unknown or 'final-stage-v' in unknown)):
                candidate = parse_record(unknown, prefix)
                require(candidate.get('schema') not in
                        ('ringct-owned-native-epoch-v1', 'ringct-owned-source-native-epoch-v1',
                         'ringct-owned-outer-epoch-v1', 'ringct-owned-group-epoch-v1',
                         'ringct-owned-final-compile-epoch-v1', 'ringct-owned-final-stage-v1'),
                        'unknown verification receipt prefix')
            continue
        require(line == stripped and stripped.startswith(prefix + ' ') and payload.startswith('{'),
                'invalid framing: ' + prefix)
        value = parse_record(payload, prefix)
        prior_outer, prior_compile = last_outer, last_compile
        last_outer = last_compile = None
        if pending_proof is not None:
            proof_prefix, proof, row, setup = pending_proof
            if row is None:
                require(prefix == 'owned_proof_rows', 'proof missing immediately following row receipt')
                require(value.get('entry_point') == proof['entry_point']
                        and integer(value.get('session_id'), 'row session') == session_id
                        and integer(value.get('sequence'), 'row sequence') == next_sequence,
                        'proof/row identity mismatch')
                next_sequence += 1
                pending_proof = proof_prefix, proof, value, setup
                continue
            is_native = proof_prefix in native_prefixes
            expected = proof_prefix.replace('_report', '_epoch') if is_native else 'owned_outer_epoch'
            require(prefix == expected, 'proof missing, reordered or wrong-family verification epoch')
            if is_native:
                source_epoch = prefix != 'owned_native_epoch'
                schema = 'ringct-owned-source-native-epoch-v1' if source_epoch else 'ringct-owned-native-epoch-v1'
                epoch = successful_epoch(value, schema, NATIVE_FIELDS | ({'source'} if source_epoch else set()))
                if source_epoch:
                    # Descriptor shape is diagnostic only: v1 has no member or
                    # operation fingerprint against which to authenticate it.
                    require(type(epoch['source']) in (str, dict), 'missing native source descriptor')
                for name in ('preissue_ns', 'preparation_ns', 'proving_ns', 'cpu_verification_ns'):
                    integer(epoch[name], name, 128)
                require(epoch['proving_ns'] == proof['elapsed_ns'], 'native proving time identity mismatch')
                totals = native[proof['entry_point']]
                totals['proofs'] += 1
                totals['cpu_verification_ns'] = add(totals['cpu_verification_ns'], epoch['cpu_verification_ns'])
            else:
                epoch = successful_epoch(value, 'ringct-owned-outer-epoch-v1', OUTER_FIELDS)
                recursive += 1
                last_outer = value['ordinal'], row, setup, proof
            require(epoch['independent_verification_complete'] is True, 'independent verification incomplete')
            pending_proof = None
            continue
        if pending_preparation is not None:
            preparation_prefix, preparation = pending_preparation
            expected, schema = preparations[preparation_prefix]
            require(prefix == expected, 'preparation missing or wrong-family epoch')
            epoch = successful_epoch(value, schema, PREPARATION_FIELDS)
            integer(epoch['preparation_ns'], 'preparation_ns', 128)
            require(epoch['preparation_complete'] is True, 'preparation incomplete')
            preparation_count += 1
            if preparation_prefix == 'owned_final_compile_report':
                last_compile = value['ordinal']
            pending_preparation = None
            continue
        if prior_compile is not None:
            require(prefix == 'owned_final_stage' and value.get('stage') == 'compile',
                    'missing final compile stage after epoch')
        if pending_setup is not None:
            require(prefix == 'proving_stage_report' and value.get('entry_point') == 'block_v2_registered_program',
                    'recursive setup missing proof')
        if prefix in native_prefixes:
            require(value['entry_point'] in native_prefixes[prefix], 'native family mismatch')
            pending_proof = prefix, value, None, None
        elif prefix in preparations:
            pending_preparation = prefix, value
        elif prefix == 'proving_stage_report':
            entry = value.get('entry_point')
            if entry == 'block_v2_preprocessing':
                pending_setup = value
            elif entry == 'block_v2_registered_program':
                require(pending_setup is not None, 'recursive proof missing setup')
                pending_proof = prefix, value, None, pending_setup
                pending_setup = None
        elif prefix == 'owned_final_stage':
            measured = final_stage(value, final_ordinal, count)
            stage = value['stage']
            if stage == 'compile':
                require(prior_compile == final_ordinal, 'final compile stage missing matching epoch')
                final_compile = measured
            elif stage == 'outer':
                require(prior_outer is not None and prior_outer[0] == final_ordinal,
                        'final outer stage missing matching verified proof')
                _, row, setup, proof = prior_outer
                require(final_compile is not None and all(measured[name] == final_compile[name]
                        for name in ('merge', 'first', 'count', 'active_rows', 'padded_rows')),
                        'final compiled/outer identity mismatch')
                require(all(measured[name] == row[name] for name in ('active_rows', 'padded_rows'))
                        and measured['setup_ns'] == setup['elapsed_ns']
                        and measured['proving_ns'] == proof['elapsed_ns'], 'final outer proof receipt mismatch')
                final_outer = measured
                final_timed_proofs += 1
            else:
                require(final_outer is not None and all(measured[name] == final_outer[name]
                        for name in ('merge', 'first', 'count', 'active_rows', 'padded_rows')),
                        'final verified root identity mismatch')
                require(integer(report.get('final_cpu_verification_ns'), 'final_cpu_verification_ns', 128)
                        == measured['cpu_verification_ns'], 'final CPU summary mismatch')
                require(report.get('qualification_scope') == 'final-aggregate'
                        and report.get('final_qualification') == measured['qualification'],
                        'final qualification summary mismatch')
            final_times[stage] = add(final_times[stage], measured['cpu_verification_ns'])
            final_ordinal += 1
        else:
            require(False, 'extra, duplicate or reordered epoch/row receipt: ' + prefix)
    require(pending_proof is None and pending_preparation is None and pending_setup is None
            and last_compile is None, 'incomplete terminal receipt sequence')
    require(final_ordinal == 2 * (count - 1) + 1, 'missing final verification stage')
    for item in owned['native_proofs']:
        require(native[item['entry_point']]['proofs'] == item['totals']['reports'],
                'native verification count differs from actual proof count')
    require(sum(item['proofs'] for item in native.values()) == report['native_proofs']
            and recursive == report['recursive_proofs'], 'verified proof coverage mismatch')
    known_ns = 0
    for value in [item['cpu_verification_ns'] for item in native.values()] + list(final_times.values()):
        known_ns = add(known_ns, value)
    require(known_ns <= integer(report['proving_and_verification_ns'], 'execution_ns', 128),
            'known CPU verification exceeds complete execution interval')
    return {'schema': 'ringct-owned-cpu-verification-receipts-v1',
        'coverage': 'existing-format-partial', 'proof_epoch_coverage_complete': True,
        'native_by_entry': native, 'recursive_proofs_verified': recursive,
        'preparation_epochs': preparation_count, 'final_stage_cpu_verification_ns': final_times,
        'known_cpu_verification_ns': known_ns, 'complete_cpu_verification_ns': None,
        'recursive_proofs_with_cpu_timing': final_timed_proofs,
        'recursive_proofs_without_cpu_timing': recursive - final_timed_proofs,
        'nonfinal_recursive_cpu_verification_ns': None,
        'exact_dispatch_identity_coverage_complete': False,
        'source_member_request_identity_authenticated': False,
        'local_epoch_ordinals_used_as_global_identities': False,
        'artifact_mutation_qualification_scope': 'final-aggregate'}
