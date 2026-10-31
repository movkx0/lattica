"""Audit actual owned-proof row receipts; never substitute planning maxima."""


ROW_FIELDS = frozenset(('schema', 'session_id', 'sequence', 'entry_point',
                        'active_rows', 'padded_rows', 'native_degree_bits'))
TOTAL_FIELDS = frozenset(('proofs', 'active_rows', 'padded_rows'))
MACHINE_ENTRY = 'block_v2_registered_program'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, name, bits=64):
    require(type(value) is int and 0 <= value < 1 << bits, 'invalid row integer: ' + name)
    return value


def fields(value, expected, name):
    require(type(value) is dict and set(value) == set(expected), 'wrong row fields: ' + name)
    return value


def add(totals, active, padded):
    totals['proofs'] = integer(totals['proofs'] + 1, 'proofs')
    totals['padded_rows'] = integer(totals['padded_rows'] + padded, 'padded sum', 128)
    if active is not None:
        totals['active_rows'] = integer(totals['active_rows'] + active, 'active sum', 128)


def compare(actual, observed, native, name):
    fields(actual, TOTAL_FIELDS, name)
    integer(actual['proofs'], name + '.proofs')
    integer(actual['padded_rows'], name + '.padded_rows', 128)
    if native:
        require(actual['active_rows'] is None, 'native active rows must remain unavailable')
    else:
        integer(actual['active_rows'], name + '.active_rows', 128)
    require(actual == observed, 'row totals do not match receipts: ' + name)


def validate(content, owned, native_entries, gpu_prefixes, parse_record):
    """Pair each row receipt with its immediately preceding successful proof report.

    The caller separately validates each stage report and the complete-case graph.
    Unstructured diagnostic lines may occur between the two records. No other
    structured proof/preparation/generation receipt may interrupt a pair.
    """
    session = integer(owned['session_id'], 'session_id')
    require(session > 0, 'zero row session')
    native = {entry: {'proofs': 0, 'active_rows': None, 'padded_rows': 0}
              for entry in native_entries}
    machine = {'proofs': 0, 'active_rows': 0, 'padded_rows': 0}
    sequence, pending = 0, None
    for line in content.splitlines():
        stripped = line.lstrip()
        prefix = stripped.split(None, 1)[0] if stripped else ''
        is_row = prefix == 'owned_proof_rows'
        require(not prefix.startswith('owned_proof_row') or is_row,
                'unknown owned row receipt prefix')
        is_stage = prefix in gpu_prefixes
        is_generation = prefix.startswith('owned_generation_')
        if not (is_row or is_stage or is_generation):
            unknown = stripped if stripped.startswith('{') else stripped[len(prefix) + 1:]
            if unknown.lstrip().startswith('{') and 'ringct-owned-proof-rows-v1' in unknown:
                candidate = parse_record(unknown, prefix)
                require(candidate.get('schema') != 'ringct-owned-proof-rows-v1',
                        'proof row schema under unknown receipt prefix')
            continue
        require(line == stripped and stripped.startswith(prefix + ' '),
                'malformed row or proof receipt line')
        payload = stripped[len(prefix) + 1:]
        require(payload.startswith('{'), 'malformed row or proof JSON framing')
        value = parse_record(payload, prefix)
        if not is_row:
            require(pending is None, 'proof row receipt missing or reordered')
            entry = value.get('entry_point')
            if is_stage and (entry in native or entry == MACHINE_ENTRY):
                pending = entry
            continue
        fields(value, ROW_FIELDS, 'receipt')
        require(value['schema'] == 'ringct-owned-proof-rows-v1', 'wrong proof row schema')
        require(pending is not None and value['entry_point'] == pending,
                'extra or mismatched proof row receipt')
        require(integer(value['session_id'], 'session_id') == session,
                'proof row session mismatch')
        require(integer(value['sequence'], 'sequence') == sequence,
                'proof row sequence mismatch')
        padded = integer(value['padded_rows'], 'padded_rows')
        require(padded > 0 and padded & (padded - 1) == 0, 'padded rows must be a power of two')
        active = value['active_rows']
        if pending in native:
            require(active is None, 'native active rows must remain unavailable')
            degree = integer(value['native_degree_bits'], 'native_degree_bits', 32)
            require(0 < degree < 64 and 1 << degree == 2 * padded,
                    'native proof degree does not match hiding-expanded trace rows')
            add(native[pending], None, padded)
        else:
            require(value['native_degree_bits'] is None, 'recursive receipt has native degree')
            integer(active, 'active_rows')
            require(padded >= 8 and active <= padded, 'invalid recursive active/padded rows')
            add(machine, active, padded)
        sequence = integer(sequence + 1, 'sequence')
        pending = None
    require(pending is None, 'terminal proof row receipt missing')
    require(integer(owned['row_receipts'], 'row_receipts') == sequence,
            'proof row receipt count mismatch')
    compare(owned['machine_rows'], machine, False, 'machine_rows')
    require(machine['proofs'] == owned['machine_proofs']['reports'],
            'recursive row count differs from proof report count')
    for entry in owned['native_proofs']:
        name = entry['entry_point']
        compare(entry['rows'], native[name], True, name)
        require(entry['rows']['proofs'] == entry['totals']['reports'],
                'native row count differs from proof report count')
    return {'schema': 'ringct-owned-proof-row-audit-v1', 'row_receipts': sequence,
            'machine_rows': machine, 'native_active_rows_available': False}
