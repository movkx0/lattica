"""Exact CPU root-check quota projection; no proof or mutation qualification."""
import re

SELECTOR = ('component_tree::owned_shake::request_merge::source::capture::acceptance::'
            'parent::production::sequence::qualification::'
            'cpu_original_hashx_sequence_root_public_capacity')
ROOT_CLAIMS = 'ringct_hashx_root_public_recheck_claims'
SOURCE_CLAIMS = 'ringct_hashx_sequence_source_claims'
CAPACITY_COMPLETE = 'ringct_hashx_sequence_capacity_complete'
TERMINAL = 'ringct_hashx_sequence_terminal'
MARKERS = (ROOT_CLAIMS, SOURCE_CLAIMS, CAPACITY_COMPLETE, TERMINAL)
HOST = 32 << 30
DEVICE = 8 << 30
NATIVE_HOST = 24 << 30
STARTUP_DEVICE = (64 << 20) + (32 + 22 + 32 + 8) * 8
U128_MAX = (1 << 128) - 1

ROOT_FIXED = dict(cpu_heights='18', planned_public_probes='46', mode='root-public-capacity',
                  actual_root_public_probes='0', native_dispatch_started='false',
                  complete_ringct_workflow='false')
SOURCE_FIXED = dict(native_outputs='10', native_attachments='10', retained_leaf_sources='5',
                    retained_parent_sources='4', original_compiler_bank='1', leaf_output_claims='5',
                    parent_output_claims='4', source_acceptance_claims='9', original_outer_sequence='true',
                    mode='root-public-capacity', native_dispatch_started='false',
                    complete_ringct_workflow='false')
CAPACITY_FIXED = dict(native_proofs='0', recursive_proofs='0', wrong_request_and_ledger_refused='true',
                      original_claims_preserved='true', physical_backend_fit='false',
                      native_dispatch_started='false', complete_ringct_workflow='false')
TERMINAL_FIXED = dict(original_quota_released='true', current_host_bytes='0', current_device_bytes='0',
                      component_success='false', mode='root-public-capacity', mutation_checks_complete='false',
                      artifact_roundtrip_complete='false', complete_ringct_workflow='false')
ROOT_NUMBERS = ('verifier_host_bytes', 'caller_host_bytes', 'total_host_bytes')
SOURCE_NUMBERS = ('host_bytes', 'device_bytes')
CAPACITY_NUMBERS = ('original_claims_host_bytes', 'startup_host_bytes', 'startup_device_bytes',
                    'phase_wrappers_host_bytes', 'phase_wrappers_device_bytes', 'pcs_host_bytes',
                    'pcs_device_bytes', 'simultaneous_host_bytes', 'simultaneous_device_bytes', 'projection_ns')
TERMINAL_NUMBERS = ('peak_host_bytes', 'peak_device_bytes', 'component_through_destruction_ns')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def marker(content, name, fixed, numbers):
    header = r'(?:test ' + re.escape(SELECTOR) + r' \.\.\. )?' if name == ROOT_CLAIMS else ''
    found = list(re.finditer(r'^' + header + r'(?P<marker>' + name + r') (?P<fields>[^\n]+)$', content, re.M))
    require(content.count(name) == 1 and len(found) == 1, 'missing or malformed ' + name)
    found = found[0]
    pairs = found.group('fields').split(' ')
    # Only the exact fixed mode uses hyphens; all numeric fields are checked
    # separately below, so a signed or noncanonical integer cannot pass.
    require(all(re.fullmatch(r'[a-z_]+=[a-z0-9-]+', item) for item in pairs),
            'invalid root-capacity marker fields')
    fields = dict(item.split('=') for item in pairs)
    require(len(fields) == len(pairs) and set(fields) == set(fixed) | set(numbers),
            'duplicate, missing or additional root-capacity marker fields')
    require(all(fields[key] == value for key, value in fixed.items()),
            'contradictory root-capacity marker flags/counts')
    values = {}
    for key in numbers:
        require(re.fullmatch(r'0|[1-9][0-9]{0,38}', fields[key]),
                'noncanonical root-capacity marker integer')
        value = int(fields[key])
        require(value <= (U128_MAX if key.endswith('_ns') else (1 << 64) - 1),
                'root-capacity marker integer overflow')
        values[key] = value
    return found.start('marker'), values


def valid_header_payload(payload):
    if payload == '' or payload.startswith(ROOT_CLAIMS + ' '):
        return True
    # libtest's prefix may share its line with this maintained compiler
    # diagnostic. proof_inputs.rs pins the growth rule and eight-byte Val.
    number = r'(0|[1-9][0-9]{0,19})'
    growth = re.fullmatch(r'bounded_proof_input_growth old_values=' + number
                         + r' new_values=' + number + r' live_bytes=' + number
                         + r' value_limit=' + number, payload)
    if growth is None:
        return False
    old, new, live, limit = map(int, growth.groups())
    return (0 < limit <= 1 << 20 and 0 <= old < new <= limit
            and new == min(max(old * 2, 4), limit) and live == (old + new) * 8)


def validate_log(content, observation_ns):
    require(type(observation_ns) is int and 0 < observation_ns <= U128_MAX,
            'missing runner-owned root-capacity observation')
    require(type(content) is str, 'root-capacity log is not text')
    names = re.findall(r'\bringct_[A-Za-z0-9_]+', content)
    require(len(names) == len(MARKERS) and set(names) == set(MARKERS),
            'foreign, missing or duplicate root-capacity evidence')
    require(not any(value in content for value in (
        'proving_stage_report', 'NATIVE_EXECUTION_RECEIPT', 'PUBLIC_HASH_EXECUTION',
        'OPENCL_OPT_RESULT', 'DIRECT_SPEND_RESULT', 'DIRECT_RING_RESULT', 'panicked at', 'FAILED',
        'fallback=true', 'retry=true')),
        'root-capacity projection emitted proof, workflow or failure evidence')
    headers = list(re.finditer(r'^test (\S+) \.\.\. ([^\n]*)$', content, re.M))
    completions = list(re.finditer(r'^ok$', content, re.M))
    footers = list(re.finditer(
        r'^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; '
        r'(?:0|[1-9][0-9]*) filtered out; finished in [0-9]+\.[0-9]+s$', content, re.M))
    require(len(headers) == len(footers) == len(completions) == 1
            and headers[0].group(1) == SELECTOR and valid_header_payload(headers[0].group(2))
            and content.count('test result:') == 1,
            'root-capacity requires its exact passing isolated test and footer')
    root_pos, root = marker(content, ROOT_CLAIMS, ROOT_FIXED, ROOT_NUMBERS)
    source_pos, source = marker(content, SOURCE_CLAIMS, SOURCE_FIXED, SOURCE_NUMBERS)
    capacity_pos, capacity = marker(content, CAPACITY_COMPLETE, CAPACITY_FIXED, CAPACITY_NUMBERS)
    terminal_pos, terminal = marker(content, TERMINAL, TERMINAL_FIXED, TERMINAL_NUMBERS)
    require(headers[0].start() < root_pos < source_pos < capacity_pos < terminal_pos
            < completions[0].start() < footers[0].start(), 'root-capacity evidence is out of order')
    require(0 < source['host_bytes'] <= HOST and source['device_bytes'] == 0,
            'root-capacity source claims exceed unchanged worker limits')
    require(root['verifier_host_bytes'] > 0 and root['caller_host_bytes'] > (64 << 10)
            and root['verifier_host_bytes'] + root['caller_host_bytes'] == root['total_host_bytes']
            and root['total_host_bytes'] <= source['host_bytes'],
            'root recheck original reservation is incomplete or not included in source claims')
    require(capacity['original_claims_host_bytes'] == source['host_bytes'],
            'root-capacity original source claims changed')
    require(capacity['startup_host_bytes'] > (8 << 30)
            and capacity['phase_wrappers_host_bytes'] > 0
            and 0 < capacity['pcs_host_bytes'] <= NATIVE_HOST,
            'root-capacity startup, wrapper or native host allowance changed')
    require(capacity['startup_device_bytes'] == STARTUP_DEVICE
            and capacity['phase_wrappers_device_bytes'] == 0
            and capacity['pcs_device_bytes'] == DEVICE - STARTUP_DEVICE,
            'root-capacity original device quota pieces changed')
    remaining_host = (HOST - source['host_bytes'] - capacity['startup_host_bytes']
                      - capacity['phase_wrappers_host_bytes'])
    require(capacity['pcs_host_bytes'] == min(NATIVE_HOST, remaining_host),
            'root-capacity PCS projection does not use original remaining host allowance')
    host = source['host_bytes'] + sum(capacity[key] for key in
        ('startup_host_bytes', 'phase_wrappers_host_bytes', 'pcs_host_bytes'))
    device = source['device_bytes'] + sum(capacity[key] for key in
        ('startup_device_bytes', 'phase_wrappers_device_bytes', 'pcs_device_bytes'))
    require(host == capacity['simultaneous_host_bytes'] <= HOST,
            'root-capacity simultaneous host accounting disagrees')
    require(device == capacity['simultaneous_device_bytes'] == DEVICE,
            'root-capacity simultaneous device accounting disagrees')
    require(host <= terminal['peak_host_bytes'] <= HOST
            and device <= terminal['peak_device_bytes'] <= DEVICE,
            'root-capacity terminal peaks disagree with projection or limits')
    elapsed = terminal['component_through_destruction_ns']
    require(0 < capacity['projection_ns'] <= elapsed <= observation_ns,
            'root-capacity timing disagrees with cleanup or runner observation')
    return dict(schema='ringct-hashx-root-public-capacity-v1', scope='root-public-quota-projection-only',
                cpu_heights=18, planned_public_probes=46, actual_root_public_probes=0, positive_checks=0,
                native_proofs=0, recursive_proofs=0, stage_receipts=0, root_recheck_claims=root,
                source_claims=source, quota_projection=capacity, terminal=terminal,
                original_quota_released=True, owner_quota_cleanup_complete=True,
                process_engine_device_audit_complete=False, native_dispatch_started=False,
                physical_backend_fit=False, actual_proving_fit=False, root_public_recheck_complete=False,
                raw_proof_mutation_checks_complete=False, interior_mutation_checks_complete=False,
                mutation_checks_complete=False, artifact_roundtrip_complete=False,
                complete_ringct_workflow=False, performance_qualified=False)
