"""Exact original-quota projection evidence; no backend or proving qualification."""
import re

SELECTOR = ('component_tree::owned_shake::request_merge::source::capture::acceptance::'
            'parent::production::sequence::qualification::cpu_original_hashx_sequence_capacity')
PREFIX = 'ringct_hashx_sequence_'
HOST = 32 << 30
DEVICE = 8 << 30
NATIVE_HOST = 24 << 30
STARTUP_DEVICE = (64 << 20) + (32 + 22 + 32 + 8) * 8
U128_MAX = (1 << 128) - 1
SOURCE_FIXED = dict(native_outputs='10', native_attachments='10', retained_leaf_sources='5',
                    retained_parent_sources='4', original_compiler_bank='1', leaf_output_claims='5',
                    parent_output_claims='4', source_acceptance_claims='9', original_outer_sequence='true',
                    mode='capacity', native_dispatch_started='false', complete_ringct_workflow='false')
CAPACITY_FIXED = dict(native_proofs='0', recursive_proofs='0', wrong_request_and_ledger_refused='true',
                      original_claims_preserved='true', physical_backend_fit='false',
                      native_dispatch_started='false', complete_ringct_workflow='false')
TERMINAL_FIXED = dict(original_quota_released='true', current_host_bytes='0', current_device_bytes='0',
                      component_success='true', mode='capacity', mutation_checks_complete='false',
                      artifact_roundtrip_complete='false', complete_ringct_workflow='false')
SOURCE_NUMBERS = ('host_bytes', 'device_bytes')
CAPACITY_NUMBERS = ('original_claims_host_bytes', 'startup_host_bytes', 'startup_device_bytes',
                    'phase_wrappers_host_bytes', 'phase_wrappers_device_bytes', 'pcs_host_bytes',
                    'pcs_device_bytes', 'simultaneous_host_bytes', 'simultaneous_device_bytes', 'projection_ns')
TERMINAL_NUMBERS = ('peak_host_bytes', 'peak_device_bytes', 'component_through_destruction_ns')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def marker(content, suffix, fixed, numbers):
    name = PREFIX + suffix
    header = r'(?:test ' + re.escape(SELECTOR) + r' \.\.\. )?' if suffix == 'source_claims' else ''
    matches = list(re.finditer(r'^' + header + r'(?P<marker>' + name + r') (?P<fields>[^\n]+)$', content, re.M))
    require(content.count(name) == 1 and len(matches) == 1, 'missing or malformed ' + name)
    found = matches[0]
    pairs = found.group('fields').split(' ')
    require(all(re.fullmatch(r'[a-z_]+=[a-z0-9]+', item) for item in pairs), 'invalid marker fields')
    fields = dict(item.split('=') for item in pairs)
    require(len(fields) == len(pairs) and set(fields) == set(fixed) | set(numbers),
            'duplicate, missing or additional marker fields')
    require(all(fields[key] == value for key, value in fixed.items()), 'contradictory marker flags/counts')
    values = {}
    for key in numbers:
        raw = fields[key]
        require(re.fullmatch(r'0|[1-9][0-9]{0,38}', raw), 'noncanonical marker integer')
        value = int(raw)
        require(value <= (U128_MAX if key.endswith('_ns') else (1 << 64) - 1), 'marker integer overflow')
        values[key] = value
    return found.start('marker'), values


def validate_log(content, observation_ns):
    require(type(observation_ns) is int and 0 < observation_ns <= U128_MAX,
            'missing runner-owned monotonic observation')
    require(content.count(PREFIX) == 3, 'unexpected or duplicate combined-sequence evidence')
    require(not any(value in content for value in (
        'proving_stage_report', 'NATIVE_EXECUTION_RECEIPT', 'PUBLIC_HASH_EXECUTION',
        'OPENCL_OPT_RESULT', 'DIRECT_SPEND_RESULT', 'DIRECT_RING_RESULT', 'panicked at', 'FAILED')),
        'source projection emitted proving or workflow evidence')
    headers = list(re.finditer(r'^test (\S+) \.\.\. ([^\n]*)$', content, re.M))
    completions = list(re.finditer(r'^ok$', content, re.M))
    footers = list(re.finditer(
        r'^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; '
        r'(?:0|[1-9][0-9]*) filtered out; finished in [0-9]+\.[0-9]+s$', content, re.M))
    require(len(headers) == len(footers) == len(completions) == 1
            and headers[0].group(1) == SELECTOR
            and not re.match(r'^(?:ok|ignored)(?:$|[ ,])', headers[0].group(2))
            and content.count('test result:') == 1,
            'capacity projection requires exact passing test and footer')
    source_pos, source = marker(content, 'source_claims', SOURCE_FIXED, SOURCE_NUMBERS)
    capacity_pos, capacity = marker(content, 'capacity_complete', CAPACITY_FIXED, CAPACITY_NUMBERS)
    terminal_pos, terminal = marker(content, 'terminal', TERMINAL_FIXED, TERMINAL_NUMBERS)
    require(headers[0].start() < source_pos < capacity_pos < terminal_pos
            < completions[0].start() < footers[0].start(),
            'projection evidence is out of order')
    require(0 < source['host_bytes'] <= HOST and source['device_bytes'] == 0,
            'source claims exceed unchanged worker limits')
    require(capacity['original_claims_host_bytes'] == source['host_bytes'],
            'source original claims changed')
    require(capacity['startup_host_bytes'] > 8 << 30
            and capacity['phase_wrappers_host_bytes'] > 0
            and 0 < capacity['pcs_host_bytes'] <= NATIVE_HOST,
            'startup, wrapper or native host allowance changed')
    require(capacity['startup_device_bytes'] == STARTUP_DEVICE
            and capacity['phase_wrappers_device_bytes'] == 0
            and capacity['pcs_device_bytes'] == DEVICE - STARTUP_DEVICE,
            'original device quota pieces changed')
    remaining_host = HOST - source['host_bytes'] - capacity['startup_host_bytes'] - capacity['phase_wrappers_host_bytes']
    require(capacity['pcs_host_bytes'] == min(NATIVE_HOST, remaining_host),
            'native PCS projection does not use original remaining host budget')
    host = source['host_bytes'] + sum(capacity[key] for key in
        ('startup_host_bytes', 'phase_wrappers_host_bytes', 'pcs_host_bytes'))
    device = source['device_bytes'] + sum(capacity[key] for key in
        ('startup_device_bytes', 'phase_wrappers_device_bytes', 'pcs_device_bytes'))
    require(host == capacity['simultaneous_host_bytes'] <= HOST,
            'simultaneous original host accounting disagrees')
    require(device == capacity['simultaneous_device_bytes'] == DEVICE,
            'simultaneous original device accounting disagrees')
    require(host <= terminal['peak_host_bytes'] <= HOST
            and device <= terminal['peak_device_bytes'] <= DEVICE,
            'terminal peaks disagree with projection or limits')
    elapsed = terminal['component_through_destruction_ns']
    require(0 < capacity['projection_ns'] <= elapsed <= observation_ns,
            'projection timing disagrees with component cleanup or runner observation')
    return dict(scope='original-quota-projection-only', native_proofs=0, recursive_proofs=0,
                source_claims=source, quota_projection=capacity, terminal=terminal,
                original_quota_released=True, native_dispatch_started=False, physical_backend_fit=False,
                mutation_checks_complete=False, artifact_roundtrip_complete=False,
                complete_ringct_workflow=False, performance_qualified=False)
