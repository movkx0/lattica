"""Accept serial identity clocks only when tied to verified recursive fixtures."""

import re
from owned_workflow_case_receipts import parse_record

SELECTOR = 'identity_preprocessing_screen::cpu_recursive_serial_identity_diagnostic'
PREFIX = 'SERIAL_IDENTITY_DIAGNOSTIC '
COMPLETE = 'SERIAL_IDENTITY_COMPLETE programs=5 gpu_oracles=1 verified=2 mutations_rejected=2 complete_workflow=false'
CLOCK = re.compile(r'bounded_cpu_identity_hash fields=(\d+) count_ns=(\d+) hash_and_framing_ns=(\d+) total_ns=(\d+)')
STAGES = {'witness_trace', 'preprocessing', 'lookup', 'quotient', 'transcript', 'grinding',
          'scalar', 'randomness', 'transform', 'hiding', 'commitment', 'opening', 'fri_fold',
          'fri_query', 'final_polynomial'}


def require(value, message):
    if not value:
        raise ValueError('serial identity diagnostic: ' + message)


def integer(value, minimum=0):
    return type(value) is int and minimum <= value < 1 << 128


def validate_proof(row, expected):
    if not expected:
        require(all(row.get(key) is None for key in ('proof_wall_ns', 'verification_ns', 'proof_report')),
                'unexpected proof measurement')
        return
    require(integer(row.get('proof_wall_ns'), 1) and integer(row.get('verification_ns'), 1),
            'missing proof or verification wall clock')
    report = row.get('proof_report')
    require(isinstance(report, dict), 'missing proof report')
    require(report.get('schema') == 'lattica-proving-stages-v1'
            and report.get('entry_point') == 'block_v2_registered_program'
            and report.get('policy') == 'gpu_required' and report.get('succeeded') is True
            and report.get('stage_coverage_complete') is True
            and report.get('completion_rejected') is False
            and report.get('observation_errors') == 0 and report.get('components') == [],
            'incomplete GPU proof report')
    require(report.get('capabilities', {}).get('scope') == 'registered_proof', 'wrong proof scope')
    require(integer(report.get('elapsed_ns'), 1) and report['elapsed_ns'] <= row['proof_wall_ns'],
            'proof clock reconciliation')
    observations = report.get('observations', [])
    require(len(observations) == len(STAGES) and {o['stage'] for o in observations} == STAGES,
            'incomplete arithmetic coverage')
    for observation in observations:
        require(observation['backend'] == 'open_cl' and integer(observation['calls'], 1)
                and observation['calls'] == observation['completed_calls']
                and integer(observation['device_calls'], 1)
                and observation['device_calls'] <= observation['completed_calls']
                and integer(observation['device_ns'], 1), 'incomplete GPU arithmetic')


def validate(content):
    active = None
    closed = None
    clocks = []
    rows = []
    quotient_shapes = []
    for line in content.splitlines():
        if line.startswith('bounded_gpu_quotient_specialization '):
            fields = dict(word.split('=', 1) for word in line.split()[1:] if '=' in word)
            if 'source_sha3' in fields:
                require(re.fullmatch('[0-9a-f]{64}', fields['source_sha3']) is not None,
                        'malformed quotient source digest')
                require(fields.get('selected') in ('true', 'false'), 'invalid specialization selection')
                quotient_shapes.append(dict(
                    selected=fields['selected'] == 'true', source_sha3=fields['source_sha3'],
                    **{key: int(fields[key]) for key in ('instructions', 'registers', 'private_bytes', 'build_ns')}))
        elif line.startswith('SERIAL_IDENTITY_BEGIN '):
            require(active is None and closed is None, 'overlapping registration')
            require(line == f'SERIAL_IDENTITY_BEGIN {len(rows)}', 'wrong registration order')
            active = len(rows)
            clocks = []
        elif line.startswith('bounded_cpu_identity_hash ') and active is not None:
            match = CLOCK.fullmatch(line)
            require(match is not None, 'malformed clock')
            clocks.append(tuple(map(int, match.groups())))
        elif line.startswith('SERIAL_IDENTITY_END '):
            require(active is not None and line == f'SERIAL_IDENTITY_END {active}', 'unmatched end')
            require(len(clocks) == 1, 'missing or duplicated clock; require gpu-tuning build')
            closed = active
            active = None
        elif line.startswith(PREFIX):
            require(active is None and closed == len(rows), 'result without completed registration')
            row = parse_record(line[len(PREFIX):], PREFIX)
            require(row.get('schema') == 'ringct-serial-cpu-identity-diagnostic-v1', 'wrong schema')
            require(type(row.get('program')) is int and row['program'] == closed < 5, 'wrong program')
            require(type(row.get('public_values')) is int and row['public_values'] == 46,
                    'wrong recursive public arity')
            require(row.get('complete_workflow') is False, 'component mislabeled as workflow')
            height = row.get('height')
            require(integer(height, 1) and height <= 1 << 20 and height & (height - 1) == 0, 'invalid height')
            require(integer(row.get('registration_ns'), 1), 'missing registration time')
            require(integer(row.get('cpu_identity_ns'), 1) and integer(row.get('gpu_preprocessing_ns'), 1)
                    and row['cpu_identity_ns'] + row['gpu_preprocessing_ns'] <= row['registration_ns'],
                    'registration clock reconciliation')
            require(row.get('gpu_reference_checked') is (closed == 0), 'GPU oracle coverage')
            for name in ('independent_cpu_verified_proof', 'changed_public_rejected'):
                require(row.get(name) is (closed < 2), 'proof verification coverage')
            validate_proof(row, closed < 2)
            identity = row.get('identity')
            require(isinstance(identity, list) and len(identity) == 4
                    and all(type(x) is int and 0 <= x < 0xffff_ffff_0000_0001 for x in identity),
                    'noncanonical identity')
            fields, count, hashing, total = clocks[0]
            require(integer(fields, 1) and integer(count) and integer(hashing, 1)
                    and integer(total, 1) and count + hashing == total <= row['cpu_identity_ns'],
                    'clock reconciliation')
            rows.append(dict(row, fields=fields, count_ns=count,
                             hash_and_framing_ns=hashing, total_hash_ns=total,
                             identity_overhead_ns=row['cpu_identity_ns'] - total))
            closed = None
    require(active is None and closed is None and len(rows) == 5, 'incomplete registrations')
    require(content.splitlines().count(COMPLETE) == 1, 'missing completion')
    total = sum(row['total_hash_ns'] for row in rows)
    count = sum(row['count_ns'] for row in rows)
    return {
        'schema': 'ringct-serial-cpu-identity-diagnostic-acceptance-v1',
        'programs': 5, 'gpu_oracles': 1, 'verified': 2, 'mutations_rejected': 2,
        'count_ns': count, 'hash_and_framing_ns': total - count, 'total_hash_ns': total,
        'count_fraction': count / total, 'rows': rows,
        'cpu_identity_ns': sum(row['cpu_identity_ns'] for row in rows),
        'identity_overhead_ns': sum(row['identity_overhead_ns'] for row in rows),
        'proof_wall_ns': sum(row['proof_wall_ns'] or 0 for row in rows),
        'quotient_device_ns': sum(observation['device_ns'] for row in rows
                                 for observation in (row['proof_report'] or {}).get('observations', [])
                                 if observation['stage'] == 'quotient'),
        'quotient_shapes': quotient_shapes,
        'representative_crypto_quotient_observed': sum(
            shape['instructions'] == 5315 and shape['registers'] == 256
            for shape in quotient_shapes) >= 2,
        'complete_workflow': False, 'performance_qualified': False,
    }
