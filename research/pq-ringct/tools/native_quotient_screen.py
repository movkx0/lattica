"""Audit stage-local native proofs; this never qualifies workflow performance."""
import re
from owned_workflow_case_receipts import parse_record

SELECTOR = ('native_quotient_screen::'
            'native_quotient_compilation_and_execution_verify_small_and_large_shapes')
PREFIX = 'NATIVE_QUOTIENT_SCREEN '
ENVIRONMENT = 'LATTICA_RINGCT_NATIVE_QUOTIENT_SCREEN'
COMPLETE = ('NATIVE_QUOTIENT_SCREEN_COMPLETE rounds=2 cases_per_round=12 proofs=24 '
            'verified=24 mutations_rejected=24 complete_workflow=false')
STAGES = {'witness_trace', 'public_values', 'preprocessing', 'randomness', 'transform',
          'quotient', 'hiding', 'commitment', 'opening', 'transcript', 'grinding',
          'scalar', 'fri_fold', 'fri_query', 'final_polynomial'}


def require(value, message):
    if not value:
        raise ValueError('native quotient screen: ' + message)


def positive(value):
    return type(value) is int and 0 < value < 1 << 128


def validate(content):
    rows = [parse_record(line[len(PREFIX):], PREFIX) for line in content.splitlines()
            if line.startswith(PREFIX)]
    require(len(rows) == 24 and content.splitlines().count(COMPLETE) == 1,
            'missing complete proof inventory')
    require(len(re.findall(r'^test result: ok\. 1 passed; 0 failed;.*$', content, re.M)) == 1,
            'expected one passing screen test')
    shapes = [('aes', domain, blocks, blocks * 1024) for blocks in (8, 64) for domain in (17, 29)]
    shapes += [('affine', variant, count, count * 512) for count in (8, 64) for variant in range(4)]
    for ordinal, row in enumerate(rows):
        family, variant, count, height = shapes[ordinal % 12]
        require(row['schema'] == 'ringct-native-quotient-screen-v1'
                and row['round'] == ordinal // 12 and row['case'] == ordinal % 12
                and (row['family'], row['variant'], row['count'], row['rows']) ==
                    (family, variant, count, height), 'changed or reordered public shape')
        require(row['operation_host_bytes'] == 24 << 30
                and row['verified'] is True and row['mutation_rejected'] is True
                and row['public_synthetic_inputs'] is True and row['complete_workflow'] is False,
                'changed resource or acceptance scope')
        require(positive(row['proof_wall_ns']) and positive(row['verification_ns']), 'missing wall clocks')
        report = row['report']
        require(report['schema'] == 'lattica-proving-stages-v1'
                and report['policy'] == 'gpu_required' and report['succeeded'] is True
                and report['stage_coverage_complete'] is True
                and report['completion_rejected'] is False and report['observation_errors'] == 0
                and report['components'] == [], 'incomplete GPU proof report')
        require(report['entry_point'] == ('pq_aes_lane_native' if family == 'aes'
                                         else 'ringct_native_quotient_affine_screen'),
                'wrong native producer')
        capabilities = report['capabilities']
        require(capabilities['scope'] == 'proof_request'
                and capabilities['profile'] == 'block_v2_cubic'
                and capabilities['max_log_fri_arity'] == 1, 'changed native proof profile')
        require(positive(report['elapsed_ns']) and report['elapsed_ns'] <= row['proof_wall_ns'],
                'proof report exceeds enclosing wall clock')
        observations = report['observations']
        require(len(observations) == len(STAGES)
                and {o['stage'] for o in observations} == STAGES, 'incomplete arithmetic coverage')
        for observation in observations:
            require(observation['backend'] == 'open_cl'
                    and positive(observation['calls'])
                    and observation['calls'] == observation['completed_calls']
                    and positive(observation['device_calls'])
                    and observation['device_calls'] <= observation['completed_calls']
                    and positive(observation['device_ns']), 'missing completed device work')
    require(content.rfind(PREFIX) < content.index(COMPLETE) < content.index('test result: ok.'),
            'completion markers are out of order')
    return dict(schema='ringct-native-quotient-screen-audit-v1', proofs=24,
                independent_cpu_verifications=24, rejected_mutations=24,
                complete_workflow_qualified=False, measurements=rows)
