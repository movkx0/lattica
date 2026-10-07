"""Matched-pair promotion and isolated capacity/cadence research arithmetic.

These checks do not replace proof verification or turn capacity into measured
throughput. Production parameters and admission contracts are never edited.
"""
import hashlib
import json
import math
import statistics


def compare(pairs):
    if len(pairs) != 5:
        raise ValueError('promotion requires exactly five completed matched pairs')
    changes = []
    reasons = []
    seen_matches, seen_runs = set(), set()
    previous_finish = None
    boot_id = None
    contract = pairs[0]['control'].get('comparison_contract')
    for index, pair in enumerate(pairs):
        order = ['control', 'candidate'] if index % 2 == 0 else ['candidate', 'control']
        if pair.get('order') != order or not pair.get('match_id'):
            raise ValueError('matched pairs must alternate execution order and declare their match')
        if pair['match_id'] in seen_matches:
            raise ValueError('matched pair identifiers must be unique')
        seen_matches.add(pair['match_id'])
        for name in order:
            run = pair[name]
            capture = run.get('capture', {})
            identity = capture.get('run_id')
            start, finish = capture.get('started_monotonic_ns'), capture.get('finished_monotonic_ns')
            if (not isinstance(identity, str) or not identity or identity in seen_runs
                    or not capture.get('boot_id') or type(start) is not int or type(finish) is not int
                    or not 0 < start < finish):
                raise ValueError('each run requires a unique captured identity and complete time interval')
            seen_runs.add(identity)
            boot_id = boot_id or capture['boot_id']
            if capture['boot_id'] != boot_id or (previous_finish is not None and start < previous_finish):
                raise ValueError('captured runs must follow the declared alternating order without overlap in one boot')
            previous_finish = finish
            if run.get('comparison_contract') != contract:
                raise ValueError('all pairs must share one workload and resource contract')
        control, candidate = pair['control'], pair['candidate']
        for name, run in [('control', control), ('candidate', candidate)]:
            if (run.get('status') != 'succeeded' or run.get('cleanup_failure')
                    or run.get('post_seal_deadline_misses', 1) != 0
                    or run.get('resource_failures', 1) != 0
                    or run.get('accounting', {}).get('status') != 'complete'
                    or run['accounting'].get('failures', 1) != 0):
                reasons.append(f'pair {index + 1} {name}: correctness/resource/deadline gate')
        if (control.get('comparison_contract') is None
                or control.get('comparison_contract') != candidate.get('comparison_contract')):
            raise ValueError('pair workload, deadlines, resource assignment, and geometry must match')
        c = float(control['accounting']['user_transactions_per_minute'])
        n = float(candidate['accounting']['user_transactions_per_minute'])
        if c <= 0 or n < 0 or not all(math.isfinite(v) for v in (c, n)):
            raise ValueError('comparison needs finite delivered rates and a positive control')
        changes.append((n / c - 1) * 100)
    median = statistics.median(changes)
    improved = sum(change > 0 for change in changes)
    if median <= 0 or improved < 4:
        reasons.append('need a positive median improvement and at least four improved pairs')
    return {'schema_version': 1, 'eligible_for_performance_promotion': not reasons,
            'median_delivered_throughput_change_percent': median, 'improved_pairs': improved,
            'pair_changes_percent': changes, 'reasons': reasons, 'production_activation': False}


def research_profile(capacity, cycle_seconds, issuance_inputs):
    if (type(capacity) is not int or capacity not in (64, 128, 256, 512)
            or type(cycle_seconds) is not int or not 60 <= cycle_seconds <= 720
            or type(issuance_inputs) is not int or not 0 <= issuance_inputs < capacity):
        raise ValueError('research bounds: 64..512 power-of-two inputs, 60..720 seconds, explicit issuance')
    profile = {'namespace': 'lattica-protocol-research-v1', 'capacity': capacity,
               'tree_depth': capacity.bit_length() - 1, 'cycle_seconds': cycle_seconds,
               'issuance_inputs': issuance_inputs, 'root_bytes_bound': 2 * 1024 * 1024,
               'security_parameters': 'unchanged; complete-tree composition must be re-evaluated'}
    identity = hashlib.sha256(json.dumps(profile, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'schema_version': 1, 'proposal': profile, 'proposal_sha256': identity,
            'capacity_ceiling_user_transactions_per_hour': (capacity - issuance_inputs) * 3600 / cycle_seconds,
            'ceiling_is_measured_throughput': False, 'execution_enabled': False, 'production_activation': False,
            'required_validation': ['recursive closure and complete-tree security', 'new registry and profile identity',
                                    'Rust/Zig boundary vectors and count encoding', 'bounded body and root sizes',
                                    'issuance/emission policy', 'anchors, HTLC heights, reorgs and wallet retries',
                                    'full lifecycle matched pairs and sustained qualification'],
            'boundary_counts': sorted({1, 2, 3, capacity // 2, capacity - 1, capacity, capacity + 1}),
            'accepted_count_range': [1, capacity]}
