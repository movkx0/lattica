#!/usr/bin/env python3
"""Summarize an audited complete workflow; this is not an acceptance auditor."""
import argparse
import json
from pathlib import Path

import opencl_private_spend_validate as guard


def metrics(record):
    result = record['correctness_result']
    guard.validate_result(result)
    guard.validate_experiments(result, record)
    measured = guard.validate_measurement(result, record)
    guard.require(record.get('status') == 'passed' and record.get('error') is None
                  and record.get('all_subprocesses_terminal_and_reaped') is True,
                  'workflow lacks terminal guard acceptance')
    context, cases = result['context'], result['cases']
    operations = context['operations']
    native = recursive_children = merges = 0
    case_metrics = []
    for case in cases:
        counts = {name: family['fresh_proofs'] for name, family in case['cache']['families'].items()}
        case_native = sum(count for name, count in counts.items() if name != 'outer')
        case_merges = len(case['merges'])
        native += case_native
        recursive_children += counts['outer']
        merges += case_merges
        case_metrics.append({
            'transactions': case['count'], 'native_stark_proofs': case_native,
            'recursive_transaction_proofs': counts['outer'], 'recursive_batch_proofs': case_merges,
            'fresh_proofs_by_family': counts,
            'active_workflow_seconds': case.get('timing', {}).get('active_wall_seconds'),
            'artifact_bytes': case.get('artifact', {}).get('bytes'),
        })
    guard.require(native == operations['native_gpu_succeeded'], 'native proof totals differ')
    guard.require(recursive_children + merges == operations['prove_succeeded'], 'recursive proof totals differ')
    return {
        'schema': 'pq-ringct-audited-workflow-metrics-v1',
        'scope': 'fresh_end_to_end_correctness_workflow',
        'experiments': guard.experiment_selection(record),
        'measurement': measured, 'cases': case_metrics,
        'proofs': {'native_stark': native, 'recursive_transaction': recursive_children,
                   'recursive_batch': merges, 'total_stark': native + recursive_children + merges},
        'timing_seconds': {
            'registration_preprocessing': context['registration_seconds'],
            'registration_and_verifier_setup': context.get('registration_setup_seconds'),
            'native_private_spend': operations['native_spend_seconds'],
            'witness_preparation': operations['witness_preparation_seconds'],
            'native_stark_calls': operations['native_gpu_seconds'],
            'recursive_stark_calls': operations['prove_seconds'],
            'worker_cpu_verification': operations.get('verify_seconds'),
            'cpu_post_shutdown_artifact_decode_verify': sum(
                case.get('timing', {}).get('cpu_post_shutdown_artifact_decode_verify_seconds', 0)
                for case in cases),
        },
        'timing_scope': 'Host wall timers may include setup and waits. CPU verification is scoped to the worker and post-shutdown artifacts; these are not all CPU work.',
        'cache': {key: context.get(key) for key in (
            'registrations', 'prepared_cache_hits', 'metadata_cache_hits', 'metadata_evictions',
            'metadata_entries', 'maximum_metadata_entries', 'metadata_cache_payload_bytes',
            'identity_hint_hits', 'identity_receipt_entries', 'identity_receipt_cache_bytes')},
        'geometry': {
            'registered_active_rows': context.get('registered_active_rows'),
            'registered_padded_rows': context.get('registered_padded_rows'),
            'registered_row_scope': context.get('registered_row_scope'),
            'prove_active_rows': operations.get('prove_active_rows'),
            'prove_padded_rows': operations.get('prove_padded_rows'),
            'prove_row_scope': operations.get('prove_row_scope'),
        },
        'memory': {
            'managed_gpu_peak_bytes': context['session_finish']['managed_peak_bytes'],
            'process_cgroup_peak_bytes': record.get('terminal_state', {}).get('MemoryPeak'),
            'process_cap_bytes': record['memory_max_bytes'],
            'driver_limits': guard.driver_limits(record),
            'gpu_context_reserve_bytes': record['environment'].get('LATTICA_V2_GPU_CONTEXT_BYTES'),
            'cgroup_swap_limit_bytes': record.get('terminal_state', {}).get('MemorySwapMax'),
        },
        'performance_qualified': False,
        'limitations': ['No relative speedup established by one run.',
                        'Null measurements were not observed.',
                        'Managed GPU memory and context reserve do not measure total physical VRAM.'],
    }


def audited_metrics(envelope_path):
    envelope = json.loads(envelope_path.read_text())
    guard.require(envelope.get('schema') == 'pq-r4-terminal-acceptance-envelope-v1'
                  and envelope.get('full_correctness_accepted') is True
                  and envelope.get('benchmark_accepted') is True,
                  'accepted complete benchmark envelope required')
    record_path = Path(envelope['guard'])
    guard.require(guard.sha(record_path) == envelope['guard_sha256'], 'guard changed since audit')
    record = json.loads(record_path.read_text())
    guard.require(guard.sha(record['raw_log']) == envelope['complete_log_sha256']
                  == record['raw_log_sha256'], 'complete log changed since audit')
    bindings = envelope['audit_evidence']
    guard.require(set(bindings) == {'receipts', 'case-v2', 'native', 'n3'}, 'four independent audits required')
    for name, binding in bindings.items():
        path = Path(binding['path'])
        guard.require(guard.sha(path) == binding['sha256'], 'audit changed: ' + name)
        audit = json.loads(path.read_text())
        guard.require(audit.get('log_sha256', audit.get('cutoff_sha256')) == record['raw_log_sha256'],
                      'audit bound to a different log: ' + name)
        if name in ('native', 'n3'):
            guard.require(audit.get('accepted') is True, 'audit not accepted: ' + name)
        if name == 'native':
            guard.require(audit.get('anomalies') == {} and audit.get('minimum_device_calls') == 31,
                          'native audit mismatch')
        elif name == 'case-v2':
            guard.require(audit.get('targeted_checks_passed') is True and audit.get('anomaly_counts') == {},
                          'case audit mismatch')
        elif name == 'receipts':
            guard.require(audit.get('anomaly_samples') == [] and not any(
                key.startswith('anomaly_') and value for key, value in audit['counts'].items()),
                'receipt audit mismatch')
    report = metrics(record)
    report['provenance'] = {'envelope': str(envelope_path), 'envelope_sha256': guard.sha(envelope_path),
                            'guard_sha256': envelope['guard_sha256'], 'audit_evidence': bindings}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--acceptance-envelope', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = audited_metrics(args.acceptance_envelope)
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'output': str(args.output), 'measurement': report['measurement'], 'proofs': report['proofs']}))


if __name__ == '__main__':
    main()
