#!/usr/bin/env python3
"""Compare independently audited identity screens without promoting production use."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import statistics

import identity_screen_report as screen

AUDITOR_SHA256 = 'cd50f04dfabd1351051ce6c6f033da21785d4c12b4452c588c1b4eba8f184807'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def summarize(audits, stage):
    """Input is the exact result of screen.audit, never unaudited report JSON."""
    require(stage in ('screening', 'matched'), 'unknown comparison stage')
    pairs = 1 if stage == 'screening' else 3
    require(len(audits) == 2 * pairs, 'wrong repetition count')
    reference = audits[0]['evidence']
    seen_records, seen_proofs = set(), set()
    previous_finish = None
    samples = []
    for index, audit in enumerate(audits):
        mode = ('baseline', 'receipt-v1')[index % 2]
        require(audit['schema'] == 'lattica-direct-ring-identity-evidence-audit-v1'
                and audit['source_executable_artifact_log_bound'] is True
                and audit['research_only'] is True
                and audit['complete_faithful_ringct_workflow'] is False
                and audit['performance_qualified'] is False, 'invalid audit scope')
        require(audit['mode'] == mode, 'expected alternating baseline and receipt')
        evidence, report = audit['evidence'], audit['screen']
        for key in ('executable_sha256', 'source_snapshot_sha256', 'physical_gpu_uuid',
                    'build_record_sha256', 'process_memory_max_bytes',
                    'process_memory_high_bytes', 'swap_limit_bytes'):
            require(evidence[key] == reference[key], 'comparison provenance differs: ' + key)
        record, proof = evidence['guard_record_sha256'], audit['file_sha256']['case-0/proof.bin']
        require(record not in seen_records and proof not in seen_proofs,
                'repeated run or proof artifact')
        seen_records.add(record)
        seen_proofs.add(proof)
        start, finish = (datetime.fromisoformat(evidence[key])
                         for key in ('started_utc', 'finished_utc'))
        require(start.utcoffset() is not None and finish.utcoffset() is not None
                and finish > start, 'invalid run interval')
        require(previous_finish is None or start >= previous_finish,
                'runs overlap or are out of chronological order')
        previous_finish = finish
        workflow = report['workflow']
        samples.append(dict(mode=mode, record=evidence['guard_record'], record_sha256=record,
            proof_sha256=proof, screen_ns=report['complete_single_case_screen_ns'],
            workflow_ns=workflow['complete_research_workflow_ns'],
            guard_wall_seconds=evidence['guard_wall_seconds'],
            host_peak_bytes=evidence['guarded_cgroup_host_peak_bytes'],
            prover_setup_ns=workflow['prover_setup_ns'],
            verifier_setup_ns=workflow['verifier_setup_ns'],
            cpu_verification_ns=workflow['cpu_verification_ns'],
            identity_execution=audit['actual_identity_execution']))
    metrics = {}
    for key in ('screen_ns', 'workflow_ns', 'guard_wall_seconds', 'host_peak_bytes',
                'prover_setup_ns', 'verifier_setup_ns', 'cpu_verification_ns'):
        baseline = statistics.median(row[key] for row in samples[::2])
        candidate = statistics.median(row[key] for row in samples[1::2])
        require(baseline > 0 and candidate > 0, 'nonpositive measurement')
        metrics[key] = dict(baseline_median=baseline, candidate_median=candidate,
                           reduction_percent=100 * (baseline - candidate) / baseline)
    return dict(schema='lattica-direct-ring-identity-comparison-v1', stage=stage,
        research_only=True, complete_faithful_ringct_workflow=False,
        n3_n4_aggregation_qualified=False, cryptographic_adoption_qualified=False,
        production_promotion_qualified=False, protocol_redesign_twofold_qualified=False,
        changed_witness_reuse_qualified=False, case_count=1, matched_pairs=pairs,
        performance_qualified=False,
        single_case_research_timing_threshold_met=(stage == 'matched'
            and metrics['workflow_ns']['reduction_percent'] >= 5
            and metrics['screen_ns']['reduction_percent'] >= 5),
        timing_boundary=audits[0]['screen']['timing_boundary'],
        limitations=[
            'One fixed research statement, one fresh proof per run, no recursive aggregate.',
            'Screen timer excludes final summary serialization and process launch; guard wall is the enclosing interval through launch and terminal checks.',
            'Screening is separate from three matched alternating pairs.',
            'No faithful RingCT, seven distinct receipt cases, N3/N4, different-witness reuse, asynchronous-failure or security-review qualification.'
        ], metrics=metrics, samples=samples)


def compare(records, stage, screening_records=None):
    auditor = Path(screen.__file__).resolve()
    require(hashlib.sha256(auditor.read_bytes()).hexdigest() == AUDITOR_SHA256,
            'identity auditor source changed')
    audits = [screen.audit(path.resolve()) for path in records]
    result = summarize(audits, stage)
    if stage == 'matched':
        require(screening_records is not None and len(screening_records) == 2,
                'matched comparison requires separate screening records')
        screened = [screen.audit(path.resolve()) for path in screening_records]
        summarize(screened, 'screening')
        combined = screened + audits
        require(len({item['evidence']['guard_record_sha256'] for item in combined}) == 8
                and len({item['file_sha256']['case-0/proof.bin'] for item in combined}) == 8,
                'screening reused as matched measurement')
        require(datetime.fromisoformat(screened[-1]['evidence']['finished_utc'])
                <= datetime.fromisoformat(audits[0]['evidence']['started_utc']),
                'matched runs preceded screening completion')
        for key in ('executable_sha256', 'source_snapshot_sha256', 'physical_gpu_uuid',
                    'build_record_sha256', 'process_memory_max_bytes',
                    'process_memory_high_bytes', 'swap_limit_bytes'):
            require(screened[0]['evidence'][key] == audits[0]['evidence'][key],
                    'screening provenance differs: ' + key)
        result['excluded_screening_records'] = [item['evidence']['guard_record'] for item in screened]
        result['excluded_screening_record_sha256'] = [item['evidence']['guard_record_sha256'] for item in screened]
    else:
        require(screening_records is None, 'screening cannot exclude earlier screening')
    result['comparison_tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result['identity_auditor_sha256'] = AUDITOR_SHA256
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', required=True, choices=('screening', 'matched'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--screening-records', type=Path, nargs=2)
    parser.add_argument('records', type=Path, nargs='+')
    args = parser.parse_args()
    result = compare(args.records, args.stage, args.screening_records)
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'output': str(args.output), 'stage': result['stage'],
                      'metrics': result['metrics']}))
