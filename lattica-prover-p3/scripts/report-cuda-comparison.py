#!/usr/bin/env python3
"""Compare independently audited, uninstrumented recursive benchmark arms."""
import argparse
import json
import math
from pathlib import Path
import statistics

METRICS = ('whole_launcher_seconds', 'proof_observations_seconds')


def compare(report, baseline, candidate):
    if report.get('status') != 'passed' or report.get('instrumented') is not False:
        raise ValueError('comparison requires a passed, uninstrumented campaign')
    selected = {}
    for row in report['trials']:
        if row['phase'] != 'measured' or row['arm'] not in (baseline, candidate):
            continue
        if (row.get('status') != 'passed' or row.get('instrumented') is not False
                or row.get('cpu_root_audit_passed') is not True or row.get('workers_retired') is not True
                or row.get('fresh_recursive_proofs') != row['count'] or row.get('seed_proofs') != 0
                or row.get('block_capacity') != 128
                or any(v != 0 for v in row['memory_event_deltas'].values())):
            raise ValueError('sample lacks complete fresh proof, retirement or resource evidence')
        if any(not isinstance(row.get(m), (int, float)) or not math.isfinite(row[m]) or row[m] <= 0 for m in METRICS):
            raise ValueError('sample time must be finite and positive')
        key = row['count'], row['arm'], row['index']
        if key in selected:
            raise ValueError('duplicate sample index')
        selected[key] = row
    workloads, all_nonregressing, any_improvement, inconclusive = [], True, False, False
    for count in (4, 8):
        indices = sorted(index for n, arm, index in selected if n == count and arm == baseline)
        candidate_indices = sorted(index for n, arm, index in selected if n == count and arm == candidate)
        if indices != candidate_indices or len(indices) not in (5, 10):
            raise ValueError('each workload requires five or ten matched pairs')
        result = dict(count=count, pairs=len(indices), user_transactions=count*3//4, issuance_entries=count//4)
        for metric in METRICS:
            before = [selected[count, baseline, i][metric] for i in indices]
            after = [selected[count, candidate, i][metric] for i in indices]
            old, new = statistics.median(before), statistics.median(after)
            reductions = [100*(1-b/a) for a,b in zip(before,after)]
            reduction = 100*(1-new/old)
            wins = sum(b < a for a,b in zip(before,after))
            result[metric] = dict(baseline_median=old, candidate_median=new,
                                  median_reduction_percent=reduction, paired_reductions_percent=reductions,
                                  candidate_faster_pairs=wins)
            all_nonregressing &= reduction >= -2
            if metric == 'proof_observations_seconds':
                sufficient_wins = wins >= 4*len(indices)//5
                any_improvement |= reduction >= 2 and sufficient_wins
                inconclusive |= (reduction >= 2 and not sufficient_wins) or (
                    0 < reduction < 2 and sufficient_wins and min(reductions) < 2 < max(reductions))
        result['candidate_aggregation_equivalent_user_transactions_per_hour'] = (
            count*3//4*3600/result['whole_launcher_seconds']['candidate_median'])
        workloads.append(result)
    qualified = bool(any_improvement and all_nonregressing)
    return dict(schema='lattica-cuda-comparison-v1', baseline=baseline, candidate=candidate,
                qualified=qualified, repeat_recommended=bool(not qualified and inconclusive and len(indices)==5),
                rule='At least 2% lower median proof interval on an improving workload with >=80% paired wins; '
                     'no workload median regression over 2% in either proof interval or launcher time.',
                workloads=workloads,
                scope='Aggregation of retained wallet proofs; wallet generation, durable application and separate CPU audits excluded.')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('report', type=Path)
    ap.add_argument('--baseline', required=True)
    ap.add_argument('--candidate', required=True)
    ap.add_argument('--output', type=Path)
    args = ap.parse_args()
    result = json.dumps(compare(json.loads(args.report.read_text()), args.baseline, args.candidate), indent=2)+'\n'
    if args.output:
        with args.output.open('x') as stream:
            stream.write(result)
    else:
        print(result, end='')


if __name__ == '__main__':
    main()
