"""Produce source/device-bound layout costs from matched successful screens.

Each pair needs one first-request observation plus at least three warm requests.
The Rust driver applies the 10% median-gain threshold; costs never admit proofs.
"""
import argparse
import json
from pathlib import Path
import statistics
from gpu_aggregation_profile import require


def matched_cost(baseline, candidate):
    for record in (baseline, candidate):
        require(record.get('status') == 'passed' and record.get('gpu_aggregation_acceptance'), 'screen did not pass its guard')
    a, b = (r['gpu_aggregation_acceptance'] for r in (baseline, candidate))
    for row in (a, b):
        require(row['options']['command'] == 'screen' and row['report']['verified']
                and row['report']['complete_aggregation'] is False, 'only verified subtree screens provide grouping costs')
    require(a['options']['profile'] == 'legacy' and b['options']['profile'] == 'grouped-v2', 'legacy/candidate pair required')
    for key in ('input_sha3', 'source_sha3', 'scope', 'request', 'first_leaf', 'leaves'):
        require(a['report'].get(key) == b['report'].get(key), 'screen scope/source/input mismatch')
    for key in ('transactions', 'workload', 'family'):
        require(a['options'][key] == b['options'][key], 'screen case/family mismatch')
    uuid = baseline['environment']['LATTICA_GPU_DEVICE_UUID']
    require(uuid == candidate['environment']['LATTICA_GPU_DEVICE_UUID'], 'screen device mismatch')
    warm = []
    first = []
    for row in (a, b):
        samples = row['report']['samples']
        require(len(samples) >= 4 and [s['repetition'] for s in samples] == list(range(len(samples)))
                and all(s['verified'] for s in samples), 'three independent warm observations required')
        require(samples[0]['process_state'] == 'first-request'
                and all(s['process_state'] == 'warm-request' for s in samples[1:]), 'first/warm timing mismatch')
        first.append(samples[0]['seconds']); warm.append([s['seconds'] for s in samples[1:]])
    width = b['report']['width']
    require(b['report'].get('admitted_maximum_group', width) == width, 'requested width was not admitted on this screen')
    cost = dict(family=b['options']['family'], width=width, baseline=warm[0], candidate=warm[1])
    note = dict(first_request_seconds=first, warm_ratio=statistics.median(warm[1])/statistics.median(warm[0]),
                full_aggregation_qualified=False)
    return a['report']['source_sha3'], uuid, cost, note


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pair', nargs=2, action='append', type=Path, required=True, metavar=('BASELINE', 'CANDIDATE'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    costs, notes, identities = [], [], set()
    for baseline, candidate in args.pair:
        source, uuid, cost, note = matched_cost(json.loads(baseline.read_text()), json.loads(candidate.read_text()))
        identities.add((source, uuid)); costs.append(cost); notes.append(note)
    require(len(identities) == 1 and len({(c['family'], c['width']) for c in costs}) == len(costs), 'ambiguous layout selection')
    source, uuid = identities.pop()
    value = dict(schema='ringct-gpu-aggregation-selection-v1', source_sha3=source, device_uuid=uuid,
                 costs=costs, observations=notes, performance_qualified=False)
    with args.output.open('x') as output:
        json.dump(value, output, indent=2); output.write('\n')


if __name__ == '__main__':
    main()
