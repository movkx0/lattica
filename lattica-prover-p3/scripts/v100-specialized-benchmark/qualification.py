#!/usr/bin/env python3
"""Evaluate paired, frozen-binary pass-two evidence for both V100 workloads."""
import argparse
import hashlib
import json
from pathlib import Path
from statistics import median


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def compare(baseline, candidate):
    if len(baseline) != len(candidate) or len(baseline) not in (5, 10):
        raise ValueError('qualification requires five or ten complete pairs')
    if any(v <= 0 for v in baseline + candidate):
        raise ValueError('invalid elapsed time')
    before, after = median(baseline), median(candidate)
    return {
        'pairs': len(baseline), 'baseline_seconds': baseline, 'candidate_seconds': candidate,
        'median_baseline_seconds': before, 'median_candidate_seconds': after,
        'time_reduction_percent': 100 * (1 - after / before),
        'throughput_increase_percent': 100 * (before / after - 1),
        'paired_wins': sum(b > c for b, c in zip(baseline, candidate)),
        'required_paired_wins': (4 * len(baseline) + 4) // 5,
    }


def gate(workloads):
    return (all(w['time_reduction_percent'] > 0
                and w['paired_wins'] >= w['required_paired_wins'] for w in workloads)
            and any(w['time_reduction_percent'] >= 5 for w in workloads))


def summarize(root, candidate='final', pairs=5):
    root = Path(root)
    roots, proofs, workloads, files = set(), 0, {}, {}
    for shape, inputs in [('four', 4), ('concurrent', 16)]:
        arms = {}
        for arm, label in [('baseline', 'baseline'), ('candidate', candidate)]:
            binary_dir = root / ('evidence' if shape == 'four' else 'eight')
            pin = json.loads((binary_dir / (label + '-build.json')).read_text())
            if digest(binary_dir / label) != pin['binary_sha256']:
                raise ValueError('frozen binary changed')
            samples = []
            for pair in range(1, pairs + 1):
                name = f'paired-{shape}-{pair:02d}-{arm}'
                path = (root / 'evidence' / (name + '.json') if shape == 'four'
                        else root / 'eight/evidence' / name / 'summary.json')
                sample = json.loads(path.read_text())
                files[str(path.relative_to(root))] = digest(path)
                if (sample['status'], sample['label'], sample['tuning'], sample['inputs'],
                        sample['binary_sha256']) != ('passed', label, '', inputs, pin['binary_sha256']):
                    raise ValueError('sample identity or completion mismatch')
                jobs = [sample] if shape == 'four' else sample['jobs']
                if len(jobs) != (1 if shape == 'four' else 2):
                    raise ValueError('wrong root count')
                for job in jobs:
                    count = 3 if shape == 'four' else 7
                    coverage = job['gpu_stage_coverage']
                    if (job['cpu_audit']['status'] != 'passed' or job['recursive_proofs'] != count
                            or coverage['fresh_gpu_proofs'] != count or coverage['required_stage_count'] != 16):
                        raise ValueError('missing CPU verification or GPU coverage')
                    if job['root_sha256'] in roots:
                        raise ValueError('root reused between measurements')
                    roots.add(job['root_sha256']); proofs += count
                telemetry = [sample['telemetry']] if shape == 'four' else sample['cohorts']
                if any(any(t['memory_event_deltas'].values()) for t in telemetry):
                    raise ValueError('memory-pressure event during sample')
                samples.append(sample)
            energy = [s['power']['energy_wh'] if shape == 'four' else s['energy_wh'] for s in samples]
            power = [s['power']['average_power_w'] if shape == 'four' else s['average_power_w'] for s in samples]
            arms[arm] = {
                'binary_sha256': pin['binary_sha256'],
                'seconds': [s['seconds'] for s in samples],
                'median_energy_wh': median(energy), 'median_average_power_w': median(power),
                'sampled_peak_gpu_mib': max(s['telemetry']['peak_gpu_mib'] if shape == 'four'
                                          else s['peak_gpu_mib'] for s in samples),
                'peak_managed_bytes_per_worker': max(j['managed_gpu_peak_bytes'] for s in samples
                                                     for j in ([s] if shape == 'four' else s['jobs'])),
            }
        comparison = compare(arms['baseline']['seconds'], arms['candidate']['seconds'])
        comparison.update(arms=arms,
                          baseline_inputs_per_hour=inputs * 3600 / comparison['median_baseline_seconds'],
                          candidate_inputs_per_hour=inputs * 3600 / comparison['median_candidate_seconds'],
                          energy_reduction_percent=100 * (1 - arms['candidate']['median_energy_wh']
                                                          / arms['baseline']['median_energy_wh']))
        workloads[shape] = comparison
    passed = gate(list(workloads.values()))
    return {
        'schema': 'lattica-v100-pass2-qualification-v1', 'status': 'passed' if passed else 'inconclusive',
        'gate': 'Both medians improve; at least one improves 5%; at least 80% paired wins in each workload.',
        'workloads': workloads, 'cpu_verified_fresh_roots': len(roots), 'fresh_recursive_proofs': proofs,
        'sample_hashes': files, 'production_qualified': False,
        'timing': 'Four-input aggregation excludes initialization. Concurrent latency includes both worker lifetimes. Energy includes worker initialization/shutdown. CPU audits are excluded.',
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--candidate', default='final')
    parser.add_argument('--pairs', type=int, choices=[5, 10], default=5)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = summarize(args.evidence, args.candidate, args.pairs)
    with args.output.open('x') as output:
        json.dump(result, output, indent=2); output.write('\n')
    print(result['status'])
