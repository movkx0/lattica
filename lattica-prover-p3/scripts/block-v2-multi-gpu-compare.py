#!/usr/bin/env python3
"""Five alternating, audited two-job comparisons using one preserved binary.

Run after serial qualification with concurrent-worker budgets. A failed arm
stops the suite. There is no automatic retry or continuation of partial arms.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import os
import time


def write(path, value):
    with path.open('x') as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write('\n')


def cold_warm(directory):
    cold, warm = [], []
    for path in directory.glob('*/[pm]*.log'):
        for line in path.read_text().splitlines():
            if not line.startswith('grouped_node_complete '):
                continue
            fields = dict(item.split('=', 1) for item in line.split()[1:] if '=' in item)
            (warm if int(fields['cache_hits']) else cold).append(int(fields['elapsed_ms']) / 1000)
    return {'cold_seconds': cold, 'warm_seconds': warm,
            'scope': 'first proof versus reused preprocessing in each process; driver cache is not cleared'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--runner', type=Path, required=True)
    p.add_argument('--evidence', type=Path, required=True)
    p.add_argument('--single-gpu', required=True)
    p.add_argument('--rounds', type=int, default=5)
    a = p.parse_args()
    if a.rounds < 1:
        p.error('rounds must be positive')
    base = json.loads(a.config.read_text())
    if len(base['gpu_uuids']) != 2 or a.single_gpu not in base['gpu_uuids']:
        p.error('exactly two selected GPUs, including the qualified single GPU, required')
    a.evidence.mkdir(mode=0o700)
    shutil.copyfile(__file__, a.evidence / 'comparison-runner.py')
    write(a.evidence / 'input.json', {'config': base, 'runner': str(a.runner.resolve()),
          'runner_sha256': hashlib.sha256(a.runner.read_bytes()).hexdigest(), 'rounds': a.rounds, 'single_gpu': a.single_gpu})
    try:
        results = []
        roots = set()
        for repeat in range(1, a.rounds + 1):
            arms = ['sequential', 'concurrent'] if repeat % 2 else ['concurrent', 'sequential']
            for arm in arms:
                config = json.loads(json.dumps(base))
                config.pop('worker_slots', None)
                config.pop('qualification_mode', None)
                config['gpu_uuids'] = [a.single_gpu] if arm == 'sequential' else base['gpu_uuids']
                config['max_concurrency'] = 1 if arm == 'sequential' else 2
                template = base['jobs'][0]
                config['jobs'] = [{k: v for k, v in template.items() if k != 'gpu_uuid'} for _ in range(2)]
                for i, job in enumerate(config['jobs']):
                    job['id'] = f'round-{repeat}-{arm}-{i+1}'
                stem = f'{repeat:02d}-{arm}'
                cfg = a.evidence / (stem + '-config.json')
                directory = a.evidence / stem
                write(cfg, config)
                write(a.evidence / (stem + '-started.json'), {'time_ns': time.time_ns()})
                started = time.monotonic()
                try:
                    with (a.evidence / (stem + '-controller.log')).open('x') as log:
                        subprocess.run([sys.executable, str(a.runner.resolve()), '--config', str(cfg.resolve()), '--evidence', str(directory.resolve())], stdout=log, stderr=subprocess.STDOUT, check=True,
                                       env={**os.environ, "LATTICA_BENCHMARK_REPORT_DEFER": "1"})
                    elapsed = time.monotonic() - started
                except BaseException as error:
                    # Failed work consumes the measured window too.
                    write(a.evidence / (stem + '-result.json'), {
                        'repeat': repeat, 'arm': arm, 'status': 'failed',
                        'pair_makespan_seconds': time.monotonic() - started,
                        'individual_seconds': [], 'error': type(error).__name__,
                    })
                    raise
                summary = json.loads(subprocess.check_output([sys.executable, str(a.runner.resolve()), '--summarize', str(directory.resolve())], text=True))
                if summary['status'] != 'succeeded' or len(summary['results']) != 2 or not all(r['cpu_audited'] for r in summary['results']):
                    raise ValueError('both jobs must finish and pass independent CPU audit')
                overlap = 0.0
                if arm == 'concurrent':
                    uuids = {r['budget']['gpu']['uuid'] for r in summary['results']}
                    attempts = [d for d in directory.iterdir() if d.is_dir() and (d / 'result.json').exists()]
                    starts = [json.loads((d / 'pairs-started.json').read_text())['started_ns'] for d in attempts]
                    ends = [json.loads((d / 'merges-finished.json').read_text())['finished_ns'] for d in attempts]
                    overlap = (min(ends) - max(starts)) / 1e9
                    if len(uuids) != 2 or overlap <= 0:
                        raise ValueError('concurrent arm did not execute overlapping jobs on two distinct GPUs')
                for worker in summary['results']:
                    proof_hash = worker['artifacts']['node.3.0']
                    if proof_hash in roots:
                        raise ValueError('unexpected repeated root proof; fresh randomness required')
                    roots.add(proof_hash)
                result = {'repeat': repeat, 'arm': arm, 'pair_makespan_seconds': elapsed, 'jobs_per_hour': 7200 / elapsed,
                          'individual_seconds': [r['elapsed_seconds'] for r in summary['results']], 'proving_overlap_seconds': overlap,
                          'cold_warm': cold_warm(directory), 'workers': summary['results']}
                write(a.evidence / (stem + '-result.json'), result)
                results.append(result)
                print(json.dumps({k: v for k, v in result.items() if k not in ('workers', 'cold_warm')}), flush=True)
        medians = {arm: statistics.median(r['pair_makespan_seconds'] for r in results if r['arm'] == arm) for arm in ('sequential', 'concurrent')}
        summary = {'status': 'succeeded', 'rounds': a.rounds, 'results': results,
                   'median_pair_makespan_seconds': medians,
                   'median_jobs_per_hour': {arm: 7200 / seconds for arm, seconds in medians.items()},
                   'pair_makespan_reduction_percent': 100 * (1 - medians['concurrent'] / medians['sequential']),
                   'production_ready': False}
        write(a.evidence / 'summary.json', summary)
    finally:
        # Child exports are deferred until all pair timing and cleanup have ended.
        from block_v2_report_export import export_after_run
        export_after_run(a.evidence)



if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'FAILED: {error}; suite stopped, no automatic retry', file=sys.stderr)
        sys.exit(1)
