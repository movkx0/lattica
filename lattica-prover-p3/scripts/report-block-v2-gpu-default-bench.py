"""Read pinned evidence and compare completed GPU-default runs with controls."""
import hashlib
import json
from pathlib import Path
import statistics
import time

OUT = Path(__file__).resolve().parents[1] / "target/block-v2-gpu-default-bench-20261002-a"
GIB = 1 << 30


def read(path):
    return json.loads(path.read_text())


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def report():
    plan = read(OUT / 'plan.json')
    state = read(OUT / 'run-state.json')
    assert digest(OUT / 'plan.json') == state['plan_sha256']
    for name, expected in plan['pins'].items():
        assert digest(Path(name)) == expected, name
    arms = {arm: [] for arm in plan['arms']}
    for item in state['attempts']:
        if item['register'] or item['status'] != 'complete':
            continue
        path = OUT / 'evidence' / item['label'] / 'manifest.json'
        assert digest(path) == item['manifest_sha256']
        manifest = read(path)
        assert manifest['status'] == 'GPU_PROOF_VERIFIED_RESEARCH_ONLY'
        stages = [a for a in manifest['attempts'] if a['name'] in ('pairs', 'merges')]
        assert len(stages) == 2
        wall = sum(a['wall_seconds'] for a in stages)
        cpu = sum(a['telemetry']['accounting']['cpu_usage_usec'] for a in stages) / 1e6
        sampled_major_faults = 0
        events = {}
        for stage in stages:
            host = path.parent / stage['host_log']
            assert digest(host) == stage['host_log_sha256']
            samples = [json.loads(line) for line in host.read_text().splitlines()]
            sampled_major_faults += max((x.get('memory.stat') or {}).get('pgmajfault', 0) for x in samples)
            for key in ('high', 'max', 'oom', 'oom_kill'):
                events[key] = events.get(key, 0) + max((x.get('memory.events') or {}).get(key, 0) for x in samples)
        arms[item['arm']].append({
            'label': item['label'], 'round': int(item['label'].split('-')[1]),
            'recursive_seconds': manifest['recursive_command_ms'] / 1000,
            'complete_controller_seconds': item['elapsed_seconds'],
            'worker_stage_seconds': wall, 'cpu_seconds': cpu, 'average_logical_cpus': cpu / wall,
            'cpu_fraction_of_24': cpu / wall / 24,
            'peak_worker_ram_gib': max(a['telemetry']['accounting']['memory_peak'] for a in stages) / GIB,
            'peak_mapped_scratch_gib': max(a['telemetry']['duration']['spill_peak_bytes'] for a in stages) / GIB,
            'peak_swap_bytes': max(a['telemetry']['accounting']['memory_swap_peak'] for a in stages),
            'sampled_major_faults': sampled_major_faults, 'sampled_memory_events': events,
            'verified': True, 'manifest': str(path), 'manifest_sha256': digest(path),
        })
    result = {'schema': 'gpu-default-ram-performance-comparison-v1', 'generated_utc': time.time(),
              'status': state['status'], 'production_ready': False,
              'plan_sha256': digest(OUT / 'plan.json'), 'arms': {},
              'scope': 'Eight public wallet proofs; four paired wrappers and three merges; CPU-audited root.',
              'interpretation': [
                  'The preserved control already enabled GPU explicitly; default GPU is not a CPU-to-GPU comparison.',
                  'Three trials per arm are exploratory; no five-pair performance promotion or full-block qualification.',
                  'RAM peaks include charged RAM scratch; do not add scratch size to worker RAM.',
                  'CPU equivalents divide worker cgroup CPU time by stage wall time on a hybrid P/E CPU.',
                  'Major faults and memory events use sampled cgroup counters; swap/RAM peaks use final accounting.',
                  'Historical medians are context only; interleaved current 16-thread controls are the primary comparison.'
              ]}
    for arm, rows in arms.items():
        result['arms'][arm] = {'runs': rows, 'n': len(rows)}
        if rows:
            result['arms'][arm].update({
                'median_seconds': statistics.median(x['recursive_seconds'] for x in rows),
                'minimum_seconds': min(x['recursive_seconds'] for x in rows),
                'maximum_seconds': max(x['recursive_seconds'] for x in rows),
                'median_average_logical_cpus': statistics.median(x['average_logical_cpus'] for x in rows),
                'maximum_worker_ram_gib': max(x['peak_worker_ram_gib'] for x in rows),
                'maximum_scratch_gib': max(x['peak_mapped_scratch_gib'] for x in rows),
            })
    control = {x['round']: x for x in arms['ram16-control']}
    candidate = {x['round']: x for x in arms['ram16']}
    result['matched_16_thread_rounds'] = [
        {'round': number, 'control_seconds': control[number]['recursive_seconds'],
         'candidate_seconds': candidate[number]['recursive_seconds'],
         'candidate_time_change_percent': 100 * (candidate[number]['recursive_seconds'] / control[number]['recursive_seconds'] - 1)}
        for number in sorted(control.keys() & candidate.keys())]
    if control and candidate:
        result['new16_vs_control16_median_time_change_percent'] = 100 * (
            result['arms']['ram16']['median_seconds'] / result['arms']['ram16-control']['median_seconds'] - 1)
    historical = read(Path(plan['previous_suite']) / 'summary.json')
    result['historical_ram_medians_seconds'] = {
        arm: historical['arms'][arm]['median_recursive_seconds'] for arm in ('ram8', 'ram16')}
    result['historical_ram24_single_seconds'] = read(OUT.parent / 'block-v2-max-threads-20261002-a/summary.json')['arms']['ram24']['median_recursive_seconds']
    if state['status'] == 'COMPLETE_RESEARCH_ONLY':
        assert len(state['attempts']) == 16 and all(x['status'] == 'complete' for x in state['attempts'])
        assert all(len(rows) == 3 for rows in arms.values())
        assert all(x['peak_swap_bytes'] == 0 for rows in arms.values() for x in rows)
        result['sampled_memory_limit_events_zero'] = all(
            not any(x['sampled_memory_events'].values()) for rows in arms.values() for x in rows)
        (OUT / 'performance-comparison.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({
        'status': result['status'], 'completed_proofs': sum(len(x) for x in arms.values()),
        'arms': {arm: {k: v for k, v in values.items() if k != 'runs'} for arm, values in result['arms'].items()},
        'matched_16_thread_rounds': result['matched_16_thread_rounds'],
        'median_time_change_percent': result.get('new16_vs_control16_median_time_change_percent'),
        'active': [{k: item[k] for k in ('label', 'status', 'started_utc')} for item in state['attempts'] if item['status'] != 'complete']
    }))
    return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, default=OUT)
    OUT = parser.parse_args().plan.resolve()
    report()
