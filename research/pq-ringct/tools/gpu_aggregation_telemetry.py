"""One terminal snapshot and explicit overlapping intervals, never cumulative sums."""
import json
import re


def reduce_intervals(content):
    intervals, snapshots = [], {}
    for line in content.splitlines():
        if line.startswith('GPU_AGGREGATION_INTERVAL '):
            row = json.loads(line.split(' ', 1)[1])
            if (len(intervals) >= 65536 or any(type(row.get(k)) is not int or row[k] < 0
                    for k in ('tree', 'job', 'start_ns', 'end_ns', 'duration_ns'))
                    or row['end_ns'] < row['start_ns']
                    or row['duration_ns'] != row['end_ns'] - row['start_ns']):
                raise RuntimeError('invalid aggregation stage interval')
            intervals.append(row)
        if line.startswith('bounded_gpu_') and any(('label="'+label+'"') in line for label in ('recursive OpenCL session complete', 'native operation session teardown')):
            kind = line.split(' ', 1)[0]
            if kind in snapshots:
                raise RuntimeError('duplicate terminal GPU snapshot')
            snapshots[kind] = {k: int(v) for k, v in re.findall(r'\b([a-z_]+)=(\d+)\b', line)}
    phases = {}
    for row in intervals:
        phase = phases.setdefault(row['phase'], dict(task_sum_ns=0, intervals=0))
        phase['task_sum_ns'] += row['duration_ns']
        phase['intervals'] += 1
    return dict(schema='ringct-gpu-stage-intervals-v1', overlapping=True,
                additive_wall_decomposition=False, phases=phases, intervals=intervals,
                terminal_counters=snapshots)
