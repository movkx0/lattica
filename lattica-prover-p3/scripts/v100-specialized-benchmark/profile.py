#!/usr/bin/env python3
"""Summarize diagnostic logs; device clocks from different workers stay separate."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import re

FIELDS = re.compile(r'(\w+)=("[^"]*"|\S+)')


def union_ns(intervals):
    total, end = 0, 0
    for start, stop in sorted(intervals):
        if stop < start:
            raise ValueError('nonmonotonic interval')
        total += max(0, stop - max(start, end))
        end = max(end, stop)
    return total


def summarize(path):
    events, kernels, host, stages = [], defaultdict(list), [], defaultdict(list)
    queued, submitted, device_dropped, host_dropped, span_dropped, malformed = [], [], 0, 0, 0, 0
    resources, launches = {}, defaultdict(lambda: defaultdict(int))
    for line in Path(path).read_text().splitlines():
        if line.startswith('gpu_kernel_resources '):
            row = json.loads(line.split(' ', 1)[1]); resources[row['kernel']] = row
        elif line.startswith('gpu_launch '):
            row = json.loads(line.split(' ', 1)[1])
            key = str((row['global_items'], row['local_items'], row['payload_bytes']))
            launches[row['kernel']][key] += 1
        elif line.startswith(('gpu_timeline_', 'host_timeline_', 'performance_span ', 'performance_checkpoint ')):
            row = {k: v.strip('"') for k, v in FIELDS.findall(line)}
            if line.startswith('gpu_timeline_interval '):
                start, end = int(row['start_ns']), int(row['end_ns'])
                if end < start:
                    raise ValueError('nonmonotonic device execution')
                events.append((start, end)); kernels[row['kind']].append(end - start)
                q, s = int(row.get('queued_ns', 0)), int(row.get('submitted_ns', 0))
                if q or s:
                    if not q <= s <= start:
                        raise ValueError('nonmonotonic command submission')
                    queued.append(s - q); submitted.append(start - s)
            elif line.startswith('gpu_timeline_checkpoint '):
                device_dropped += int(row['dropped'])
            elif line.startswith('host_timeline_checkpoint '):
                malformed = max(malformed, int(row['malformed']))
                host_dropped = max(host_dropped, int(row['dropped']))
            elif line.startswith('host_timeline_interval '):
                host.append(row)
            elif line.startswith('performance_span '):
                stages[row['name']].append(int(row['total_ns']))
            elif line.startswith('performance_checkpoint '):
                span_dropped = max(span_dropped, int(row['spans_dropped']))
    dropped = device_dropped + host_dropped + span_dropped
    if not events or not host or not stages or dropped or malformed:
        raise ValueError(f'incomplete diagnostic: events={len(events)}, dropped={dropped}, malformed={malformed}')
    span = max(e for _, e in events) - min(s for s, _ in events)
    busy = union_ns(events)
    host_groups = defaultdict(list)
    for row in host:
        host_groups[(row['thread'], row['name'])].append((int(row['start_ns']), int(row['end_ns'])))
    def distribution(values):
        ordered = sorted(values)
        return {'count': len(ordered), 'sum_seconds_nonadditive': sum(ordered) / 1e9,
                'p50_us': ordered[len(ordered)//2] / 1e3 if ordered else None,
                'p95_us': ordered[min(len(ordered)-1, int(len(ordered)*.95))] / 1e3 if ordered else None}
    return {
        'log': str(Path(path).resolve()), 'events': len(events), 'dropped': dropped,
        'device_span_seconds': span / 1e9, 'recorded_execution_union_seconds': busy / 1e9,
        'uncovered_seconds': (span-busy) / 1e9,
        'interpretation': 'Uncovered intervals include host work and unrecorded commands; they are not measured GPU idle time. Host spans are wall time, not CPU samples. Workers have independent clock domains.',
        'queued_to_submit': distribution(queued), 'submit_to_start': distribution(submitted),
        'events_without_submission_metadata': len(events) - len(queued),
        'kernels': {k: distribution(v) for k, v in sorted(kernels.items(), key=lambda x: -sum(x[1]))},
        'inclusive_host_spans_seconds_nonadditive': {k: sum(v)/1e9 for k, v in sorted(stages.items(), key=lambda x: -sum(x[1]))},
        'entered_host_seconds_by_thread_and_span': [{'thread': t, 'span': k, 'seconds': union_ns(v)/1e9} for (t, k), v in host_groups.items()],
        'kernel_resources': resources, 'launch_shapes': launches,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('logs', nargs='+', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = {'schema': 'lattica-opencl-profile-v1', 'workers': [summarize(p) for p in args.logs]}
    with args.output.open('x') as output:
        json.dump(result, output, indent=2); output.write('\n')
